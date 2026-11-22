//! Reading a paper backup through a camera.
//!
//! One symbol at a time, not a photograph of a page. A whole page across
//! a 1920px sensor is 2.7 pixels per module and will not read; one symbol
//! filling the same sensor is 6.6 and reads easily. So the holder moves
//! the page, and `paper::Sheet` accumulates symbols in any order.
//!
//! Capture runs on its own thread and reports through a callback, because
//! grid detection costs most of a frame interval and the UI thread has a
//! window to paint.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use kenter_wallet::paper::Scanned;
use nokhwa::pixel_format::LumaFormat;
use nokhwa::utils::{ApiBackend, CameraFormat, FrameFormat, RequestedFormat, RequestedFormatType};

/// Modules across the widest symbol a sheet can carry, quiet zone
/// included.
///
/// This is the only lever on whether a camera can read us. The physical
/// module size cancels out: a symbol is `modules * module_mm` across, so
/// filling the frame with it puts exactly `modules` modules on the sensor
/// whatever the millimetres are.
///
/// **Derived from the density cap, not from the page cell.** The cell the
/// page reserves is `sheet::SYMBOL_MODULES`, 185 — a version-40 symbol —
/// but symbols do not fill it: `paper::chunk_payload` caps a symbol at
/// version 24, which is 121 modules with its quiet zone, and the page
/// simply scales the smaller symbol up into the same square. Measuring
/// against the cell would refuse cameras that read fine.
///
/// Reading 185 after that change made the gate 53% pessimistic, and the
/// cost landed exactly where it hurts: a 1280x720 camera came out at 3.31
/// against a floor of 4 and was **refused, though it reads at 5.06**. A
/// gate that turns away a working camera is worse than no gate, because
/// the holder has no way to tell a real limit from a wrong one.
///
/// Computed rather than written down so it tracks the cap, including an
/// overridden one.
fn modules() -> f32 {
    static N: std::sync::OnceLock<f32> = std::sync::OnceLock::new();
    *N.get_or_init(|| {
        // The header rides in the symbol alongside the payload, and
        // `paper` keeps its size implicit in these two constants.
        let header = kenter_wallet::paper::SYMBOL_CAPACITY - kenter_wallet::paper::CHUNK_PAYLOAD;
        let widest = kenter_wallet::paper::chunk_payload() + header;
        match qrcode::QrCode::with_error_correction_level(vec![0u8; widest], qrcode::EcLevel::M) {
            Ok(code) => code.width() as f32 + 2.0 * crate::qr::QUIET as f32,
            // Only reachable if the cap exceeds what a symbol can hold,
            // which `chunk_payload` clamps against. The page cell is the
            // safe answer: it is the largest symbol that can be drawn.
            Err(_) => crate::sheet::SYMBOL_MODULES,
        }
    })
}

/// How much of the frame's short side a holder can be expected to fill
/// with one symbol while still seeing enough page to aim. Deliberately
/// not a best case.
const FILL: f32 = 0.85;

/// Pixels per module below which we say the camera is not good enough,
/// rather than show a viewfinder that cannot work.
///
/// Three is the decoder's hard floor. Four is where it still reads with a
/// hand-held page, ordinary lighting and lens softness in the way.
const FLOOR: f32 = 4.0;

/// Preview width sent to the UI.
///
/// Decoding runs at full sensor resolution; this is only what a human
/// looks at, and pushing 2.7MB a frame through the event loop to draw it
/// 400px wide would be absurd.
const PREVIEW_W: u32 = 480;

/// What a frame of this size is worth, in pixels per module.
pub fn pixels_per_module(short_side: u32) -> f32 {
    short_side as f32 * FILL / modules()
}

/// Is a camera of this resolution worth offering?
pub fn good_enough(short_side: u32) -> bool {
    pixels_per_module(short_side) >= FLOOR
}

/// What the capture thread tells the UI.
pub enum Event {
    /// The camera opened. `px_per_module` is what decides whether this is
    /// a usable instrument, and the screen says it out loud.
    Opened {
        name: String,
        width: u32,
        height: u32,
        px_per_module: f32,
    },
    /// A frame to show. Luminance; the UI greys it out to pixels.
    Preview {
        width: u32,
        height: u32,
        luma: Vec<u8>,
    },
    /// A Kenter symbol was read. Duplicates are expected and harmless —
    /// `Sheet::add` is idempotent, and at a dozen frames a second the
    /// same symbol lands many times while the holder holds the page.
    Symbol(Box<Scanned>),
    /// A full-resolution frame, because it was asked for.
    ///
    /// Never sent unprompted: this is 2.7MB at 1920x1440, and pushing
    /// that through the event loop twelve times a second to save one
    /// copy of it would be absurd.
    Shot {
        width: u32,
        height: u32,
        luma: Vec<u8>,
    },
    /// Something the holder needs to know.
    Trouble(String),
    /// The thread has stopped and the device is released.
    Closed,
}

/// Where the chosen camera is remembered between runs.
///
/// A machine with a front and a rear camera will offer the rear one
/// first, and the rear one is the awkward one to hold a page in front
/// of. Choosing is cheap; choosing again every single run is not.
fn choice_file() -> Option<std::path::PathBuf> {
    crate::wallet::home_dir().map(|h| h.join(".kenter-camera"))
}

/// The camera last used, if one was recorded and still exists.
pub fn remembered() -> Option<String> {
    std::fs::read_to_string(choice_file()?)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Record a camera as the one to open next time. Best effort: failing to
/// remember a preference must never stop a capture.
pub fn remember(name: &str) {
    if let Some(p) = choice_file() {
        let _ = std::fs::write(p, name);
    }
}

/// Every camera this machine offers, as `(index, human name)`.
pub fn cameras() -> Result<Vec<(u32, String)>, String> {
    let found = nokhwa::query(ApiBackend::Auto).map_err(|e| e.to_string())?;
    Ok(found
        .iter()
        .enumerate()
        .map(|(i, c)| (i as u32, c.human_name()))
        .collect())
}

/// Which camera to open.
///
/// `KENTER_CAMERA` wins, as either a number or any part of a name, so a
/// test run can be pinned without touching the saved choice. Then what
/// was used last. Then whatever the machine lists first.
fn choose(cams: &[nokhwa::utils::CameraInfo], want: Option<&str>) -> usize {
    let pick = |s: &str| -> Option<usize> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        if let Ok(n) = s.parse::<usize>() {
            if n < cams.len() {
                return Some(n);
            }
        }
        let lower = s.to_lowercase();
        cams.iter()
            .position(|c| c.human_name().to_lowercase().contains(&lower))
    };

    want.and_then(pick)
        .or_else(|| std::env::var("KENTER_CAMERA").ok().as_deref().and_then(pick))
        .or_else(|| remembered().as_deref().and_then(pick))
        .unwrap_or(0)
}

/// A running capture thread. Dropping it stops the camera.
pub struct Capture {
    stop: Arc<AtomicBool>,
    /// Set to ask for one full-resolution frame.
    shot: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Capture {
    /// Open the best raw format this machine offers and start reading.
    ///
    /// Returns immediately. Opening a camera takes a noticeable moment
    /// and the UI must not wait on it, so even failure arrives as an
    /// [`Event`] rather than an error here.
    pub fn start(sink: impl Fn(Event) + Send + 'static) -> Capture {
        Capture::start_on(None, sink)
    }

    /// [`Capture::start`] on a named camera.
    ///
    /// `want` is a number or any part of a name. A camera opened this way
    /// becomes the remembered one, so the next run does not have to be
    /// told again.
    pub fn start_on(want: Option<String>, sink: impl Fn(Event) + Send + 'static) -> Capture {
        let stop = Arc::new(AtomicBool::new(false));
        let shot = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let want_shot = shot.clone();
        let join = std::thread::spawn(move || {
            run_on(&flag, &want_shot, &sink, want.as_deref());
            sink(Event::Closed);
        });
        Capture {
            stop,
            shot,
            join: Some(join),
        }
    }

    /// Ask for one frame at full resolution.
    ///
    /// The only honest test image for this pipeline comes from the
    /// camera it will run on: a phone photograph measures the phone.
    pub fn grab(&self) {
        self.shot.store(true, Ordering::Relaxed);
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            // Joining matters: the device stays claimed until the thread
            // lets go of it, and a holder who leaves this screen and
            // comes back would otherwise find their own camera busy.
            let _ = j.join();
        }
    }
}

/// Luminance out of whatever the sensor handed us.
///
/// Raw formats only. MJPEG would need a JPEG decoder in the capture path
/// and the C library that comes with it, which `Cargo.toml` explains at
/// length is not a trade worth making.
fn luma_of(format: FrameFormat, raw: &[u8], w: u32, h: u32) -> Option<Vec<u8>> {
    let pixels = (w as usize) * (h as usize);
    match format {
        // Semi-planar: a full-resolution Y plane first, then interleaved
        // chroma. Exactly the grayscale a QR reader wants, for free.
        FrameFormat::NV12 | FrameFormat::GRAY => raw.get(..pixels).map(<[u8]>::to_vec),
        // Packed 4:2:2 — luminance in every other byte.
        FrameFormat::YUYV => {
            if raw.len() < pixels * 2 {
                return None;
            }
            Some(raw.iter().step_by(2).take(pixels).copied().collect())
        }
        FrameFormat::RAWRGB => {
            if raw.len() < pixels * 3 {
                return None;
            }
            // Rec. 601 luma in integers, the same weighting `image` uses,
            // so a frame reads the same whichever path produced it.
            Some(
                raw.chunks_exact(3)
                    .take(pixels)
                    .map(|p| {
                        ((p[0] as u32 * 299 + p[1] as u32 * 587 + p[2] as u32 * 114) / 1000) as u8
                    })
                    .collect(),
            )
        }
        _ => None,
    }
}

/// Shrink for display.
///
/// Nearest-neighbour on purpose: this is the picture a human looks at and
/// never the one the decoder reads, so module edges do not matter and
/// speed does.
fn preview(luma: &[u8], w: u32, h: u32) -> (u32, u32, Vec<u8>) {
    if w <= PREVIEW_W {
        return (w, h, luma.to_vec());
    }
    let pw = PREVIEW_W;
    let ph = (h * pw / w).max(1);
    let mut out = Vec::with_capacity((pw * ph) as usize);
    for y in 0..ph {
        let sy = y * h / ph;
        for x in 0..pw {
            let sx = x * w / pw;
            out.push(luma[(sy * w + sx) as usize]);
        }
    }
    (pw, ph, out)
}

/// The raw format with the most pixels on its short side.
///
/// The short side is what counts: a symbol is square, so framing it fills
/// the smaller dimension first.
fn best_raw(cam: &mut nokhwa::Camera) -> Option<CameraFormat> {
    let mut formats = cam.compatible_camera_formats().ok()?;
    formats.retain(|f| {
        matches!(
            f.format(),
            FrameFormat::NV12 | FrameFormat::YUYV | FrameFormat::GRAY | FrameFormat::RAWRGB
        )
    });
    formats.sort_by_key(|f| {
        let r = f.resolution();
        (r.width_x.min(r.height_y), f.frame_rate())
    });
    formats.last().copied()
}

fn run_on(stop: &AtomicBool, shot: &AtomicBool, sink: &impl Fn(Event), want: Option<&str>) {
    let cams = match nokhwa::query(ApiBackend::Auto) {
        Ok(c) => c,
        Err(e) => return sink(Event::Trouble(format!("could not look for cameras: {e}"))),
    };
    if cams.is_empty() {
        return sink(Event::Trouble(
            "no camera on this machine - use image files instead".into(),
        ));
    }

    // The chosen camera first, then the rest. A device can be busy --
    // held by a video call, or by a previous run that was killed rather
    // than closed -- and a machine with a second camera sitting idle
    // should use it rather than present a dead window.
    let first = choose(&cams, want);
    let order: Vec<usize> = std::iter::once(first)
        .chain((0..cams.len()).filter(|i| *i != first))
        .collect();

    let mut last_trouble = String::new();
    for (attempt, i) in order.iter().enumerate() {
        let info = cams[*i].clone();
        if attempt > 0 {
            sink(Event::Trouble(format!(
                "{last_trouble} - trying {} instead",
                info.human_name()
            )));
        }
        match try_camera(stop, shot, sink, &info) {
            Ok(()) => return,
            Err(why) => last_trouble = why,
        }
    }
    sink(Event::Trouble(format!(
        "{last_trouble} - no camera on this machine would start, so use image files instead"
    )));
}

/// Open one camera and run it until asked to stop.
///
/// `Err` means this device is not usable and another is worth trying;
/// `Ok` means it ran, however briefly.
fn try_camera(
    stop: &AtomicBool,
    shot: &AtomicBool,
    sink: &impl Fn(Event),
    info: &nokhwa::utils::CameraInfo,
) -> Result<(), String> {
    let info = info.clone();

    let mut cam = nokhwa::Camera::new(
        info.index().clone(),
        RequestedFormat::new::<LumaFormat>(RequestedFormatType::AbsoluteHighestResolution),
    )
    .map_err(|e| {
        format!(
            "could not open {}: {e}. Another program may be using it",
            info.human_name()
        )
    })?;

    if let Some(best) = best_raw(&mut cam) {
        // A refusal is not fatal: the format it opened with may be raw
        // and usable anyway, and the checks below are what decide.
        let _ = cam.set_camera_requset(RequestedFormat::new::<LumaFormat>(
            RequestedFormatType::Exact(best),
        ));
    }

    let fmt = cam.camera_format();
    let (w, h) = (fmt.resolution().width_x, fmt.resolution().height_y);
    let short = w.min(h);

    // Both refusals are deliberate and both name the way out. A
    // viewfinder that cannot possibly resolve a symbol is worse than no
    // viewfinder: too few pixels looks exactly like bad focus, so the
    // holder would keep trying.
    if matches!(fmt.format(), FrameFormat::MJPEG) {
        return Err(format!(
            "{} only offers compressed frames, which this build cannot read",
            info.human_name()
        ));
    }
    if !good_enough(short) {
        return Err(format!(
            "{} is {w}x{h}, giving {:.1} pixels per module against the {FLOOR:.0} a symbol \
             needs",
            info.human_name(),
            pixels_per_module(short)
        ));
    }

    cam.open_stream()
        .map_err(|e| format!("could not start {}: {e}", info.human_name()))?;

    // Said only once the stream is actually going. Announcing on open
    // put "live" on screen for a camera that then failed to produce a
    // single frame, which is how the window came to be black.
    let first = cam
        .frame()
        .map_err(|e| format!("{} opened but produced nothing: {e}", info.human_name()))?;
    remember(&info.human_name());
    sink(Event::Opened {
        name: info.human_name(),
        width: w,
        height: h,
        px_per_module: pixels_per_module(short),
    });
    drop(first);

    while !stop.load(Ordering::Relaxed) {
        let frame = match cam.frame() {
            Ok(f) => f,
            Err(e) => {
                sink(Event::Trouble(format!("the camera stopped: {e}")));
                break;
            }
        };
        let res = frame.resolution();
        let Some(luma) = luma_of(
            frame.source_frame_format(),
            frame.buffer(),
            res.width_x,
            res.height_y,
        ) else {
            sink(Event::Trouble(
                "this camera's frames are in a format this build cannot read".into(),
            ));
            break;
        };

        if shot.swap(false, Ordering::Relaxed) {
            sink(Event::Shot {
                width: res.width_x,
                height: res.height_y,
                luma: luma.clone(),
            });
        }

        let (pw, ph, small) = preview(&luma, res.width_x, res.height_y);
        sink(Event::Preview {
            width: pw,
            height: ph,
            luma: small,
        });

        // Full resolution, never the preview. Reading what was shrunk for
        // display is the mistake that cost a day on the file path.
        let Some(img) = image::GrayImage::from_raw(res.width_x, res.height_y, luma) else {
            continue;
        };
        // Find the symbols in the frame first. Decoding a whole view at
        // once makes the reader hunt finder patterns across every symbol
        // in it, and the neighbours are the clutter that defeats it --
        // which is why a sheet held up whole and decoded as one image reads
        // one symbol at best.
        for s in crate::scan::read_frame(img).symbols {
            sink(Event::Symbol(Box::new(s)));
        }
    }
    let _ = cam.stop_stream();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gate measures the symbol we actually print, not the cell it
    /// sits in.
    ///
    /// Computed against a version-40 symbol the figures would be 6.62,
    /// 4.96 and 3.31, and 720p would be refused. A sheet carries no
    /// version-40 symbol, so that would be a **false warning** -- turning
    /// away a camera that reads at better than five pixels a module.
    #[test]
    fn the_gate_measures_the_symbol_we_print() {
        // Version 24 plus an eight-module quiet zone.
        assert_eq!(modules(), 121.0, "the cap is version 24");

        assert!((pixels_per_module(1440) - 10.12).abs() < 0.01);
        assert!((pixels_per_module(1080) - 7.59).abs() < 0.01);
        assert!((pixels_per_module(720) - 5.06).abs() < 0.01);
        assert!((pixels_per_module(480) - 3.37).abs() < 0.01);
    }

    /// A camera is turned away only when it genuinely cannot work.
    #[test]
    fn only_a_camera_that_cannot_work_is_refused() {
        assert!(good_enough(1440), "1920x1440 is the measured good case");
        assert!(good_enough(1080));
        assert!(
            good_enough(720),
            "720p reads at 5.06 px/module; refusing it is a false warning, and              raw-only webcams on Linux commonly offer nothing better"
        );
        assert!(!good_enough(480), "480p really is too thin, at 3.37");
    }

    /// NV12's Y plane is the first w*h bytes and nothing else.
    #[test]
    fn nv12_luminance_is_the_leading_plane() {
        let (w, h) = (4u32, 2u32);
        let mut raw = vec![7u8; (w * h) as usize];
        raw.extend_from_slice(&[200u8; 4]); // chroma, must not appear
        let luma = luma_of(FrameFormat::NV12, &raw, w, h).expect("luma");
        assert_eq!(luma, vec![7; 8]);
    }

    /// YUYV interleaves, so taking the plane whole would read chroma as
    /// picture and turn every symbol into noise.
    #[test]
    fn yuyv_luminance_is_every_other_byte() {
        let (w, h) = (2u32, 1u32);
        let raw = [10u8, 99, 20, 99];
        let luma = luma_of(FrameFormat::YUYV, &raw, w, h).expect("luma");
        assert_eq!(luma, vec![10, 20]);
    }

    /// A short buffer must not panic the capture thread.
    #[test]
    fn a_truncated_frame_is_refused_rather_than_indexed() {
        assert!(luma_of(FrameFormat::NV12, &[1, 2, 3], 64, 64).is_none());
        assert!(luma_of(FrameFormat::YUYV, &[1, 2, 3], 64, 64).is_none());
        assert!(luma_of(FrameFormat::RAWRGB, &[1, 2, 3], 64, 64).is_none());
    }

    /// Compressed frames have no luminance plane to slice.
    #[test]
    fn mjpeg_has_no_raw_luminance() {
        assert!(luma_of(FrameFormat::MJPEG, &[0; 4096], 32, 32).is_none());
    }

    /// The preview shrinks and never grows, and keeps its aspect.
    #[test]
    fn the_preview_shrinks_to_a_sane_size() {
        let (w, h) = (1920u32, 1440u32);
        let (pw, ph, px) = preview(&vec![0u8; (w * h) as usize], w, h);
        assert_eq!(pw, PREVIEW_W);
        assert_eq!(ph, 360);
        assert_eq!(px.len(), (pw * ph) as usize);

        // Already small: left alone rather than upscaled.
        let (sw, sh, _) = preview(&vec![0u8; 100], 10, 10);
        assert_eq!((sw, sh), (10, 10));
    }
}
