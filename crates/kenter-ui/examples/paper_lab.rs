//! A viewfinder and nothing else, for sizing paper symbols against real
//! optics.
//!
//! The density question does not need a window: `calibration_sheet` and
//! `read_back` already measure it through printed pages and photographs.
//! What needs one is the **camera** path, which is unusable blind — you
//! cannot aim at a 55mm square you cannot see, and a failure to read is
//! indistinguishable from a failure to point.
//!
//! So this is deliberately not an application. One window showing the
//! live preview, every word to the console, no wallet, no key, no PIN.
//! It drives the real [`kenter_ui::camera::Capture`] and the real
//! `scan::read_luma`, because a harness that reimplements them would
//! teach us about the harness.
//!
//! Run: `cargo run -p kenter-ui --example paper_lab`
//!
//! Point it at one symbol of a printed sheet, filling the frame. Symbols
//! are reported as they land, each one once.

use std::collections::BTreeSet;
use std::num::NonZeroU32;
use std::rc::Rc;
use std::time::Instant;

use kenter_ui::camera::{Capture, Event as CamEvent};
use winit::application::ApplicationHandler;
use winit::event::{ElementState, WindowEvent};
use winit::keyboard::{KeyCode, PhysicalKey};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::window::{Window, WindowId};

fn main() {
    let event_loop = EventLoop::<CamEvent>::with_user_event()
        .build()
        .expect("event loop");
    event_loop.set_control_flow(ControlFlow::Wait);

    println!("paper_lab - point the camera at ONE symbol, filling the frame.");
    println!("Every symbol that reads is reported once.");
    println!("SPACE switches camera (remembered for next time).");
    println!("S saves the current frame at full resolution, for the bake-off.");
    println!("Close the window to stop.\n");

    match kenter_ui::camera::cameras() {
        Ok(list) if !list.is_empty() => {
            let last = kenter_ui::camera::remembered();
            for (i, name) in &list {
                let mark = match &last {
                    Some(l) if l == name => "  <- last used",
                    _ => "",
                };
                println!("  [{i}] {name}{mark}");
            }
            println!();
        }
        Ok(_) => println!("no cameras found\n"),
        Err(e) => println!("could not list cameras: {e}\n"),
    }

    let proxy = event_loop.create_proxy();
    let mut app = Lab {
        proxy,
        window: None,
        surface: None,
        capture: None,
        frame: None,
        seen: BTreeSet::new(),
        which: 0,
        mood: Mood::Starting,
        lit: None,
        last_item: None,
        items_total: 9,
        frames: 0,
        reads: 0,
        started: Instant::now(),
        last_report: Instant::now(),
    };
    event_loop.run_app(&mut app).expect("run");
}

/// What the window is doing, as a colour.
#[derive(PartialEq)]
enum Mood {
    Starting,
    Live,
    Broken,
}

impl Mood {
    fn colour(&self) -> u32 {
        match self {
            // Blue-grey: waiting. Amber: broken, press space. Distinct, so
            // a black window never means all three at once.
            Mood::Starting => 0x0014_2030,
            Mood::Live => 0x0010_1418,
            Mood::Broken => 0x0030_1c0c,
        }
    }
}

struct Lab {
    proxy: EventLoopProxy<CamEvent>,
    window: Option<Rc<Window>>,
    surface: Option<softbuffer::Surface<Rc<Window>, Rc<Window>>>,
    capture: Option<Capture>,
    /// Latest preview: width, height, luminance.
    frame: Option<(u32, u32, Vec<u8>)>,
    /// Which (wallet, item, symbol) triples have been read, so a symbol
    /// held in frame for a second does not print sixty times.
    ///
    /// The wallet belongs in the key. Every sheet numbers its items from
    /// zero, so without it a second sheet's item 2 is silently
    /// swallowed as a duplicate of the first sheet's -- which is
    /// exactly what happened the first time two sheets met this.
    seen: BTreeSet<(String, u16, u16)>,
    /// Which camera of [`kenter_ui::camera::cameras`] is open.
    which: usize,
    /// What the window should be saying when there is no picture. With
    /// no text rendering here, the background colour is the only way to
    /// tell "starting" from "broken" from "pointed at something dark".
    mood: Mood,
    /// When a symbol last landed. The window flashes green for a moment
    /// after, because the holder is looking at the paper and the window,
    /// not at a terminal behind them.
    lit: Option<Instant>,
    /// Which item flashed most recently, so the strip can mark it apart
    /// from the ones already collected.
    last_item: Option<u16>,
    /// How many items the sheet says it has, learned from the first
    /// symbol read. Nine until something says otherwise.
    items_total: u16,
    frames: u64,
    reads: u64,
    started: Instant,
    last_report: Instant,
}

impl ApplicationHandler<CamEvent> for Lab {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }
        let attrs = Window::default_attributes()
            .with_title("paper lab - viewfinder")
            .with_inner_size(winit::dpi::LogicalSize::new(720.0, 540.0));
        let window = Rc::new(event_loop.create_window(attrs).expect("window"));
        let context = softbuffer::Context::new(window.clone()).expect("context");
        let surface = softbuffer::Surface::new(&context, window.clone()).expect("surface");
        self.window = Some(window);
        self.surface = Some(surface);

        // Start the cycle where the remembered camera actually is, so
        // the first press moves to a different one rather than reopening
        // the same device.
        if let (Ok(list), Some(last)) = (
            kenter_ui::camera::cameras(),
            kenter_ui::camera::remembered(),
        ) {
            if let Some(i) = list.iter().position(|(_, n)| *n == last) {
                self.which = i;
            }
        }
        self.open(None);
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, e: CamEvent) {
        match e {
            CamEvent::Opened {
                name,
                width,
                height,
                px_per_module,
            } => {
                println!("camera: {name}");
                println!("format: {width}x{height}");
                println!(
                    "budget: {px_per_module:.2} px/module with a symbol filling the frame \
                     (4 is the floor)\n"
                );
            }

            CamEvent::Preview {
                width,
                height,
                luma,
            } => {
                self.frames += 1;
                self.mood = Mood::Live;
                self.frame = Some((width, height, luma));
                if let Some(w) = &self.window {
                    w.request_redraw();
                }
                // A heartbeat, so a silent window is distinguishable from
                // a stalled one.
                if self.last_report.elapsed().as_secs() >= 5 {
                    println!(
                        "  .. {} frames, {:.1} fps, {} symbols read",
                        self.frames,
                        self.frames as f32 / self.started.elapsed().as_secs_f32(),
                        self.reads
                    );
                    self.last_report = Instant::now();
                }
            }

            CamEvent::Symbol(s) => {
                self.reads += 1;
                self.lit = Some(Instant::now());
                self.last_item = Some(s.item);
                self.items_total = s.items.max(1);
                if self.seen.insert((s.wallet.clone(), s.item, s.index)) {
                    println!(
                        "READ  wallet {}  item {} of {}, symbol {} of {}   [{} distinct]",
                        s.wallet,
                        s.item + 1,
                        s.items,
                        s.index + 1,
                        s.total,
                        self.seen.len()
                    );
                }
            }

            CamEvent::Shot {
                width,
                height,
                luma,
            } => {
                // Named by the clock, so a run leaves an ordered series
                // rather than one file overwritten eight times.
                // `KENTER_PAPER_SHOTS`, else `target/paper-shots`.
                let dir = std::env::var_os("KENTER_PAPER_SHOTS")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| std::path::PathBuf::from("target").join("paper-shots"));
                let dir = dir.as_path();
                let _ = std::fs::create_dir_all(dir);
                let n = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let path = dir.join(format!("frame-{n}.png"));
                match image::GrayImage::from_raw(width, height, luma) {
                    Some(img) => match img.save(&path) {
                        Ok(()) => println!("saved {}", path.display()),
                        Err(e) => println!("could not save: {e}"),
                    },
                    None => println!("frame did not fit its own dimensions"),
                }
            }

            CamEvent::Trouble(why) => {
                println!("\ntrouble: {why}\n");
                // Not fatal on its own: the capture thread falls back to
                // another camera and reports this on the way past, so
                // only treat it as broken if nothing is arriving.
                if self.frames == 0 {
                    self.mood = Mood::Broken;
                }
                if let Some(w) = &self.window {
                    w.request_redraw();
                }
            }

            CamEvent::Closed => {
                println!("camera closed");
                if self.window.is_none() {
                    event_loop.exit();
                }
            }
        }
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        match event {
            // Space moves to the next camera. A Surface lists its rear
            // one first, and the rear one is the awkward one to hold a
            // page in front of.
            WindowEvent::KeyboardInput { event: key, .. }
                if key.state == ElementState::Pressed
                    && key.physical_key == PhysicalKey::Code(KeyCode::Space) =>
            {
                let list = kenter_ui::camera::cameras().unwrap_or_default();
                if list.len() < 2 {
                    println!("only one camera to choose from");
                    return;
                }
                self.which = (self.which + 1) % list.len();
                let (_, name) = list[self.which].clone();
                println!("\nswitching to [{}] {name}", self.which);
                // Dropped first, and dropping joins: two captures would
                // otherwise race for one device and the new one would
                // lose.
                self.capture = None;
                self.frame = None;
                self.frames = 0;
                self.mood = Mood::Starting;
                self.open(Some(name));
            }
            WindowEvent::CloseRequested => {
                // Drop the capture before leaving, so the device is
                // released rather than held until the process dies.
                self.capture = None;
                summarise(self);
                event_loop.exit();
            }
            // S for a full-resolution frame. The only honest test image
            // for this pipeline comes from the camera it runs on.
            WindowEvent::KeyboardInput { event: key, .. }
                if key.state == ElementState::Pressed
                    && key.physical_key == PhysicalKey::Code(KeyCode::KeyS) =>
            {
                match &self.capture {
                    Some(c) => {
                        c.grab();
                        println!("grabbing a frame...");
                    }
                    None => println!("no camera running"),
                }
            }

            WindowEvent::RedrawRequested => self.redraw(),
            _ => {}
        }
    }
}

impl Lab {
    /// Start capture, on a named camera or on whichever is remembered.
    fn open(&mut self, want: Option<String>) {
        let proxy = self.proxy.clone();
        self.capture = Some(Capture::start_on(want, move |e| {
            let _ = proxy.send_event(e);
        }));
    }

    fn redraw(&mut self) {
        let (Some(window), Some(surface)) = (&self.window, &mut self.surface) else {
            return;
        };
        let size = window.inner_size();
        let (w, h) = (size.width.max(1), size.height.max(1));
        surface
            .resize(NonZeroU32::new(w).unwrap(), NonZeroU32::new(h).unwrap())
            .unwrap();
        let mut buffer = surface.buffer_mut().unwrap();
        buffer.fill(self.mood.colour());

        // Half a second is long enough to catch out of the corner of an
        // eye and short enough not to blur one read into the next.
        let hit = self
            .lit
            .is_some_and(|t| t.elapsed() < std::time::Duration::from_millis(500));
        if let Some((fw, fh, luma)) = &self.frame {
            // Fit, keep the aspect, centre. Stretching would lie about
            // framing, and framing is the whole point of looking.
            let scale = (w as f32 / *fw as f32).min(h as f32 / *fh as f32);
            let (dw, dh) = ((*fw as f32 * scale) as u32, (*fh as f32 * scale) as u32);
            let (ox, oy) = ((w - dw.min(w)) / 2, (h - dh.min(h)) / 2);
            for y in 0..dh.min(h) {
                let sy = ((y as f32 / scale) as u32).min(fh - 1);
                for x in 0..dw.min(w) {
                    let sx = ((x as f32 / scale) as u32).min(fw - 1);
                    let v = luma[(sy * fw + sx) as usize] as u32;
                    buffer[((oy + y) * w + ox + x) as usize] = if hit {
                        (v / 3 << 16) | (v << 8) | (v / 3)
                    } else {
                        (v << 16) | (v << 8) | v
                    };
                }
            }
        }
        // A cell per item along the bottom: dark means not yet read,
        // green means collected, bright green is the one that just
        // landed. "It flashed" is not an answer to "which one was it",
        // and holding a sheet is no time to read a terminal.
        let n = self.items_total as u32;
        let strip = 34u32.min(h / 6);
        let top = h.saturating_sub(strip);
        let gap = 3u32;
        let cell = (w.saturating_sub(gap * (n + 1))) / n.max(1);
        for i in 0..n {
            let got = self.seen.iter().any(|(_, item, _)| *item as u32 == i);
            let just = hit && self.last_item.is_some_and(|l| l as u32 == i);
            let colour = if just {
                0x0060_ff80
            } else if got {
                0x0020_7a40
            } else {
                0x0024_2a33
            };
            let x0 = gap + i * (cell + gap);
            for y in (top + gap)..(h.saturating_sub(gap)) {
                for x in x0..(x0 + cell).min(w) {
                    buffer[(y * w + x) as usize] = colour;
                }
            }
        }

        window.pre_present_notify();
        buffer.present().unwrap();
    }
}

fn summarise(lab: &Lab) {
    println!("\n---");
    println!(
        "{} frames in {:.1}s ({:.1} fps)",
        lab.frames,
        lab.started.elapsed().as_secs_f32(),
        lab.frames as f32 / lab.started.elapsed().as_secs_f32().max(0.001)
    );
    if lab.frames == 0 {
        // The old text offered advice about density here, which is
        // nonsense when no frame ever arrived: nothing was looked at, so
        // nothing can be concluded about what can be read.
        println!("no frames arrived - the camera never streamed, so this says");
        println!("nothing about density or focus. Usually the device is held by");
        println!("something else; close it, or press space for another camera.");
    } else if lab.seen.is_empty() {
        println!("{} frames, no symbols read.", lab.frames);
        println!(
            "The camera worked, so this IS a reading failure: either the symbol\n\
             did not fill the frame, or it is too dense. Print calibration.pdf\n\
             and work down the items until one reads."
        );
    } else {
        let items: BTreeSet<(String, u16)> =
            lab.seen.iter().map(|(w, i, _)| (w.clone(), *i)).collect();
        println!("distinct symbols: {}", lab.seen.len());
        println!("items seen: {items:?}");
        println!(
            "On a calibration sheet the items run densest first, so the LOWEST\n\
             number here is the density this camera can be relied on for."
        );
    }
}
