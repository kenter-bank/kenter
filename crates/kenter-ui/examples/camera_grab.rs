//! Prove we can get pixels without the C decoder, and read a symbol.
//!
//! Enumerating formats is not the same as receiving frames: `decoding` is
//! off (see `Cargo.toml`), so this checks that raw NV12 still arrives and
//! that its Y plane is directly usable.
//!
//! Hold one symbol of a printed sheet up to the camera, filling the frame.
//!
//! Run: `cargo run -p kenter-ui --example camera_grab`

use nokhwa::pixel_format::LumaFormat;
use nokhwa::utils::{ApiBackend, RequestedFormat, RequestedFormatType, Resolution};
use nokhwa::Camera;

fn main() {
    let cams = nokhwa::query(ApiBackend::Auto).expect("enumerate");
    let Some(info) = cams.first() else {
        println!("no cameras");
        return;
    };
    println!("opening {}", info.human_name());

    // Highest raw resolution: 6.62 px/module at 1920x1440 on this machine,
    // against a floor near 4 (`camera_probe`).
    let mut cam = Camera::new(
        info.index().clone(),
        RequestedFormat::new::<LumaFormat>(RequestedFormatType::Closest(
            nokhwa::utils::CameraFormat::new(
                Resolution::new(1920, 1440),
                nokhwa::utils::FrameFormat::NV12,
                30,
            ),
        )),
    )
    .expect("open camera");

    cam.open_stream().expect("stream");
    println!("format: {:?}", cam.camera_format());

    // A few frames: the first off a webcam is routinely black or
    // mid-exposure, and reporting that as a decode failure would be a lie.
    let start = std::time::Instant::now();
    let mut grabbed = 0u32;
    for i in 0..30 {
        let frame = cam.frame().expect("frame");
        grabbed += 1;
        if grabbed % 10 == 0 {
            println!(
                "  -- {grabbed} frames in {:.2}s ({:.1} fps)",
                start.elapsed().as_secs_f32(),
                grabbed as f32 / start.elapsed().as_secs_f32()
            );
        }
        let raw = frame.buffer();
        let res = frame.resolution();

        // NV12 is a full-resolution Y plane followed by interleaved
        // chroma. Luminance alone is what a QR reader wants.
        let luma: Vec<u8> = if raw.len() >= (res.width_x * res.height_y) as usize {
            raw[..(res.width_x * res.height_y) as usize].to_vec()
        } else {
            println!("  frame {i}: {} bytes, too short for a Y plane", raw.len());
            continue;
        };

        let img = image::GrayImage::from_raw(res.width_x, res.height_y, luma).expect("wrap");
        let mut prep = rqrr::PreparedImage::prepare(img);
        let grids = prep.detect_grids();
        let bright = prep_brightness(&frame.buffer()[..64]);

        if let Some(g) = grids.first() {
            let mut out = Vec::new();
            match g.decode_to(&mut out) {
                Ok(_) => {
                    println!(
                        "  frame {i}: READ {} bytes, header {:?}",
                        out.len(),
                        String::from_utf8_lossy(&out[..out.len().min(4)])
                    );
                    return;
                }
                Err(e) => println!("  frame {i}: grid found, not decodable: {e}"),
            }
        } else if i % 5 == 0 {
            println!(
                "  frame {i}: {}x{}, {} bytes, no symbol yet (avg {bright})",
                res.width_x,
                res.height_y,
                raw.len()
            );
        }
    }
    println!("no symbol read - pixels are arriving if the sizes above look right");
}

fn prep_brightness(head: &[u8]) -> u32 {
    head.iter().map(|b| *b as u32).sum::<u32>() / head.len().max(1) as u32
}
