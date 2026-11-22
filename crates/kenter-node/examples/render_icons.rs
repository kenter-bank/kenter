//! Render the node's icons from the Kenter logo skin
//! (`crates/kenter-ui/skins/kenter/logo.svg`):
//!
//! - `packaging/assets/kenter.ico`: 16 to 256 px, PNG-compressed entries,
//!   for the installer and its shortcuts;
//! - `crates/kenter-node/assets/tray-logo-32.rgba`: 32×32 straight RGBA,
//!   embedded in the tray, which paints a status dot over it at runtime.
//!
//! The SVG is the source of truth: re-run after the artist changes it.
//!
//! ```sh
//! cargo run -p kenter-node --example render_icons
//! ```

use std::path::PathBuf;

use resvg::tiny_skia::{Pixmap, Transform};
use resvg::usvg;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo = crate_dir.join("../..");
    let svg = std::fs::read(repo.join("crates/kenter-ui/skins/kenter/logo.svg"))?;
    let tree = usvg::Tree::from_data(&svg, &usvg::Options::default())?;

    let render = |size: u32| -> Result<Pixmap, Box<dyn std::error::Error>> {
        let mut px = Pixmap::new(size, size).ok_or("pixmap")?;
        let s = tree.size();
        let t = Transform::from_scale(size as f32 / s.width(), size as f32 / s.height());
        resvg::render(&tree, t, &mut px.as_mut());
        Ok(px)
    };

    // The .ico: a directory of PNGs (Windows Vista and later read these).
    let sizes = [16u32, 24, 32, 48, 64, 256];
    let pngs: Vec<Vec<u8>> = sizes
        .iter()
        .map(|&s| render(s).and_then(|p| Ok(p.encode_png()?)))
        .collect::<Result<_, _>>()?;
    let mut ico = Vec::new();
    ico.extend_from_slice(&[0, 0, 1, 0]);
    ico.extend_from_slice(&(sizes.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * sizes.len() as u32;
    for (&s, png) in sizes.iter().zip(&pngs) {
        let dim = if s >= 256 { 0 } else { s as u8 };
        ico.extend_from_slice(&[dim, dim, 0, 0]);
        ico.extend_from_slice(&1u16.to_le_bytes()); // planes
        ico.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
        ico.extend_from_slice(&(png.len() as u32).to_le_bytes());
        ico.extend_from_slice(&offset.to_le_bytes());
        offset += png.len() as u32;
    }
    for png in &pngs {
        ico.extend_from_slice(png);
    }
    let ico_path = repo.join("packaging/assets/kenter.ico");
    std::fs::create_dir_all(ico_path.parent().unwrap())?;
    std::fs::write(&ico_path, &ico)?;

    // The tray's base image: straight (not premultiplied) RGBA.
    let tray = render(32)?;
    let rgba: Vec<u8> = tray
        .pixels()
        .iter()
        .flat_map(|p| {
            let c = p.demultiply();
            [c.red(), c.green(), c.blue(), c.alpha()]
        })
        .collect();
    let tray_path = crate_dir.join("assets/tray-logo-32.rgba");
    std::fs::create_dir_all(tray_path.parent().unwrap())?;
    std::fs::write(&tray_path, &rgba)?;

    println!("wrote {} ({} bytes)", ico_path.display(), ico.len());
    println!("wrote {} ({} bytes)", tray_path.display(), rgba.len());
    Ok(())
}
