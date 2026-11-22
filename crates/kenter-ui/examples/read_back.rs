//! Read captured images and say which symbols survived.
//!
//! The companion to `calibration_sheet`: it reports per image what was
//! found, at what size, so a failed capture says *which density* failed
//! rather than just "nothing read". Needs no wallet and no key — it
//! stops at the symbol header, which is cleartext.
//!
//! Run: `cargo run -p kenter-ui --example read_back -- photo1.jpg ...`

fn main() {
    let paths: Vec<std::path::PathBuf> = std::env::args_os().skip(1).map(Into::into).collect();
    if paths.is_empty() {
        eprintln!("give me some image files");
        std::process::exit(2);
    }

    let mut read: Vec<u16> = Vec::new();
    for path in &paths {
        let img = match image::open(path) {
            Ok(i) => i,
            Err(e) => {
                println!("{}: cannot open - {e}", path.display());
                continue;
            }
        };
        let (w, h) = (img.width(), img.height());
        // Both readers on the same pixels. The whole-image one trips over
        // neighbouring symbols on a multi-symbol page -- it can return one
        // of nine, with the LEAST dense failing first -- so the comparison
        // is the point, not a nicety.
        let found = kenter_ui::scan::read_page(&img);

        // Pixels across the long side is what the file path's floor is
        // quoted in, so print it next to the result.
        println!(
            "{}: {w}x{h} - {} ours, {} unreadable, {} not ours",
            path.display(),
            found.symbols.len(),
            found.unreadable,
            found.foreign
        );
        for s in &found.symbols {
            println!(
                "    item {} of {}, symbol {} of {}",
                s.item + 1,
                s.items,
                s.index + 1,
                s.total
            );
            read.push(s.item);
        }
    }

    read.sort_unstable();
    read.dedup();
    println!("\nitems that came back: {read:?}");
    println!(
        "On a calibration sheet the items run densest first, so the lowest\n\
         number that reads is the density we can rely on."
    );
}
