//! Render one skin at a chosen size, for looking at an icon bigger than
//! the UI draws it.
//!
//! ```text
//! cargo run -p kenter-ui --example skin_preview -- logo 192 out.png
//! ```

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let name = args.get(1).map(String::as_str).unwrap_or("logo");
    let size: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(192);
    let out = args.get(3).cloned().unwrap_or_else(|| format!("{name}-{size}.png"));
    let path = format!("{}/skins/kenter/{name}.svg", env!("CARGO_MANIFEST_DIR"));
    if std::env::var("SKIN_DUMP").is_ok() { dump(&path); }
    let pelt = pelt::Pelt::load(&path).expect("skin");
    let img = pelt.render(size, size).expect("render");
    std::fs::write(&out, img.encode_png().expect("png")).expect("write");
    println!("wrote {out}");
}

#[allow(dead_code)]
fn dump(path: &str) {
    let src = std::fs::read_to_string(path).unwrap();
    let f = pelt::render::filter_svg_state(&src, "default");
    let r = pelt::token_resolver::resolve_tokens(&f, &Default::default());
    println!("{r}");
}
