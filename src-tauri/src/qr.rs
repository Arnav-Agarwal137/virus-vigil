// QR codes in a picture (B8). Decoded here, on this laptop - the picture never leaves it.
// The page then runs its own link / UPI / scam checks on the text found inside.

use serde_json::{json, Value};
use std::path::Path;

pub const IMAGE_EXTS: [&str; 6] = ["png", "jpg", "jpeg", "webp", "bmp", "gif"];

fn codes_in(img: &image::GrayImage) -> Vec<String> {
    let (w, h) = img.dimensions();
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(w as usize, h as usize, |x, y| img.get_pixel(x as u32, y as u32)[0]);
    let mut out = Vec::new();
    for g in prepared.detect_grids() {
        if let Ok((_, text)) = g.decode() {
            if !out.contains(&text) {
                out.push(text);
            }
        }
    }
    out
}

/// {read, codes: [text...], error?}. read=false means the picture itself could not be opened,
/// which is different from "opened, no QR code in it" (read=true, codes=[]).
pub fn read(path: &Path) -> Value {
    let img = match image::open(path) {
        Ok(i) => i.to_luma8(),
        Err(e) => return json!({"read": false, "codes": [], "error": format!("could not open the picture: {e}")}),
    };
    let mut codes = codes_in(&img);
    // Big phone photos: a smaller copy often decodes when the full one does not.
    let (w, h) = img.dimensions();
    if codes.is_empty() && w.max(h) > 1400 {
        let scale = 1200.0 / w.max(h) as f32;
        let small = image::imageops::resize(&img, (w as f32 * scale) as u32, (h as f32 * scale) as u32, image::imageops::FilterType::Triangle);
        codes = codes_in(&small);
    }
    json!({"read": true, "codes": codes, "size": [w, h]})
}
