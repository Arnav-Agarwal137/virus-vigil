"""Builds the QR test pictures for qr.rs (B8). Encoder: segno (independent of the rqrr decoder under test).
Run: PYTHONPATH=<folder with segno> python make_qr.py   (segno is not needed by the app itself)
Writes qr-*.png / .jpg next to this file and qr-cases.json with what each picture must decode to."""
import io, json, pathlib
import segno
from PIL import Image, ImageDraw

here = pathlib.Path(__file__).parent
cases = []

def png(name, text, scale=8):
    buf = io.BytesIO()
    segno.make(text, error="m").save(buf, kind="png", scale=scale, border=4)
    buf.seek(0)
    return Image.open(buf).convert("RGB")

def save(img, name, codes, fmt="PNG"):
    img.save(here / name, fmt)
    cases.append({"file": name, "codes": codes})

upi = "upi://pay?pa=refund.desk@okaxis&pn=Refund%20Desk&am=5000&cu=INR&tn=Claim%20refund"
url = "https://bit.ly/3xYz-parcel"
save(png("upi", upi), "qr-upi.png", [upi])
save(png("url", url), "qr-url.png", [url])
# A phone photo: big canvas, grey background, the code small and off-centre, saved as JPEG.
photo = Image.new("RGB", (3000, 2200), (170, 170, 165))
code = png("p", url, scale=6)
photo.paste(code, (1900, 1300))
ImageDraw.Draw(photo).rectangle([100, 100, 900, 700], fill=(40, 90, 160))
save(photo, "qr-photo.jpg", [url], "JPEG")
# Two different codes in one picture.
two = Image.new("RGB", (900, 450), "white")
two.paste(png("a", upi, scale=5), (0, 0))
two.paste(png("b", url, scale=5), (470, 0))
save(two, "qr-two.png", [upi, url])
# No QR code at all.
plain = Image.new("RGB", (400, 300), "white")
ImageDraw.Draw(plain).ellipse([50, 50, 350, 250], fill=(200, 60, 60))
save(plain, "qr-none.png", [])
# Not a picture, named like one.
(here / "qr-broken.png").write_bytes(b"this is not a picture")
cases.append({"file": "qr-broken.png", "codes": [], "unreadable": True})

(here / "qr-cases.json").write_text(json.dumps(cases, indent=1), encoding="utf-8")
print(len(cases), "cases")
