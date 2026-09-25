"""Draw the app icon (the UI's pulse-line mark) and build AppIcon.icns with iconutil."""
import os
import shutil
import subprocess
import tempfile

from PIL import Image, ImageDraw, ImageFilter

SIZE = 1024


def draw(size: int = SIZE) -> Image.Image:
    scale = size / 32
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    # macOS icon grid: the tile sits inside a ~10% margin with rounded corners
    margin, radius = size * 0.1, size * 0.18
    tile = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(tile)
    d.rounded_rectangle([margin, margin, size - margin, size - margin], radius=radius, fill=(16, 22, 43, 255),
                        outline=(35, 44, 79, 255), width=int(size * 0.008))
    img.alpha_composite(tile)
    inner = (size - 2 * margin) / 32
    pts = [(5, 20), (10, 20), (13, 11), (17, 24), (20, 16), (27, 16)]
    pts = [(margin + x * inner, margin + y * inner) for x, y in pts]
    glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    ImageDraw.Draw(glow).line(pts, fill=(94, 230, 255, 170), width=int(inner * 3.2), joint="curve")
    img.alpha_composite(glow.filter(ImageFilter.GaussianBlur(size * 0.02)))
    line = ImageDraw.Draw(img)
    line.line(pts, fill=(94, 230, 255, 255), width=int(inner * 2.2), joint="curve")
    for x, y in (pts[0], pts[-1]):
        r = inner * 1.1
        line.ellipse([x - r, y - r, x + r, y + r], fill=(94, 230, 255, 255))
    return img


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    base = draw()
    base.save(os.path.join(here, "icon.png"))
    iconset = os.path.join(tempfile.mkdtemp(), "AppIcon.iconset")
    os.makedirs(iconset)
    for s in (16, 32, 128, 256, 512):
        base.resize((s, s), Image.LANCZOS).save(os.path.join(iconset, f"icon_{s}x{s}.png"))
        base.resize((s * 2, s * 2), Image.LANCZOS).save(os.path.join(iconset, f"icon_{s}x{s}@2x.png"))
    subprocess.run(["iconutil", "-c", "icns", iconset, "-o", os.path.join(here, "AppIcon.icns")], check=True)
    shutil.rmtree(os.path.dirname(iconset))
    print("wrote AppIcon.icns and icon.png")


if __name__ == "__main__":
    main()
