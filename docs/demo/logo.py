#!/usr/bin/env python3
"""Gera docs/assets/logo.png e banner.png (1280x640, também serve de prévia social do GitHub).
A geometria é a mesma de docs/assets/logo.svg. Requer: pillow."""

import math
import os

from PIL import Image, ImageDraw, ImageFilter, ImageFont

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets")
MONO = os.environ.get("NSCOPE_FONT_BOLD", os.path.expanduser("~/.local/share/fonts/JetBrainsMonoNF/JetBrainsMonoNerdFont-Bold.ttf"))
SANS = "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf"
SANS_B = "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf"


def icon(size):
    """Ícone em RGBA (supersample 4x)."""
    k = 4 * size / 256
    im = Image.new("RGBA", (int(256 * k), int(256 * k)), (0, 0, 0, 0))
    g = Image.new("RGBA", im.size)
    gd = ImageDraw.Draw(g)
    for y in range(im.height):  # degradê diagonal simples
        t = y / im.height
        gd.line((0, y, im.width, y), fill=(int(18 + (8 - 18) * t), int(52 + (20 - 52) * t), int(92 + (38 - 92) * t), 255))
    mask = Image.new("L", im.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, im.width - 1, im.height - 1), 58 * k, fill=255)
    im.paste(g, (0, 0), mask)
    d = ImageDraw.Draw(im, "RGBA")
    d.rounded_rectangle((2 * k, 2 * k, 254 * k, 254 * k), 56 * k, outline=(56, 189, 248, 90), width=int(3 * k))
    cx = cy = 128 * k
    sweep = Image.new("RGBA", im.size, (0, 0, 0, 0))
    sd = ImageDraw.Draw(sweep)
    for i in range(60):  # cunha do radar com degradê radial
        r = 78 * k * (1 - i / 60)
        sd.pieslice((cx - r, cy - r, cx + r, cy + r), -90, -35, fill=(125, 211, 252, int(70 / 60 * 1 + 4)))
    im.alpha_composite(sweep)
    d = ImageDraw.Draw(im, "RGBA")
    for r, col, w in [(78, (125, 211, 252, 255), 8), (48, (56, 189, 248, 205), 5)]:
        d.ellipse((cx - r * k, cy - r * k, cx + r * k, cy + r * k), outline=col, width=int(w * k))
    for a, b in [((128, 26), (128, 60)), ((128, 196), (128, 230)), ((26, 128), (60, 128)), ((196, 128), (230, 128))]:
        d.line((a[0] * k, a[1] * k, b[0] * k, b[1] * k), fill=(186, 230, 253, 255), width=int(8 * k))
        for p in (a, b):
            d.ellipse((p[0] * k - 4 * k, p[1] * k - 4 * k, p[0] * k + 4 * k, p[1] * k + 4 * k), fill=(186, 230, 253, 255))
    d.ellipse((cx - 16 * k, cy - 16 * k, cx + 16 * k, cy + 16 * k), fill=(224, 242, 254, 255))
    d.ellipse(((171 - 8) * k, (84 - 8) * k, (171 + 8) * k, (84 + 8) * k), fill=(186, 230, 253, 255))
    d.ellipse(((171 - 15) * k, (84 - 15) * k, (171 + 15) * k, (84 + 15) * k), outline=(186, 230, 253, 128), width=int(3 * k))
    d.ellipse(((90 - 6) * k, (160 - 6) * k, (90 + 6) * k, (160 + 6) * k), fill=(125, 211, 252, 255))
    return im.resize((size, size), Image.LANCZOS)


def banner(w=1280, h=640):
    bg = Image.linear_gradient("L").rotate(90).resize((w, h))
    base = Image.merge("RGB", [bg.point(lambda v, a=a, b=b: int(a + (b - a) * v / 255)) for a, b in zip((10, 30, 62), (5, 12, 26))])
    glow = Image.radial_gradient("L").resize((900, 900)).point(lambda v: max(0, 255 - v * 255 // 180) * 90 // 255)
    base.paste(Image.new("RGB", glow.size, (56, 189, 248)), (-120, -260), glow)
    base.paste(Image.new("RGB", glow.size, (37, 99, 235)), (w - 560, h - 560), glow)
    d = ImageDraw.Draw(base, "RGBA")
    for x in range(20, w, 40):  # grade de pontos discreta
        for y in range(20, h, 40):
            d.ellipse((x - 1, y - 1, x + 1, y + 1), fill=(125, 211, 252, 28))
    ic = icon(300)
    sh = Image.new("RGBA", (360, 360), (0, 0, 0, 0))
    ImageDraw.Draw(sh).rounded_rectangle((30, 40, 330, 340), 70, fill=(56, 189, 248, 70))
    sh = sh.filter(ImageFilter.GaussianBlur(26))
    base.paste(sh, (110, 140), sh)
    base.paste(ic, (140, 170), ic)
    f = ImageFont.truetype(MONO, 150)
    d.text((480, 255), "nscope", font=f, fill=(125, 211, 252, 255), anchor="lm")
    d.text((486, 365), "O nmap sem decorar flags.", font=ImageFont.truetype(SANS_B, 46), fill=(226, 240, 255, 255), anchor="lm")
    d.text((486, 428), "Interface de terminal em português que monta, explica", font=ImageFont.truetype(SANS, 28), fill=(148, 190, 225, 255), anchor="lm")
    d.text((486, 466), "e executa o nmap com segurança.", font=ImageFont.truetype(SANS, 28), fill=(148, 190, 225, 255), anchor="lm")
    x = 486
    for txt in ["TUI", "Rust", "pt-BR", "sem telemetria"]:
        f2 = ImageFont.truetype(SANS_B, 24)
        tw = int(f2.getlength(txt)) + 40
        d.rounded_rectangle((x, 510, x + tw, 556), 23, fill=(14, 52, 92, 255), outline=(56, 189, 248, 200), width=2)
        d.text((x + tw / 2, 533), txt, font=f2, fill=(186, 230, 253, 255), anchor="mm")
        x += tw + 16
    return base


if __name__ == "__main__":
    icon(512).save(os.path.join(OUT, "logo.png"), optimize=True)
    banner().save(os.path.join(OUT, "banner.png"), optimize=True)
    print("ok")
