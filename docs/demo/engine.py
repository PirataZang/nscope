"""Motor que grava o nscope de verdade num pseudo-terminal e rende vídeo (30 fps) com
cursor de mouse animado, cliques, teclas na tela, legendas e zoom dinâmico.

Só para desenvolvimento (não faz parte do binário). Requer: python3, pyte, pillow, ffmpeg.
Nada aqui é falso: o nscope roda de verdade (com o nmap instalado); gravamos o que ele desenha.
"""

import fcntl
import hashlib
import math
import multiprocessing as mp
import os
import pty
import select
import struct
import subprocess
import termios
import time
from functools import lru_cache

import pyte
from PIL import Image, ImageDraw, ImageFilter, ImageFont

FPS = 30
OUT_W, OUT_H = 1920, 1080
S = 2  # a cena é desenhada em 2x e reduzida na saída (zoom sem borrar)
SCENE_W, SCENE_H = OUT_W * S, OUT_H * S
CELL_W, CELL_H = 33, 54  # px por célula na cena (2x)
TITLE_H = 80
PAD = 40  # respiro entre a borda da janela e o terminal
TOP_SHIFT = 70  # desce a janela para sobrar espaço à legenda no topo

FONT_REG = os.environ.get("NSCOPE_FONT", os.path.expanduser("~/.local/share/fonts/JetBrainsMonoNF/JetBrainsMonoNerdFont-Regular.ttf"))
FONT_BOLD = os.environ.get("NSCOPE_FONT_BOLD", os.path.expanduser("~/.local/share/fonts/JetBrainsMonoNF/JetBrainsMonoNerdFont-Bold.ttf"))
SHADES = {"█": 1.0, "▓": 0.75, "▒": 0.5, "░": 0.25}
FONT_FALLBACK = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
SANS_BOLD = "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf"
SANS = "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf"

BG = (11, 18, 32)
FG = (203, 213, 225)
PALETTE = {
    "black": (30, 41, 59), "red": (248, 113, 113), "green": (74, 222, 128), "brown": (251, 191, 36),
    "blue": (96, 165, 250), "magenta": (192, 132, 252), "cyan": (34, 211, 238), "white": (226, 232, 240),
    "brightblack": (100, 116, 139), "brightred": (252, 165, 165), "brightgreen": (134, 239, 172),
    "brightbrown": (253, 230, 138), "brightyellow": (253, 230, 138), "brightblue": (147, 197, 253),
    "brightmagenta": (216, 180, 254), "brightcyan": (103, 232, 249), "brightwhite": (248, 250, 252),
}
LIGHT_BLUE = (125, 211, 252)

KEYS = {
    "enter": b"\r", "tab": b"\t", "esc": b"\x1b", "up": b"\x1b[A", "down": b"\x1b[B",
    "right": b"\x1b[C", "left": b"\x1b[D", "backspace": b"\x7f", "ctrl-c": b"\x03", "space": b" ",
    "shift-tab": b"\x1b[Z",
}
KEYCAP = {"enter": "Enter", "tab": "Tab", "esc": "Esc", "up": "↑", "down": "↓", "right": "→", "left": "←",
          "backspace": "⌫", "ctrl-c": "Ctrl+C", "space": "Espaço", "shift-tab": "Shift+Tab"}


def ease(t):
    t = min(max(t, 0.0), 1.0)
    return t * t * (3 - 2 * t)


def color_of(name, default):
    if name == "default":
        return default
    if name in PALETTE:
        return PALETTE[name]
    try:
        return tuple(int(name[i:i + 2], 16) for i in (0, 2, 4))
    except (ValueError, TypeError):
        return default


def origin(cols, rows):
    """Canto (px da cena) da célula 0,0 do terminal dentro da janela."""
    ww, wh = cols * CELL_W + 2 * PAD, rows * CELL_H + TITLE_H + PAD
    return (SCENE_W - ww) / 2 + PAD, (SCENE_H - wh) / 2 + TITLE_H + TOP_SHIFT


# --------------------------------------------------------------------------- gravação

class Demo:
    """Controla o nscope num pty e guarda um quadro por 1/30 s."""

    def __init__(self, cols=100, rows=30, cmd=("nscope",), cwd=None, env=None):
        self.cols, self.rows = cols, rows
        self.screen = pyte.Screen(cols, rows)
        self.stream = pyte.ByteStream(self.screen)
        self.frames = []
        self.n = 0
        self.t0 = None
        self.cursor = (cols / 2, rows / 2)  # em células (float)
        self.click_at = -10.0
        self.keycap = ("", -10.0)
        self.caption_state = ("", 0.0, None)  # texto, desde, até
        self.cam_from = self.cam_to = self._box(None)
        self.cam_t0, self.cam_dur = 0.0, 0.0
        e = dict(os.environ, TERM="xterm-256color", COLORTERM="truecolor", LANG="pt_BR.UTF-8")
        e.update(env or {})
        pid, fd = pty.fork()
        if pid == 0:
            if cwd:
                os.chdir(cwd)
            os.execvpe(cmd[0], list(cmd), e)
        self.pid, self.fd = pid, fd
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        os.set_blocking(fd, False)

    # ---- tempo
    @property
    def now(self):
        return self.n / FPS

    def tick(self):
        """Avança um quadro: espera o relógio real, lê a saída do nscope e grava o estado."""
        if self.t0 is None:
            self.t0 = time.monotonic()
        deadline = self.t0 + (self.n + 1) / FPS
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            r, _, _ = select.select([self.fd], [], [], left)
            if r:
                self._read()
        self._read()
        self.n += 1
        self.frames.append(self._snapshot())

    def _read(self):
        try:
            data = os.read(self.fd, 65536)
            while data:
                self.stream.feed(data)
                data = os.read(self.fd, 65536)
        except (BlockingIOError, OSError):
            pass

    def _snapshot(self):
        buf = self.screen.buffer
        snap = tuple(tuple(buf[y][x] for x in range(self.cols)) for y in range(self.rows))
        c = self.screen.cursor
        t = self.now
        text, since, until = self.caption_state
        cap_alpha = 0.0
        if text:
            cap_alpha = min((t - since) / 0.35, 1.0)
            if until is not None:
                cap_alpha = min(cap_alpha, max((until - t) / 0.35, 0.0))
        return dict(
            snap=snap, text_cursor=(c.x, c.y, c.hidden), t=t, mouse=self.cursor,
            click_dt=t - self.click_at, key=self.keycap[0], key_dt=t - self.keycap[1],
            cam=self._cam(t), caption=text, cap_alpha=cap_alpha,
        )

    # ---- ações (todas síncronas: consomem quadros)
    def wait(self, sec):
        for _ in range(max(1, round(sec * FPS))):
            self.tick()

    def send(self, data):
        os.write(self.fd, data)

    def key(self, name, hold=0.45, show=True):
        self.send(KEYS.get(name, name.encode()))
        if show:
            self.keycap = (KEYCAP.get(name, name), self.now)
        self.wait(hold)

    def type(self, text, cps=11):
        for ch in text:
            self.send(ch.encode())
            self.wait(1 / cps)

    def text(self):
        return "\n".join(self.screen.display)

    def find(self, needle, nth=0):
        """Posição (coluna, linha), em células 1-based, do centro da n-ésima ocorrência do texto na tela."""
        hits = []
        for y, line in enumerate(self.screen.display):
            start = 0
            while (i := line.find(needle, start)) >= 0:
                hits.append((i + (len(needle) + 1) / 2, y + 1.0))
                start = i + 1
        if len(hits) <= nth:
            raise RuntimeError(f"texto não encontrado na tela: {needle!r}\n{self.text()}")
        return hits[nth]

    def wait_for(self, needle, timeout=90, speed=1):
        """Espera o texto aparecer. Com speed>1, a espera é acelerada no vídeo (só 1 quadro a cada `speed`)."""
        end = self.now + timeout
        while needle not in self.text():
            if self.now > end:
                raise RuntimeError(f"timeout esperando {needle!r}\n{self.text()}")
            self.tick()
            if speed > 1 and self.n % speed:
                self.frames.pop()

    def move(self, to, dur=0.8):
        x0, y0 = self.cursor
        x1, y1 = to
        n = max(1, round(dur * FPS))
        dx, dy = x1 - x0, y1 - y0
        dist = math.hypot(dx, dy) or 1
        nx, ny = -dy / dist, dx / dist  # curva suave: desvio perpendicular
        bend = min(3.0, dist * 0.12)
        for i in range(1, n + 1):
            e = ease(i / n)
            off = math.sin(math.pi * e) * bend
            self.cursor = (x0 + dx * e + nx * off, y0 + dy * e + ny * off)
            self.tick()
        self.cursor = (x1, y1)
        self._mouse(35, x1, y1, "M")

    def _mouse(self, code, x, y, kind):
        self.send(f"\x1b[<{code};{max(1, int(x + 0.5))};{max(1, int(y + 0.5))}{kind}".encode())

    def click(self, to, dur=0.8, pause=0.35):
        self.move(to, dur)
        self.click_at = self.now
        x, y = to
        self._mouse(0, x, y, "M")
        self.wait(0.08)
        self._mouse(0, x, y, "m")
        self.wait(pause)

    def click_text(self, needle, nth=0, **kw):
        self.click(self.find(needle, nth), **kw)

    def caption(self, text, sec=None):
        self.caption_state = (text, self.now, None if sec is None else self.now + sec) if text else ("", 0.0, None)

    def end_caption(self):
        text, since, _ = self.caption_state
        if text:
            self.caption_state = (text, since, self.now + 0.35)

    # ---- câmera
    def _box(self, cells, pad=1.5):
        """Caixa da cena (px) com proporção 16:9 que enquadra o retângulo de células (c0, r0, c1, r1)."""
        wx, wy = origin(self.cols, self.rows)
        if cells is None:
            return (0.0, 0.0, float(SCENE_W), float(SCENE_H))
        c0, r0, c1, r1 = cells
        x0, x1 = wx + (c0 - pad) * CELL_W, wx + (c1 + pad) * CELL_W
        y0, y1 = wy + (r0 - pad) * CELL_H, wy + (r1 + pad) * CELL_H
        w, h = x1 - x0, y1 - y0
        if w / h < OUT_W / OUT_H:
            nw = h * OUT_W / OUT_H
            x0, x1 = x0 - (nw - w) / 2, x1 + (nw - w) / 2
        else:
            nh = w * OUT_H / OUT_W
            y0, y1 = y0 - (nh - h) / 2, y1 + (nh - h) / 2
        w = min(x1 - x0, SCENE_W)
        h = w * OUT_H / OUT_W
        x0 = min(max(x0, 0), SCENE_W - w)
        y0 = min(max(y0, 0), SCENE_H - h)
        return (x0, y0, x0 + w, y0 + h)

    def focus(self, col, row, cols=60, dur=1.1, wait=False):
        """Zoom: centro na célula (col, row) (0-based) mostrando `cols` colunas de largura."""
        if cols >= self.cols + 4:
            return self.zoom(None, dur, wait=wait)
        ox, oy = origin(self.cols, self.rows)
        w = cols * CELL_W
        h = w * OUT_H / OUT_W
        wl, wt = ox - PAD, oy - TITLE_H  # janela
        ww, wh = self.cols * CELL_W + 2 * PAD, self.rows * CELL_H + TITLE_H + PAD
        cx, cy = ox + (col + 0.5) * CELL_W, oy + (row + 0.5) * CELL_H
        x0 = wl + (ww - w) / 2 if w >= ww else min(max(cx - w / 2, wl), wl + ww - w)
        y0 = wt + (wh - h) / 2 if h >= wh else min(max(cy - h / 2, wt), wt + wh - h)
        self.cam_from = self._cam(self.now)
        self.cam_to = (x0, y0, x0 + w, y0 + h)
        self.cam_t0, self.cam_dur = self.now, dur
        if wait:
            self.wait(dur)

    def zoom(self, cells=None, dur=1.1, pad=1.5, wait=False):
        self.cam_from = self._cam(self.now)
        self.cam_to = self._box(cells, pad)
        self.cam_t0, self.cam_dur = self.now, dur
        if wait:
            self.wait(dur)

    def _cam(self, t):
        e = ease((t - self.cam_t0) / self.cam_dur) if self.cam_dur > 0 else 1.0
        return tuple(a + (b - a) * e for a, b in zip(self.cam_from, self.cam_to))

    def close(self):
        try:  # Ctrl+C: o nscope encerra o nmap filho e apaga o temporário antes de sair
            os.write(self.fd, b"\x03")
            time.sleep(0.6)
        except OSError:
            pass
        try:
            os.kill(self.pid, 9)
        except OSError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except OSError:
            pass


# --------------------------------------------------------------------------- renderização

@lru_cache(maxsize=None)
def font(path, size):
    return ImageFont.truetype(path, size)


@lru_cache(maxsize=None)
def has_glyph(ch):
    """A fonte principal tem o glifo? (o 'tofu' do .notdef não conta)"""
    f = font(FONT_REG, 56)
    m, nd = f.getmask(ch), f.getmask("\uFFFE")
    return ch == " " or (m.getbbox() is not None and bytes(m) != bytes(nd))


@lru_cache(maxsize=1)
def base_scene(cols, rows):
    """Fundo degradê azul, brilhos, janela com barra de título e sombra."""
    grad = Image.linear_gradient("L").rotate(90).resize((SCENE_W, SCENE_H))
    bg = Image.merge("RGB", [grad.point(lambda v, a=a, b=b: int(a + (b - a) * v / 255)) for a, b in zip((8, 26, 60), (4, 10, 24))])
    for cx, cy, r, col, alpha in [(0.12, 0.08, 0.55, (56, 189, 248), 70), (0.9, 0.95, 0.6, (37, 99, 235), 80)]:
        glow = Image.radial_gradient("L").resize((int(SCENE_W * r * 2), int(SCENE_W * r * 2))).point(lambda v: max(0, 255 - v * 255 // 180))
        layer = Image.new("RGB", glow.size, col)
        mask = glow.point(lambda v: v * alpha // 255)
        bg.paste(layer, (int(SCENE_W * cx - glow.width / 2), int(SCENE_H * cy - glow.height / 2)), mask)
    tw, th = cols * CELL_W + 2 * PAD, rows * CELL_H + TITLE_H + PAD
    ox, oy = origin(cols, rows)
    wx, wy = int(ox - PAD), int(oy - TITLE_H)
    shadow = Image.new("L", (SCENE_W, SCENE_H), 0)
    ImageDraw.Draw(shadow).rounded_rectangle((wx, wy + 30, wx + tw, wy + th + 30), 36, fill=170)
    shadow = shadow.filter(ImageFilter.GaussianBlur(50))
    bg.paste(Image.new("RGB", bg.size, (0, 4, 14)), (0, 0), shadow)
    win = Image.new("RGBA", (tw, th), (0, 0, 0, 0))
    d = ImageDraw.Draw(win)
    d.rounded_rectangle((0, 0, tw - 1, th - 1), 36, fill=BG + (255,), outline=(51, 65, 85, 255), width=3)
    d.rounded_rectangle((0, 0, tw - 1, TITLE_H + 30), 36, fill=(22, 32, 52, 255))
    d.rectangle((3, TITLE_H, tw - 4, TITLE_H + 30), fill=BG + (255,))
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse((44 + i * 56, 24, 44 + i * 56 + 32, 56), fill=c)
    f = font(SANS_BOLD, 34)
    label = "nscope — o nmap sem decorar flags"
    d.text((tw / 2, TITLE_H / 2), label, font=f, fill=(148, 163, 184), anchor="mm")
    bg.paste(win, (wx, wy), win)
    return bg.convert("RGB"), int(ox), int(oy)


@lru_cache(maxsize=6)
def terminal_scene(snap):
    cols, rows = len(snap[0]), len(snap)
    base, ox, oy = base_scene(cols, rows)
    img = Image.new("RGB", (cols * CELL_W, rows * CELL_H), BG)
    d = ImageDraw.Draw(img)
    for y, row in enumerate(snap):
        x = 0
        while x < cols:  # fundos agrupados em corridas
            ch = row[x]
            bg_c = color_of(ch.bg, BG) if not ch.reverse else color_of(ch.fg, FG)
            e = x
            while e + 1 < cols and (color_of(row[e + 1].bg, BG) if not row[e + 1].reverse else color_of(row[e + 1].fg, FG)) == bg_c:
                e += 1
            if bg_c != BG:
                d.rectangle((x * CELL_W, y * CELL_H, (e + 1) * CELL_W - 1, (y + 1) * CELL_H - 1), fill=bg_c)
            x = e + 1
        for x, ch in enumerate(row):
            c = ch.data
            if not c or c == " ":
                continue
            fg = color_of(ch.fg, FG) if not ch.reverse else color_of(ch.bg, BG)
            if c in SHADES:  # blocos desenhados à mão: barras contínuas, sem as falhas da fonte
                cell_bg = color_of(ch.bg, BG) if not ch.reverse else color_of(ch.fg, FG)
                a = SHADES[c]
                mix = tuple(int(cell_bg[i] + (fg[i] - cell_bg[i]) * a) for i in range(3))
                d.rectangle((x * CELL_W, y * CELL_H, (x + 1) * CELL_W - 1, (y + 1) * CELL_H - 1), fill=mix)
                continue
            f = font(FONT_BOLD if ch.bold else FONT_REG, 56)
            if not has_glyph(c):
                f = font(FONT_FALLBACK, 52)
            d.text((x * CELL_W + CELL_W / 2, y * CELL_H + CELL_H / 2 + 2), c, font=f, fill=fg, anchor="mm")
            if ch.underscore:
                d.line((x * CELL_W, (y + 1) * CELL_H - 8, (x + 1) * CELL_W, (y + 1) * CELL_H - 8), fill=fg, width=3)
    scene = base.copy()
    scene.paste(img, (ox, oy))
    return scene


def keycap_font():
    return font(SANS_BOLD, 30)


def draw_overlay(out, rec, cols, rows):
    x0, y0, x1, y1 = rec["cam"]
    k = OUT_W / (x1 - x0)  # px de saída por px de cena
    _, ox, oy = base_scene(cols, rows)

    def to_out(px, py):
        return (px - x0) * k, (py - y0) * k

    # legenda
    if rec["caption"] and rec["cap_alpha"] > 0:
        a = rec["cap_alpha"]
        f = font(SANS_BOLD, 42)
        w = int(f.getlength(rec["caption"])) + 80
        lay = Image.new("RGBA", (OUT_W, OUT_H), (0, 0, 0, 0))
        d = ImageDraw.Draw(lay)
        top = int(34 - (1 - a) * 16)
        d.rounded_rectangle(((OUT_W - w) // 2, top, (OUT_W + w) // 2, top + 80), 40, fill=(8, 20, 40, int(215 * a)), outline=LIGHT_BLUE + (int(255 * a),), width=3)
        d.text((OUT_W // 2, top + 40), rec["caption"], font=f, fill=(240, 249, 255, int(255 * a)), anchor="mm")
        out.alpha_composite(lay)
    # tecla pressionada
    if rec["key"] and 0 <= rec["key_dt"] < 0.9:
        a = 1 - max(0.0, (rec["key_dt"] - 0.6) / 0.3)
        f = keycap_font()
        w = max(70, int(f.getlength(rec["key"])) + 44)
        lay = Image.new("RGBA", (OUT_W, OUT_H), (0, 0, 0, 0))
        d = ImageDraw.Draw(lay)
        cx, cy = OUT_W - 150, OUT_H - 38
        d.rounded_rectangle((cx - w // 2, cy - 30 + 6, cx + w // 2, cy + 30 + 6), 16, fill=(2, 10, 24, int(200 * a)))
        d.rounded_rectangle((cx - w // 2, cy - 30, cx + w // 2, cy + 30), 16, fill=(226, 240, 255, int(255 * a)), outline=LIGHT_BLUE + (int(255 * a),), width=3)
        d.text((cx, cy), rec["key"], font=f, fill=(15, 30, 60, int(255 * a)), anchor="mm")
        out.alpha_composite(lay)
    # cursor do mouse e clique
    mx, my = rec["mouse"]
    hx, hy = to_out(ox + (mx - 0.5) * CELL_W, oy + (my - 0.5) * CELL_H)
    size = max(26.0, 44 * k * S / 2)
    tile = int(size * 4)
    SS = 4
    spr = Image.new("RGBA", (tile * SS, tile * SS), (0, 0, 0, 0))
    d = ImageDraw.Draw(spr)
    c = tile * SS / 2
    u = size * SS / 20
    pts = [(0, 0), (0, 17), (4.2, 13.2), (7.2, 19.6), (9.8, 18.5), (7, 12.2), (12.4, 12.2)]
    poly = [(c + px * u, c + py * u) for px, py in pts]
    d.polygon([(px + 2.2 * u, py + 2.8 * u) for px, py in poly], fill=(0, 0, 0, 90))
    d.polygon(poly, fill=(255, 255, 255, 255), outline=(15, 23, 42, 255), width=max(2, int(u * 0.9)))
    dt = rec["click_dt"]
    if 0 <= dt < 0.5:
        r = size * (0.5 + 1.8 * ease(dt / 0.5)) * SS
        a = int(255 * (1 - dt / 0.5))
        d.ellipse((c - r, c - r, c + r, c + r), outline=LIGHT_BLUE + (a,), width=int(size * SS / 8))
    spr = spr.resize((tile, tile), Image.LANCZOS)
    out.alpha_composite(spr, (int(hx - tile / 2), int(hy - tile / 2))) if -tile < hx < OUT_W and -tile < hy < OUT_H else None


def draw_text_cursor(scene_img, rec, cols, rows):
    x, y, hidden = rec["text_cursor"]
    if hidden or int(rec["t"] * 2) % 2:
        return
    _, ox, oy = base_scene(cols, rows)
    d = ImageDraw.Draw(scene_img)
    d.rectangle((ox + x * CELL_W, oy + y * CELL_H + CELL_H - 10, ox + (x + 1) * CELL_W, oy + y * CELL_H + CELL_H - 4), fill=LIGHT_BLUE)


def render(rec):
    snap = rec["snap"]
    cols, rows = len(snap[0]), len(snap)
    scene = terminal_scene(snap)
    if not rec["text_cursor"][2] and not int(rec["t"] * 2) % 2:
        scene = scene.copy()
        draw_text_cursor(scene, rec, cols, rows)
    out = scene.resize((OUT_W, OUT_H), Image.LANCZOS, box=rec["cam"]).convert("RGBA")
    draw_overlay(out, rec, cols, rows)
    return out.convert("RGB")


FRAMES = []


def _work(chunk):
    a, b = chunk
    return a, [render(FRAMES[i]).tobytes() for i in range(a, b)]


def encode(frames, mp4=None, gif=None, gif_width=960, gif_fps=20, gif_colors=128, workers=None, still=None):
    """Rende todos os quadros em paralelo e manda para o ffmpeg (mp4 e/ou gif)."""
    global FRAMES
    FRAMES = frames
    procs = []
    if mp4:
        procs.append(subprocess.Popen(
            ["ffmpeg", "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{OUT_W}x{OUT_H}", "-r", str(FPS), "-i", "-",
             "-c:v", "libx264", "-preset", "slow", "-crf", "27", "-pix_fmt", "yuv420p", "-movflags", "+faststart", mp4], stdin=subprocess.PIPE))
    if gif:
        vf = (f"fps={gif_fps},scale={gif_width}:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors={gif_colors}:stats_mode=diff[p];"
              "[b][p]paletteuse=dither=none:diff_mode=rectangle")
        procs.append(subprocess.Popen(
            ["ffmpeg", "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{OUT_W}x{OUT_H}", "-r", str(FPS), "-i", "-",
             "-vf", vf, "-loop", "0", gif], stdin=subprocess.PIPE))
    step = 12
    chunks = [(i, min(i + step, len(frames))) for i in range(0, len(frames), step)]
    with mp.get_context("fork").Pool(workers or os.cpu_count()) as pool:
        for _, blobs in pool.imap(_work, chunks):
            for blob in blobs:
                for p in procs:
                    p.stdin.write(blob)
    for p in procs:
        p.stdin.close()
        p.wait()


def still_png(rec, path):
    global FRAMES
    render(rec).save(path, optimize=True)
