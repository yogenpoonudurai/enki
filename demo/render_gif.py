#!/usr/bin/env python3
"""Render the enki demo storyboard to GIF/MP4/PNGs.

Default: 960x540 GIF + 30 fps MP4.
HD:      ENKI_GIF_SCALE=2 ENKI_GIF_FPS=60 python3 demo/render_gif.py
         -> demo-hd.mp4 (1920x1080, 60 fps) + demo-title-hd.png

Requires Pillow, ffmpeg (for MP4), and monospace/sans TTFs.
"""
import os
import shutil
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

BASE_W, BASE_H = 960, 540
SCALE = float(os.environ.get("ENKI_GIF_SCALE", "1") or "1")
W, H = round(BASE_W * SCALE), round(BASE_H * SCALE)
FPS = int(os.environ.get("ENKI_GIF_FPS", "60" if SCALE > 1 else "30"))

BG = (13, 17, 23)
PANEL = (22, 27, 34)
CHROME = (30, 36, 44)
LINE = (38, 45, 54)
FG = (201, 209, 217)
DIM = (139, 148, 158)
GREEN = (63, 185, 80)
RED = (255, 71, 87)
ORANGE = (255, 159, 67)
AMBER = (255, 179, 71)
GREY = (173, 181, 189)

SPIN = "|/-\\"
DOT_BITS = (
    (0x01, 0x08),
    (0x02, 0x10),
    (0x04, 0x20),
    (0x40, 0x80),
)
TITLE_STYLE = os.environ.get("ENKI_GIF_TITLE", "braille").lower()

FONT_PATH = os.environ.get("ENKI_GIF_FONT", "/usr/share/fonts/TTF/DejaVuSansMono.ttf")
SANS_BOLD = "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf"
SANS = "/usr/share/fonts/TTF/DejaVuSans.ttf"
OUT_DIR = os.path.dirname(os.path.abspath(__file__))


def s(n):
    return max(1, round(n * SCALE))


def load_fonts():
    try:
        return {
            "body": ImageFont.truetype(FONT_PATH, s(17)),
            "chrome": ImageFont.truetype(FONT_PATH, s(12)),
            "logo": ImageFont.truetype(FONT_PATH, s(27)),
            "bold": ImageFont.truetype(SANS_BOLD, s(78)),
            "sans": ImageFont.truetype(SANS, s(24)),
            "small": ImageFont.truetype(SANS, s(16)),
            "mono": ImageFont.truetype(FONT_PATH, s(17)),
            "cap_bold": ImageFont.truetype(SANS_BOLD, s(19)),
            "cap": ImageFont.truetype(SANS, s(17)),
        }
    except OSError as exc:
        sys.exit(f"fonts not found: {exc}")


def copy_lines(lines):
    return [list(line) for line in lines]


def load_braille_logo():
    path = os.path.join(OUT_DIR, "..", "internal", "report", "logo_small.txt")
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().rstrip("\n").split("\n")
    except OSError:
        return []


def gradient_colors(n, start=(255, 179, 71), end=(230, 57, 70)):
    if n <= 1:
        return [start]
    return [
        tuple(round(a + (b - a) * (i / (n - 1))) for a, b in zip(start, end))
        for i in range(n)
    ]


def build_states():
    states = []
    poster = {"lines": None}

    def frame(lines, duration=110, mode="terminal"):
        states.append((copy_lines(lines), duration, mode))

    def prompt_frames(command):
        for i in range(2, len(command) + 1, 2):
            frame([[("$ ", GREEN), (command[:i], FG)]], 55)
        frame([[("$ ", GREEN), (command, FG)]], 140)

    states.append((None, 2600, "title"))

    prompt_frames("enki scan")
    base = [
        [("$ ", GREEN), ("enki scan", FG)],
        [],
        [("  AI SECURITY POSTURE · scanning this host", DIM)],
        [("", FG)],
    ]
    modules = [
        ("endpoint-exposure", "probing 12 listeners", "2 AI services exposed"),
        ("mcp", "6 MCP configs", "4 supply-chain issues"),
        ("agent-permissions", "3 agents", "bypassPermissions enabled"),
        ("secrets", "history + configs", "provider key found (redacted)"),
        ("model-artifacts", "148 files", "pickle weights"),
        ("sbom", "OSV · KEV · EPSS", "29 advisories · 4 packages"),
    ]

    def progress_bar(done, total):
        filled = round(12 * done / total)
        return [
            ("  [", DIM),
            ("█" * filled + "░" * (12 - filled), GREEN if done < total else AMBER),
            (f"]  {done}/{total} checks", DIM),
        ]

    for idx, (name, active, result) in enumerate(modules):
        for k in range(3):
            lines = copy_lines(base)
            for j, (n, _a, r) in enumerate(modules):
                if j < idx:
                    lines.append([("  ok ", GREEN), (f"{n:<20}", FG), (r, DIM)])
                elif j == idx:
                    lines.append([("  " + SPIN[(idx * 3 + k) % len(SPIN)] + " ", AMBER), (f"{n:<20}", FG), (active + "…", DIM)])
                else:
                    lines.append([("  · ", DIM), (f"{n:<20}", DIM), ("waiting", DIM)])
            lines.append([("", FG)])
            lines.append(progress_bar(idx, len(modules)))
            frame(lines, 85)

    lines = copy_lines(base)
    for n, _, r in modules:
        lines.append([("  ok ", GREEN), (f"{n:<20}", FG), (r, DIM)])
    lines += [
        [("", FG)],
        progress_bar(len(modules), len(modules)),
        [("", FG)],
        [("  POSTURE ", DIM), ("43/100", FG), (" · ", DIM), ("AT RISK", RED), ("  ·  46 findings", DIM)],
        [("", FG)],
    ]
    findings = [
        [("  CRITICAL  ", RED), ("AEP-001  Ollama API exposed on 0.0.0.0:11434", FG)],
        [("  HIGH      ", ORANGE), ('MCP-001  Unpinned MCP server "@upstash/context7-mcp"', FG)],
        [("  HIGH      ", ORANGE), ("AGT-001  Agent runs with bypassPermissions", FG)],
        [("  HIGH      ", ORANGE), ("SEC-001  OpenAI API key in .env (tracked by git)", FG)],
        [("  GUIDANCE  ", GREY), ("SBOM-001 Upgrade torch to 2.6.0 or later", FG)],
    ]
    frame(lines, 650)
    for f in findings:
        lines.append(f)
        frame(lines, 170)

    prompt_frames("enki triage report.json")
    triage_base = [[("$ ", GREEN), ("enki triage report.json", FG)], []]
    for k in range(6):
        dots = "." * (k % 4)
        lines = copy_lines(triage_base) + [
            [("  " + SPIN[k % len(SPIN)] + " ", AMBER), ("ANALYSING  ", FG), ("40 findings · system context: linux/systemd · ufw · non-root", DIM)],
            [("  " + SPIN[(k + 4) % len(SPIN)] + " ", AMBER), ("THINKING   ", FG), ("ranking by exploitability and impact" + dots, DIM)],
        ]
        frame(lines, 150)

    lines = copy_lines(triage_base) + [
        [("  " + SPIN[2] + " ", AMBER), ("ANALYSING  ", FG), ("40 findings · system context: linux/systemd · ufw · non-root", DIM)],
        [("  " + SPIN[2] + " ", AMBER), ("THINKING   ", FG), ("ranking by exploitability and impact...", DIM)],
        [],
        [("  ok ", GREEN), ("TRIAGE READY  ", FG), ("2 actions · $0.004 · deepseek-flash", DIM)],
        [],
        [("  #1 ", AMBER), ("AEP-001  Rebind Ollama to loopback (requires sudo)", FG)],
        [("  #2 ", AMBER), ("SEC-001  chmod 0600 .env, then rotate the key", FG)],
    ]
    frame(lines, 1500)
    poster["lines"] = copy_lines(lines)

    prompt_frames("enki fix")
    fix_base = [[("$ ", GREEN), ("enki fix", FG)], []]
    plan = [
        [("[1] ", FG), ("SAFE      ", GREEN), ("chmod 0600 ~/.claude.json", FG), ("        SEC-001", DIM)],
        [("[2] ", FG), ("GUIDANCE  ", GREY), ("Upgrade torch to 2.6.0 or later", FG), ("  SBOM-001", DIM)],
        [("[3] ", FG), ("RISKY     ", ORANGE), ("Bind Ollama to 127.0.0.1", FG), ("       AEP-001", DIM)],
    ]
    for item in plan:
        fix_base.append(item)
        frame(fix_base, 260)
    frame(fix_base + [[("", FG)], [("  SAFE applies with --apply · config edits ask · risky prints only", DIM)]], 1100)

    prompt_frames("enki undo")
    frame(
        [
            [("$ ", GREEN), ("enki undo", FG)],
            [],
            [("  UNDO ", AMBER), ("restored ~/.claude.json (byte-identical)", FG)],
        ],
        1000,
    )

    frame(
        [
            [],
            [("+ scan -> triage -> fix -> undo", GREEN)],
            [],
            [("Free forever locally · Apache-2.0", FG)],
            [("github.com/yogenpoonudurai/enki", AMBER)],
            [("enki scan", DIM)],
        ],
        2400,
    )
    return states, poster["lines"]


def new_window(fonts):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, W - 1, H - 1], radius=s(14), fill=PANEL, outline=LINE)
    d.rounded_rectangle([0, 0, W - 1, s(35)], radius=s(14), fill=CHROME)
    d.rectangle([0, s(22), W - 1, s(35)], fill=CHROME)
    d.line([0, s(35), W - 1, s(35)], fill=LINE)
    for i, color in enumerate([(255, 95, 86), (255, 189, 46), (27, 201, 63)]):
        cx = s(22) + i * s(20)
        d.ellipse([cx - s(6), s(12), cx + s(6), s(24)], fill=color)
    d.text((s(92), s(11)), "enki · AI security posture", font=fonts["chrome"], fill=DIM)
    return img, d


def render_text_title(fonts):
    img, d = new_window(fonts)

    def center(text, font, y, fill):
        width = d.textlength(text, font=font)
        d.text(((W - width) / 2, s(y)), text, font=font, fill=fill)

    center("ENKI", fonts["bold"], 92, AMBER)
    d.rounded_rectangle([(W - s(420)) / 2, s(194), (W + s(420)) / 2, s(199)], radius=s(2), fill=RED)
    center("AI SECURITY POSTURE", fonts["small"], 216, DIM)
    center("Find the AI stack you didn't know", fonts["sans"], 282, FG)
    center("you were running.", fonts["sans"], 316, FG)
    center("scan -> triage -> fix -> undo", fonts["mono"], 386, GREEN)
    center("Open source - Apache-2.0", fonts["small"], 428, DIM)
    return img


def draw_braille_art(d, art, x0, y0, pitch):
    """Draw the braille artwork as real dots (no glyph dependency)."""
    colors = gradient_colors(len(art) * 4)
    radius = max(2, round(pitch * 0.52))
    for row, line in enumerate(art):
        for cell, ch in enumerate(line):
            code = ord(ch)
            if not (0x2800 <= code <= 0x28FF):
                continue
            bits = code - 0x2800
            for dy in range(4):
                for dx in range(2):
                    if not bits & DOT_BITS[dy][dx]:
                        continue
                    px = x0 + (cell * 2 + dx) * pitch
                    py = y0 + (row * 4 + dy) * pitch
                    d.ellipse([px - radius, py - radius, px + radius, py + radius],
                              fill=colors[row * 4 + dy])


def render_braille_title(fonts):
    """Large braille artwork with the caption underneath."""
    img, d = new_window(fonts)
    art = load_braille_logo()
    pitch = s(7)
    x0 = s(36)
    y0 = s(24)
    draw_braille_art(d, art, x0, y0, pitch)

    caption_y = y0 + len(art) * 4 * pitch + s(14)
    d.text((x0, caption_y), "ENKI", font=fonts["cap_bold"], fill=FG)
    cx = x0 + d.textlength("ENKI", font=fonts["cap_bold"])
    d.text((cx, caption_y), " - AI Security Posture - v0.4.0", font=fonts["cap"], fill=DIM)
    return img


def is_braille(text):
    return any(0x2800 <= ord(ch) <= 0x28FF for ch in text)


def render(lines, fonts, centered=False):
    img, d = new_window(fonts)
    body = fonts["body"]

    def width_of(segs):
        return sum(d.textlength(text, font=body) for text, _ in segs)

    logo_width = 0
    if centered:
        art_widths = [width_of(segs) for segs in lines if segs and is_braille(segs[0][0])]
        logo_width = max(art_widths) if art_widths else 0
    logo_x = max(s(30), (W - logo_width) / 2) if centered else s(30)

    y = s(58)
    for segments in lines:
        if centered and segments and not is_braille(segments[0][0]):
            x = max(s(30), (W - width_of(segments)) / 2)
        else:
            x = logo_x
        for text, color in segments:
            d.text((x, y), text, font=body, fill=color)
            x += d.textlength(text, font=body)
        y += s(24)
    return img


def write_mp4(images, durations, path, fps):
    if not shutil.which("ffmpeg"):
        print("ffmpeg not found; skipping MP4")
        return False
    proc = subprocess.Popen(
        [
            "ffmpeg", "-y", "-loglevel", "error",
            "-f", "rawvideo", "-pix_fmt", "rgb24",
            "-s", f"{W}x{H}", "-r", str(fps), "-i", "-",
            "-c:v", "libx264", "-preset", "slow", "-crf", "18",
            "-pix_fmt", "yuv420p", "-movflags", "+faststart",
            path,
        ],
        stdin=subprocess.PIPE,
    )
    try:
        for img, duration in zip(images, durations):
            reps = max(1, round(duration / 1000 * fps))
            for _ in range(reps):
                proc.stdin.write(img.tobytes())
        proc.stdin.close()
    except BrokenPipeError:
        return False
    return proc.wait() == 0


def main():
    fonts = load_fonts()
    states, poster_lines = build_states()
    hd = SCALE > 1
    suffix = "-hd" if hd else ""
    rgb_frames = []
    durations = []
    title_png = os.path.join(OUT_DIR, f"demo-title{suffix}.png")
    alt_png = os.path.join(OUT_DIR, f"demo-title-alt{suffix}.png")
    selected = render_braille_title if TITLE_STYLE == "braille" else render_text_title
    alternative = render_text_title if TITLE_STYLE == "braille" else render_braille_title

    for lines, duration, mode in states:
        if mode == "title":
            img = selected(fonts)
            img.save(title_png)
            alternative(fonts).save(alt_png)
        else:
            img = render(lines, fonts, centered=(mode == "center"))
        rgb_frames.append(img)
        durations.append(duration)

    mp4_path = os.path.join(OUT_DIR, f"demo{suffix}.mp4")
    mp4_ok = write_mp4(rgb_frames, durations, mp4_path, FPS)

    if not hd:
        gif_path = os.path.join(OUT_DIR, "demo.gif")
        png_path = os.path.join(OUT_DIR, "demo.png")
        gif_frames = [img.convert("P", palette=Image.ADAPTIVE, colors=64) for img in rgb_frames]
        gif_frames[0].save(
            gif_path,
            save_all=True,
            append_images=gif_frames[1:],
            duration=durations,
            loop=0,
            optimize=True,
            disposal=2,
        )
        render(poster_lines, fonts).save(png_path)
        print(f"wrote {gif_path} ({os.path.getsize(gif_path)//1024} KB, {len(gif_frames)} frames, {sum(durations)/1000:.1f}s)")
        print(f"wrote {png_path}")

    print(f"wrote {title_png}")
    if mp4_ok:
        print(f"wrote {mp4_path} ({os.path.getsize(mp4_path)//1024} KB, {W}x{H} @ {FPS}fps)")


if __name__ == "__main__":
    main()
