"""Check one capture shot, or assemble the shots into the README GIF (desktop/capture/capture.sh).

  assemble.py check SHOT.png [--not-dominant #RRGGBB]
                                             says what SHOT holds (size, colours, the dominant
                                             one) and fails unless it is 1920x1080 with
                                             something on it whose dominant colour is not
                                             the one given (a scene shot before it changed)
  assemble.py describe SHOT.png              the same line, never failing (a diagnostic shot)
  assemble.py gif SCENES.tsv FRAMES OUT.gif  one GIF frame per NN-<scene>.png in FRAMES, in
                                             scenes.tsv order, shown for that scene's ms;
                                             1280x720, 128 colours, looped
"""
import sys
from pathlib import Path

from PIL import Image

SHOT, GIF = (1920, 1080), (1280, 720)


def scenes(table):
    rows = []
    for line in Path(table).read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            scene, ms, need, _what = line.split("\t")
            rows.append((scene, int(ms), need))
    return rows


def describe(shot):
    """Print one line about the shot; return (size, flat, dominant colour as #rrggbb or None)."""
    with Image.open(shot) as img:
        rgb = img.convert("RGB")
        size = rgb.size
        counts = rgb.getcolors(size[0] * size[1]) or []
        lo, hi = rgb.convert("L").getextrema()
        flat = hi - lo < 16
        colour = None
        if counts:
            n, (r, g, b) = max(counts)
            colour = f"#{r:02x}{g:02x}{b:02x}"
            dominant = f"{colour} ({100 * n // (size[0] * size[1])}%)"
        else:
            dominant = "?"
        what = "one flat colour" if flat else f"{len(counts)} colours"
        print(f"assemble: {shot}: {size[0]}x{size[1]}, {what}, dominant {dominant}, luma {lo}..{hi}")
        return size, flat, colour


def check(shot, flags):
    not_dominant = None
    match flags:
        case []:
            pass
        case ["--not-dominant", colour]:
            not_dominant = colour.lower()
        case _:
            sys.exit(__doc__)
    size, flat, dominant = describe(shot)
    if size != SHOT:
        sys.exit(f"assemble: {shot} is {size[0]}x{size[1]}, not {SHOT[0]}x{SHOT[1]}")
    if flat:
        sys.exit(f"assemble: {shot} is one flat colour; nothing was rendered")
    if not_dominant and dominant == not_dominant:
        sys.exit(f"assemble: {shot} is still dominated by {not_dominant}; the scene was shot before it changed")


def gif(table, frames, out):
    shots = {p.stem.split("-", 1)[1]: p for p in sorted(Path(frames).glob("[0-9][0-9]-*.png"))}
    images, durations = [], []
    for scene, ms, need in scenes(table):
        if scene not in shots:
            if need != "optional":
                sys.exit(f"assemble: no shot of the required scene {scene}")
            print(f"assemble: {scene} left out (optional, not captured)")
            continue
        with Image.open(shots[scene]) as img:
            frame = img.convert("RGB").resize(GIF, Image.LANCZOS)
        images.append(frame.quantize(colors=128, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE))
        durations.append(ms)
    images[0].save(out, save_all=True, append_images=images[1:], duration=durations, loop=0, optimize=True, disposal=1)
    print(f"{len(images)} frames, {sum(durations)} ms -> {out} ({Path(out).stat().st_size} bytes)")


if __name__ == "__main__":
    match sys.argv[1:]:
        case ["check", shot, *flags]:
            check(shot, flags)
        case ["describe", shot]:
            describe(shot)
        case ["gif", table, frames, out]:
            gif(table, frames, out)
        case _:
            sys.exit(__doc__)
