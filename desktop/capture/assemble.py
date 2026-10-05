"""Check one capture shot, or assemble the shots into the README GIF (desktop/capture/capture.sh).

  assemble.py check SHOT.png [--region X,Y,W,H] [--dominant #RRGGBB] [--not-dominant #RRGGBB]
                                             says what SHOT holds (size, colours, the dominant
                                             one) and fails unless it is 1920x1080 with
                                             something on it; with a region (the bar, say)
                                             its dominant colour is said too, and the
                                             dominant colour of the region (else the shot)
                                             must be / must not be the one given (a scene
                                             shot before its theme reached the bar)
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


def dominant_of(rgb):
    """The most common colour as #rrggbb (None for an empty image) and its share in percent."""
    counts = rgb.getcolors(rgb.size[0] * rgb.size[1]) or []
    if not counts:
        return None, 0, 0
    n, (r, g, b) = max(counts)
    return f"#{r:02x}{g:02x}{b:02x}", 100 * n // (rgb.size[0] * rgb.size[1]), len(counts)


def describe(shot, region=None):
    """Print one line about the shot (and one about the region, if any).

    Returns (size, flat, dominant colour of the region, else of the shot)."""
    with Image.open(shot) as img:
        rgb = img.convert("RGB")
        size = rgb.size
        lo, hi = rgb.convert("L").getextrema()
        flat = hi - lo < 16
        colour, share, n = dominant_of(rgb)
        what = "one flat colour" if flat else f"{n} colours"
        dominant = f"{colour} ({share}%)" if colour else "?"
        print(f"assemble: {shot}: {size[0]}x{size[1]}, {what}, dominant {dominant}, luma {lo}..{hi}")
        if region:
            x, y, w, h = region
            colour, share, n = dominant_of(rgb.crop((x, y, x + w, y + h)))
            print(f"assemble: {shot}: region {x},{y} {w}x{h}: {n} colours, dominant {colour} ({share}%)")
        return size, flat, colour


def check(shot, flags):
    region, must, must_not = None, None, None
    while flags:
        match flags:
            case ["--region", spec, *rest]:
                region = tuple(int(v) for v in spec.split(","))
                if len(region) != 4:
                    sys.exit(__doc__)
            case ["--dominant", colour, *rest]:
                must = colour.lower()
            case ["--not-dominant", colour, *rest]:
                must_not = colour.lower()
            case _:
                sys.exit(__doc__)
        flags = rest
    size, flat, dominant = describe(shot, region)
    where = f"{shot}'s region {','.join(map(str, region))}" if region else shot
    if size != SHOT:
        sys.exit(f"assemble: {shot} is {size[0]}x{size[1]}, not {SHOT[0]}x{SHOT[1]}")
    if flat:
        sys.exit(f"assemble: {shot} is one flat colour; nothing was rendered")
    if must and dominant != must:
        sys.exit(f"assemble: {where} is dominated by {dominant}, not {must}; the scene was shot before it changed")
    if must_not and dominant == must_not:
        sys.exit(f"assemble: {where} is still dominated by {must_not}; the scene was shot before it changed")


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
