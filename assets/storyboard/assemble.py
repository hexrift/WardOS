"""Assemble the screenshotted frames into assets/wardos-desktop.gif (1280x720, 128 colours)."""
import glob, json, sys
from PIL import Image
work, out = sys.argv[1], sys.argv[2]
durations = json.load(open(f"{work}/frames/durations.json"))
frames = [Image.open(f).convert("RGB").resize((1280, 720), Image.LANCZOS) for f in sorted(glob.glob(f"{work}/frames/*.png"))]
q = [f.quantize(colors=128, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE) for f in frames]
q[0].save(out, save_all=True, append_images=q[1:], duration=durations, loop=0, optimize=True, disposal=1)
print(len(q), "frames ->", out)
