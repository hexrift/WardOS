# The README desktop storyboard

`assets/wardos-desktop.gif` is a rendered storyboard, not a capture of a running
compositor. Each frame is an HTML page built from real material: the nine colour
tokens and wallpaper that `wardos-theme-render` writes for a theme, the Waybar layout
(`desktop/config/waybar`), the menu lines `ward-shell launcher --lines` prints, the
trust bar `ward-shell bar --waybar` prints, and the output of `ward init`, `ward vault`,
`ward up` and `ward verify` on `examples/ward-demo`. Chromium screenshots the pages and
Pillow assembles the GIF.

It exists so the README can show the first five minutes before a compositor capture
runs in CI; [issue #84](https://github.com/hexrift/WardOS/issues/84) is that capture,
and it replaces this directory when it lands.

```sh
cargo build --release -p wardos-theme
pip install pillow && npm install playwright
assets/storyboard/render.sh        # PLAYWRIGHT=… and CHROME=… point at an existing install
```

`story.py` holds the storyboard: one `add(...)` per frame with its caption and how long
it stays. Keep every string in it something the shipped desktop actually prints.
