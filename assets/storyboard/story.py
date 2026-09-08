"""Render the README desktop storyboard as HTML frames (see README.md here)."""
import html, json, os, sys
S = sys.argv[1]  # work dir: themes/<id>/ from wardos-theme-render; frames/ is written here
def theme(id):
    c = {}
    for line in open(f"{S}/themes/{id}/colors.env"):
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1); c[k] = v.strip('"')
    return c
E = html.escape
frames = []  # (html, duration_ms)

def page(t, body, caption, wallpaper=True, veil=False):
    G,P,SEP,T,M,A,V,R,D = (t[k] for k in ["WARDOS_GROUND","WARDOS_PANEL","WARDOS_SEPARATOR","WARDOS_TEXT","WARDOS_TEXT_MUTED","WARDOS_ACCENT","WARDOS_VERIFIED","WARDOS_RESTRICTED","WARDOS_DENIED"])
    bg = f"background:{G} url(file://{S}/themes/{t['WARDOS_THEME_ID']}/background.png) center bottom/cover" if wallpaper else f"background:{G}"
    cap = f'<div class="cap" style="background:{P};border:1px solid {SEP};color:{T}">{caption}</div>' if caption else ""
    return f"""<!doctype html><meta charset="utf-8"><style>
body{{margin:0;background:#000}} .screen{{position:relative;width:1920px;height:1080px;{bg};font-family:Inter,"DejaVu Sans",sans-serif;font-size:15px;color:{T};overflow:hidden}}
.bar{{position:absolute;left:0;top:0;right:0;height:32px;background:{G};border-bottom:1px solid {SEP};display:flex;align-items:stretch;font-size:13px;font-feature-settings:"tnum"}}
.bar .l,.bar .r{{display:flex}} .bar .c{{flex:1;display:flex;justify-content:center}} .cell{{display:flex;align-items:center;padding:0 8px;border-right:1px solid {SEP};white-space:nowrap}}
.ws{{display:flex;align-items:center;padding:0 8px;border-bottom:2px solid transparent}}
.win{{position:absolute;background:{P};border:1px solid {SEP};border-radius:6px;overflow:hidden}} .win pre{{margin:0;padding:14px 18px;font-family:"JetBrains Mono","DejaVu Sans Mono",monospace;font-size:14px;line-height:1.55;white-space:pre-wrap}}
.win .tb{{padding:8px 18px;border-bottom:1px solid {SEP};font-family:"DejaVu Sans Mono",monospace;font-size:13px;color:{M}}}
.cursor{{display:inline-block;width:8px;height:15px;background:{T};vertical-align:text-bottom}}
.menu{{position:absolute;left:640px;top:180px;width:640px;background:{P};border:1px solid {A};border-radius:6px;box-shadow:0 12px 40px rgba(0,0,0,.45);font-size:14px}}
.menu .q{{padding:12px 16px;border-bottom:1px solid {SEP};font-family:"DejaVu Sans Mono",monospace;color:{M}}} .menu .q b{{color:{T};font-weight:400}}
.menu .sec{{padding:10px 16px 4px;font-size:11px;letter-spacing:.1em;color:{M}}} .menu .row{{display:flex;justify-content:space-between;padding:0 16px;height:24px;line-height:24px;color:{T}}} .menu .row.sel{{background:{A};color:{G}}}
.notif{{position:absolute;right:8px;top:40px;width:360px;padding:8px 16px;background:{P};border:1px solid {SEP};border-radius:6px;font-size:13px;line-height:1.5}} .notif b{{display:block}} .notif tt{{font-family:"DejaVu Sans Mono",monospace}}
.notif .prog{{height:2px;margin-top:8px;background:{SEP}}} .notif.appr{{border-color:{R}}}
.cap{{position:absolute;left:50%;bottom:28px;transform:translateX(-50%);padding:8px 18px;border-radius:6px;font-size:16px;white-space:nowrap}}
.lock{{position:absolute;inset:0;background:{P}B3}} .lock .clock{{position:absolute;left:0;right:0;top:calc(50% - 128px - 60px);text-align:center;font-size:96px;font-weight:300;color:{T}}}
.lock .date{{position:absolute;left:0;right:0;top:calc(50% - 40px - 10px);text-align:center;font-size:14px;color:{M}}} .lock .in{{position:absolute;left:800px;top:calc(50% + 40px - 20px);width:320px;height:40px;border:1px solid {A};border-radius:6px;background:{P};color:{M};line-height:40px;text-align:center;font-size:14px}}
.mark{{position:absolute;left:48px;bottom:40px;font-family:"DejaVu Sans Mono",monospace;font-size:14px;letter-spacing:.2em;color:{M}}}
.ply{{position:absolute;inset:0;background:{G}}} .ply .w{{position:absolute;left:0;right:0;top:calc(50% - 24px);text-align:center;font-size:37px;color:#D9D9D6}} .ply .line{{position:absolute;left:calc(50% - 52px);top:calc(50% + 34px);height:2px;background:#8A8D91}}
</style><div class="screen">{body}{cap}</div>"""

def bar(t, session=None, agent=None, tw=None, verify=None, ws=1):
    G,P,SEP,T,M,A,V,R,D = (t[k] for k in ["WARDOS_GROUND","WARDOS_PANEL","WARDOS_SEPARATOR","WARDOS_TEXT","WARDOS_TEXT_MUTED","WARDOS_ACCENT","WARDOS_VERIFIED","WARDOS_RESTRICTED","WARDOS_DENIED"])
    def cell(text, color, mono=False, bold=False, last=False):
        st = f"color:{color};" + ("font-family:'DejaVu Sans Mono',monospace;" if mono else "") + ("font-weight:600;letter-spacing:.08em;" if bold else "") + ("border-right:none;" if last else "")
        return f'<div class="cell" style="{st}">{E(text)}</div>'
    left = cell("WARD", T, bold=True)
    if session:
        left += cell(session, T, mono=True)
        if agent: left += cell(agent, A)
        left += cell("NET restricted (dev)", R)
        if tw: left += cell("TW ✓", V)
        if verify == "ok": left += cell("VERIFY ✓ 7c01…", V)
        elif verify == "stale": left += cell("VERIFY ~ STALE", R)
    wsd = "".join(f'<div class="ws" style="color:{T if i==ws else M};border-bottom-color:{A if i==ws else "transparent"}">{i}</div>' for i in (1,2,3))
    right = "".join(cell(x, M) for x in ["vol 60%", "wlp3s0", "bt", "82%", "cpu 3%", "mem 2.1G"]) + cell("23:41", T, last=True)
    return f'<div class="bar"><div class="l">{left}</div><div class="c">{wsd}</div><div class="r">{right}</div></div>'

def win(x, y, w, h, title, pre):
    tb = f'<div class="tb">{E(title)}</div>' if title else ""
    return f'<div class="win" style="left:{x}px;top:{y}px;width:{w}px;height:{h}px">{tb}<pre>{pre}</pre></div>'

def menu(prompt, rows, sel=0, typed=""):
    body = f'<div class="q">{E(prompt)} <b>{E(typed)}</b><span class="cursor"></span></div>'
    i = 0
    for r in rows:
        if isinstance(r, tuple) and r[1] is None:
            body += f'<div class="sec">{E(r[0])}</div>'; continue
        label, detail = (r if isinstance(r, tuple) else (r, ""))
        body += f'<div class="row{" sel" if i == sel else ""}"><span>{E(label)}</span><span>{E(detail)}</span></div>'
        i += 1
    return f'<div class="menu">{body}</div>'

def notif(title, body, appr=False, prog=None):
    p = f'<div class="prog"><div style="width:{prog}%;height:2px;background:currentColor"></div></div>' if prog is not None else ""
    return f'<div class="notif{" appr" if appr else ""}"><b>{E(title)}</b>{body}{p}</div>'

def col(t, key, text): return f'<span style="color:{t[key]}">{E(text)}</span>'

def add(t, body, caption, ms, **kw): frames.append((page(t, body, caption, **kw), ms))

D_ = theme("ward-dark"); TN = theme("tokyo-night")
t = D_
# 1. Plymouth
for pct, ms in ((0.05, 700), (0.5, 500), (1.0, 500)):
    add(t, f'<div class="ply"><div class="w">WARD</div><div class="line" style="width:{int(104*pct)}px"></div></div>', "Boot · the Plymouth splash; an encrypted disk asks for its passphrase here", ms, wallpaper=False)
# 2. First desktop
add(t, bar(t), "First login · tty autologin straight into Hyprland; nothing to type", 1500)
# 3. Welcome: theme
themes = ["catppuccin-latte","catppuccin-mocha","everforest-dark","flexoki-dark","gruvbox-dark","kanagawa-wave","matte-black","nord","rose-pine","tokyo-night","ward-dark","ward-graphite","ward-high-contrast","ward-light","Skip"]
add(t, bar(t) + menu("Theme · pick the look (Super + Shift + T cycles later)", themes, sel=10), "wardos-welcome · step 1 of 4, a theme", 1800)
# 4. Keys
keys = ["Anthropic (Claude Code) · ANTHROPIC_API_KEY · not set", "OpenAI (Codex) · OPENAI_API_KEY · not set", "Continue", "Skip"]
add(t, bar(t) + menu("Keys · stored on the host, injected by the proxy, never seen by the agent", keys, sel=0), "step 2 · a key, kept on the host", 1600)
vault = f'{col(t,"WARDOS_ACCENT","$")} ward vault set ANTHROPIC_API_KEY\nANTHROPIC_API_KEY (not shown): {col(t,"WARDOS_TEXT_MUTED","••••••••••••••••••••")}\n  {col(t,"WARDOS_VERIFIED","ANTHROPIC_API_KEY stored")} in ~/.local/state/ward/vault/ANTHROPIC_API_KEY (0600); the proxy injects it, the sandbox never sees it\n\n{col(t,"WARDOS_ACCENT","$")} ward vault list\n  ANTHROPIC_API_KEY   {col(t,"WARDOS_VERIFIED","set · vault")}\n  OPENAI_API_KEY      {col(t,"WARDOS_TEXT_MUTED","not set")}\n  GITHUB_TOKEN        {col(t,"WARDOS_TEXT_MUTED","not set")}'
add(t, bar(t) + win(480, 260, 960, 300, "wardos-vault", vault), "the key is typed in a terminal, never in a menu", 2000)
# 5. Project
add(t, bar(t) + menu("Project · a directory the agent works in", ["Choose a directory", "Clone a repository", "Skip"], sel=1), "step 3 · a project", 1400)
add(t, bar(t) + menu("Repository URL (https://… or git@…)", [], typed="https://github.com/hexrift/ward-demo"), "", 1200)
init = (f'{col(t,"WARDOS_ACCENT","$")} git clone https://github.com/hexrift/ward-demo ~/ward-demo\n{col(t,"WARDOS_TEXT_MUTED","Cloning into ward-demo… done.")}\n{col(t,"WARDOS_ACCENT","$")} ward init ~/ward-demo\n'
        f'{col(t,"WARDOS_ACCENT","WARD")} init · ~/ward-demo\n\n  policy      .ward/policy.yaml       {col(t,"WARDOS_VERIFIED","written")}\n  gitignore   .gitignore              .ward/sessions/ added\n  verifier    .tamperward/config.yml  {col(t,"WARDOS_VERIFIED","written")} (cargo test)\n  tamperward  .tamperward.yml         {col(t,"WARDOS_VERIFIED","written")}\n\n{col(t,"WARDOS_TEXT_MUTED","Next")}\n  ward vault set ANTHROPIC_API_KEY   the model key, kept on the host; the proxy injects it\n  ward claude                        start the agent in the sandbox\n  ward verify                        run the protected tests in the disposable verifier')
add(t, bar(t) + win(480, 220, 960, 420, "wardos-init", init), "ward init · policy, verifier config and TamperWard wiring, idempotent", 2200)
# 6. Agent
add(t, bar(t) + menu("Agent · start in ~/ward-demo", ["Start Claude", "Start Codex", "Skip"], sel=0), "step 4 · an agent", 1400)
panel = (f'{col(t,"WARDOS_ACCENT","$")} ward claude ~/ward-demo\n<b style="color:{t["WARDOS_ACCENT"]}">WARD</b> session  {col(t,"WARDOS_TEXT_MUTED","sess_01M20HZCWQ5R2HKJ7EXC4CT9MB")}\n{col(t,"WARDOS_TEXT_MUTED","─"*44)}\n  Project       ~/ward-demo\n  Runtime       isolated (bubblewrap)\n  Repository    read &amp; write\n  Network       {col(t,"WARDOS_RESTRICTED","restricted (dev)")}\n  Credentials   {col(t,"WARDOS_VERIFIED","none")} {col(t,"WARDOS_TEXT_MUTED","(brokered, 5 services)")}\n  Containers    nested rootless\n  Observer      live\n\n{col(t,"WARDOS_TEXT_MUTED","TamperWard")}\n  Policy        {col(t,"WARDOS_VERIFIED","locked")} {col(t,"WARDOS_TEXT_MUTED","25c7a0c4a34a")}\n  Entry state   {col(t,"WARDOS_VERIFIED","frozen")} {col(t,"WARDOS_TEXT_MUTED","bb2990a298e5")}\n  Verifier      {col(t,"WARDOS_TEXT_MUTED","disposable namespace · no network · protected tests from entry")}\n\n  {col(t,"WARDOS_VERIFIED","session ACTIVE")} {col(t,"WARDOS_TEXT_MUTED","· started 0s ago")}\n  {col(t,"WARDOS_VERIFIED","CRED")} anthropic granted · injected by the proxy')
tb_note = notif("The trust bar", "The trust bar, top of the screen: project, agent state, network, credentials, observer, TamperWard; green is verified, amber restricted, red denied.")
add(t, bar(t, "ward-demo", "CLAUDE ● working", tw=True) + win(24, 56, 1100, 560, None, panel) + tb_note, "ward claude · the sandbox, the proxy, the observer; the bar goes live", 2600)
# 7. Done
add(t, bar(t, "ward-demo", "CLAUDE ● working", tw=True) + menu("You are set", ["Super + Space is everything: projects, agents, verify, apps", "Super + K lists the keys", "docs/onboarding.md is the five-minute path", "Done"], sel=3) + notif("Welcome to WardOS", "Super + Space is everything · Super + K lists the keys · docs/onboarding.md"), "done · under five minutes from first login", 2000)
# 8. Working desktop: terminal + observer
term = (f'{col(t,"WARDOS_ACCENT","~/ward-demo")}{col(t,"WARDOS_TEXT_MUTED"," main")}\n{col(t,"WARDOS_ACCENT","$")} ward claude\n  {col(t,"WARDOS_VERIFIED","CRED")} anthropic granted · injected by the proxy\n  {col(t,"WARDOS_TEXT_MUTED","NET  api.anthropic.com  allow")}\n\n{col(t,"WARDOS_ACCENT","›")} Make the token expiry check reject a token at the exact expiry second.\n\n{col(t,"WARDOS_TEXT_MUTED","● Read src/lib.rs")}\n{col(t,"WARDOS_TEXT_MUTED","● Read tests/security_expiry.rs")}\n{col(t,"WARDOS_DENIED","✗ Edit tests/security_expiry.rs — protected by TamperWard policy: tests")}\n{col(t,"WARDOS_TEXT_MUTED","● Edit src/lib.rs")}\n{col(t,"WARDOS_TEXT_MUTED","● Bash cargo test")}\n  {col(t,"WARDOS_VERIFIED","test result: ok. 3 passed")}\n\n{col(t,"WARDOS_ACCENT","›")} <span class="cursor"></span>')
def observer(extra=""):
    rows = [("00:00","START","session","WARDOS_TEXT"),("00:12","CRED","anthropic · proxy injection","WARDOS_VERIFIED"),("00:12","NET","api.anthropic.com allow","WARDOS_TEXT"),("00:13","TOOL","Read src/lib.rs","WARDOS_TEXT"),("00:14","DENY","tests/security_expiry.rs · protected by TamperWard policy: tests","WARDOS_DENIED"),("00:15","EDIT","src/lib.rs","WARDOS_TEXT"),("00:16","RUN","cargo test","WARDOS_ACCENT"),("00:19","EXIT","exit 0","WARDOS_VERIFIED")]
    out = "\n".join(f'{col(t,"WARDOS_TEXT_MUTED",ts)}  {col(t,k,kind.ljust(5))} {E(msg)}' for ts,kind,msg,k in rows)
    return win(1148, 56, 748, 1000, "● WARD │ sess_01M20HZ… │ ward-demo │ CLAUDE ● working │ LIVE", out + extra)
add(t, bar(t, "ward-demo", "CLAUDE ● working", tw=True) + win(24, 56, 1100, 1000, None, term) + observer(), "working · the agent edits code; the protected test is refused; ward watch shows every row", 2800)
# 8b. Verify freshness: a pass, then an edit turns it STALE
verify_term = term.replace('%s ' % col(t,"WARDOS_ACCENT","›") + '<span class="cursor"></span>', col(t,"WARDOS_ACCENT","$") + ' ward verify\n  ' + col(t,"WARDOS_VERIFIED","✓ VERIFIED") + ' ' + col(t,"WARDOS_TEXT_MUTED","· candidate 7c01f9a · 3 tests · 0.3s") + '\n\n' + col(t,"WARDOS_ACCENT","›") + ' <span class="cursor"></span>')
add(t, bar(t, "ward-demo", "CLAUDE ● working", tw=True, verify="ok") + win(24, 56, 1100, 1000, None, verify_term) + observer(f'\n{col(t,"WARDOS_TEXT_MUTED","00:22")}  {col(t,"WARDOS_VERIFIED","VERIFY")} candidate 7c01f9a · 3 tests'), "ward verify · VERIFY ✓ names the candidate the green mark is bound to", 2400)
stale_term = verify_term.replace(col(t,"WARDOS_ACCENT","›") + ' <span class="cursor"></span>', col(t,"WARDOS_ACCENT","›") + ' edit one line of src/lib.rs\n\n' + col(t,"WARDOS_TEXT_MUTED","● Edit src/lib.rs") + '\n\n' + col(t,"WARDOS_ACCENT","›") + ' <span class="cursor"></span>')
add(t, bar(t, "ward-demo", "CLAUDE ● working", tw=True, verify="stale") + win(24, 56, 1100, 1000, None, stale_term) + observer(f'\n{col(t,"WARDOS_TEXT_MUTED","00:22")}  {col(t,"WARDOS_VERIFIED","VERIFY")} candidate 7c01f9a · 3 tests\n{col(t,"WARDOS_TEXT_MUTED","00:29")}  {col(t,"WARDOS_TEXT_MUTED","EDIT ")} src/lib.rs') + notif("Verification is stale", "The worktree no longer digests to 7c01f9a; the green mark is gone until ward verify runs again."), "the moment the tree changes, VERIFY ~ STALE · green never outlives the state it judged", 2600)
# 9. Approval
appr = notif("Claude requests", f'<tt>api.github.com</tt><br>Reason  Read GitHub issue #381<br>Scope   WebFetch<br><span style="color:{t["WARDOS_TEXT_MUTED"]}">y allow once · s allow for the session · n deny</span>', appr=True, prog=62)
add(t, bar(t, "ward-demo", "CLAUDE ● waiting", tw=True) + win(24, 56, 1100, 1000, None, term) + observer(f'\n{col(t,"WARDOS_TEXT_MUTED","00:24")}  {col(t,"WARDOS_RESTRICTED","ASK  ")} WebFetch api.github.com') + appr, "an approval · held by the daemon, answered with y, s or n", 2200)
add(t, bar(t, "ward-demo", "CLAUDE ● working", tw=True) + win(24, 56, 1100, 1000, None, term) + observer(f'\n{col(t,"WARDOS_TEXT_MUTED","00:24")}  {col(t,"WARDOS_RESTRICTED","ASK  ")} WebFetch api.github.com\n{col(t,"WARDOS_TEXT_MUTED","00:27")}  {col(t,"WARDOS_VERIFIED","ALLOW")} api.github.com · once'), "y · allowed once; the decision is a row in the log", 1600)
# 10. Command centre
launcher = [("PROJECTS", None), ("ward-demo", "● working"), ("AGENTS", None), ("Start Claude", ""), ("Start Codex", ""), ("Resume session", "ward-demo · ● working"), ("SECURITY", None), ("Verify current project", ""), ("Review permissions", ""), ("SYSTEM", None), ("Terminal", ""), ("Browser", ""), ("Settings", "")]
add(t, bar(t, "ward-demo", "CLAUDE ● working", tw=True) + win(24, 56, 1100, 1000, None, term) + observer() + menu("WARD", launcher, sel=5), "Super + Space · the command centre: projects, agents, verify, apps", 2200)
# 11. Theme cycle
t = TN
add(t, bar(t, "ward-demo", "CLAUDE ● working", tw=True, verify=True) + win(24, 56, 1100, 1000, None, term.replace(D_["WARDOS_ACCENT"], TN["WARDOS_ACCENT"]).replace(D_["WARDOS_TEXT_MUTED"], TN["WARDOS_TEXT_MUTED"]).replace(D_["WARDOS_VERIFIED"], TN["WARDOS_VERIFIED"]).replace(D_["WARDOS_DENIED"], TN["WARDOS_DENIED"])) + observer().replace(D_["WARDOS_ACCENT"], TN["WARDOS_ACCENT"]).replace(D_["WARDOS_TEXT_MUTED"], TN["WARDOS_TEXT_MUTED"]).replace(D_["WARDOS_VERIFIED"], TN["WARDOS_VERIFIED"]).replace(D_["WARDOS_DENIED"], TN["WARDOS_DENIED"]) + notif("Theme · Tokyo Night", "Bar, terminal, menus, notifications, lock screen and wallpaper, from one file"), "Super + Shift + T · Tokyo Night; fourteen themes render into every component", 2400)
# 12. Lock
add(t, f'<div class="lock"><div class="clock">23:41</div><div class="date">Tuesday 8 September</div><div class="in">password</div><div class="mark">WARD</div></div>', "Super + L · the lock screen", 2400)
os.makedirs(f"{S}/frames", exist_ok=True)
for i, (h, ms) in enumerate(frames):
    open(f"{S}/frames/{i:02d}.html", "w").write(h)
json.dump([ms for _, ms in frames], open(f"{S}/frames/durations.json", "w"))
print(len(frames), "frames")
