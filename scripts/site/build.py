"""Generate docs/ (the GitHub Pages site) from strings.py.

    python3 scripts/site/build.py

Needs `pip install budoux` for line-break hints in Chinese. Without it the Chinese pages still build, with
breaks anywhere, which is what this script exists to avoid.
"""
import html
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from strings import BASE, LANGS, S, URLS  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
DOCS = os.path.join(ROOT, 'docs')

try:
    import budoux
    PARSERS = {'zh-Hans': budoux.load_default_simplified_chinese_parser(),
               'zh-Hant': budoux.load_default_traditional_chinese_parser()}
except ImportError:
    PARSERS = {}

CJK = re.compile(r'[\u3400-\u9fff\uff00-\uffef\u3000-\u303f]')
ASCII_ALNUM = re.compile(r'[A-Za-z0-9]')
TAG = re.compile(r'(<[^>]+>)')

# Words that must never be split over two lines: hyphenated compounds (Wi-Fi, macOS-WLAN), 802.11x, paired model names.
NOWRAP_TOKENS = re.compile(r'(BE\d+ / BE\d+|\w+(?:-\w+)+(?:\u00a0\d)?|802\.11[a-z]+|Tahoe/Sequoia)')
# A number keeps its unit and a product name keeps its version number (the space becomes a no-break space).
NBSP_PAIRS = [
    re.compile(r'(\d) (GHz|MHz|ГГц|МГц|Mbit/s|Gbit/s)'),
    re.compile(r'\b(Wi-Fi|macOS|Darwin|API|Tahoe|Sequoia|WPA|AX|BE) (\d)'),
]


def md(s, lang):
    """Mini markup to HTML, then line-break care."""
    s = html.escape(s, quote=False)
    s = re.sub(r'`([^`]+)`', r'<code>\1</code>', s)
    s = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', s)

    def link(m):
        key = m.group(2)
        href = key if key.startswith('#') else URLS[key]
        return '<a href="%s">%s</a>' % (href, m.group(1))
    s = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', link, s)
    return breaks(s, lang)


def breaks(s, lang):
    out = []
    in_code = False
    for part in TAG.split(s):
        if TAG.fullmatch(part):
            in_code = part == '<code>' or (in_code and part != '</code>')
            out.append(part)
            continue
        if in_code:
            out.append(part)
            continue
        for rx in NBSP_PAIRS:
            part = rx.sub(lambda m: m.group(1) + chr(0xa0) + m.group(2), part)
        # The no-break words are set aside while BudouX looks at the text, so no hint can land inside them.
        kept = []

        def keep(m):
            kept.append(m.group(0))
            return chr(0xE100 + len(kept) - 1)
        part = NOWRAP_TOKENS.sub(keep, part)
        parser = PARSERS.get(lang)
        if parser and CJK.search(part):
            part = wbr(part, parser)
        part = re.sub('[-]', lambda m: '<span class="nw">%s</span>' % kept[ord(m.group(0)) - 0xE100], part)
        out.append(part)
    return ''.join(out)


def wbr(text, parser):
    """BudouX phrase boundaries as <wbr>, never inside a run of ASCII letters or digits."""
    phrases = parser.parse(text)
    res = phrases[0]
    for ph in phrases[1:]:
        if ASCII_ALNUM.fullmatch(res[-1]) and ASCII_ALNUM.fullmatch(ph[0]):
            res += ph
        else:
            res += '<wbr>' + ph
    return res


def attr(s):
    return html.escape(s, quote=True)


def page(code, folder, native, hl):
    t = S[code]
    md_ = lambda x: md(x, code)           # noqa: E731
    up = '' if not folder else '../'
    ok = '<span class="pill ok"><span aria-hidden="true">✅</span> %s</span>' % t['ok']
    dev = '<span class="pill dev"><span aria-hidden="true">🧪</span> %s</span>' % t['dev']
    cardtxt = {'all': t['cards_all'], 'ac': t['cards_ac'], 'axbe': t['cards_axbe'], 'ax210': t['cards_ax210'],
               'be': t['cards_be']}
    ids = ['lineage', 'works', 'cards', 'install', 'continuity', 'report', 'build', 'license']
    nav = '\n'.join('<a href="#%s">%s</a>' % (i, attr(n)) for i, n in zip(ids, t['nav']))

    def href_to(c, f):
        if c == code:
            return './'
        return (up + f + '/') if f else (up or './')
    langs = '\n'.join(
        '<li><a href="%s" hreflang="%s" lang="%s" data-lang="%s"%s>%s<span>%s</span></a></li>' % (
            href_to(c, f), h, h, c.lower(), ' aria-current="true"' if c == code else '', c, n)
        for c, f, n, h in LANGS)
    alternates = '\n'.join(
        '<link rel="alternate" hreflang="%s" href="%s">' % (h, BASE + (f + '/' if f else ''))
        for c, f, n, h in LANGS) + '\n<link rel="alternate" hreflang="x-default" href="%s">' % BASE

    works_rows = []
    for feat, cards, status, note in t['works']:
        cell = ok if status == 'ok' else dev
        if note:
            cell += ' <span class="snote">%s</span>' % md_(note)
        works_rows.append('<tr><td>%s</td><td>%s</td><td>%s</td></tr>' % (md_(feat), cardtxt[cards], cell))

    def code_list(ids):
        return ' '.join('<code>%s</code>' % i for i in ids.split())
    cards_rows = [
        ('Wi-Fi 7', 'BE200, BE202, Killer BE1750 x/w', code_list('272B'), 'iwx, MLD API 92 (86)'),
        ('Wi-Fi 7', 'BE201, Killer BE1750 i/s', code_list('A840 7740 4D40'), 'iwx, MLD API 92'),
        ('Wi-Fi 6E', 'AX210, AX211, AX411', code_list('2725 2726 7A70 7AF0 51F0 51F1 54F0 7F70 2729 7E40'), 'iwx, API 68'),
        ('Wi-Fi 6', 'AX200, AX201, AX1650', code_list('2723 2720 02F0 06F0 34F0 3DF0 4DF0 43F0 A0F0'), 'iwx, API 68'),
        ('Wi-Fi 5', '9260, 9461, 9462, 9560, 8265, 8260, 7265, 7260, 3168, 3165, 3160', md_(t['see_plist']), 'iwm'),
        ('Wi-Fi 4', '6xxx, 5xxx, 4965, 2200, 2230, 1000, 1030, 100, 105, 130, 135', md_(t['see_plist']), 'iwn'),
    ]
    cards_html = '\n'.join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
        '<span class="nw">%s</span>' % g, m, p, h) for g, m, p, h in cards_rows)
    boot_codes = ['itlwm_he=1', 'itlwm_gl_api=86', '-itlawdl …']
    boot_rows = '\n'.join('<tr><td><code>%s</code></td><td>%s</td></tr>' % (c, md_(e))
                          for c, e in zip(boot_codes, t['boot']))
    cred = '\n'.join('<li>%s</li>' % md_(c) for c in t['cred'])
    steps = '\n'.join('<li>%s</li>' % md_(c) for c in t['steps'])
    awdl_li = '\n'.join('<li>%s</li>' % md_(c) for c in t['awdl_li'])
    chain = '\n'.join('<li><strong>%s</strong><span>%s</span></li>' % (a, md_(b)) for a, b in zip(
        ['itlwm', 'laobamac/itlwm', 'Eric-AirportItlwm'], t['chain']))
    st = t['stats']
    th = lambda cols: ''.join('<th>%s</th>' % md_(c) for c in cols)   # noqa: E731
    desc = t['sub'] if code != 'en-US' else (
        'Native macOS Wi-Fi for Intel cards, from 802.11n to Wi-Fi 7. macOS Tahoe 26 and Sequoia 15, WPA3, 6 GHz, '
        '802.11be, BE200 / BE201 and every card itlwm supports.')
    is_root = not folder
    root_js = '<script>var SITE_ROOT=true;</script>\n' if is_root else ''

    doc = f'''<!DOCTYPE html>
<html lang="{hl}" data-lang="{code.lower()}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{attr(t['title'])}</title>
<meta name="description" content="{attr(desc)}">
<link rel="canonical" href="{BASE + (folder + '/' if folder else '')}">
{alternates}
<link rel="icon" type="image/png" href="{up}be200-icon.png">
<link rel="stylesheet" href="{up}style.css">
{root_js}<script src="{up}lang.js"></script>
<script defer src="{up}app.js"></script>
</head>
<body>
<a class="skip" href="#main">{attr(t['skip'])}</a>
<header class="top"><div class="bar">
<a class="brand" href="#top"><img src="{up}be200-icon.png" width="28" height="28" alt="">Eric-AirportItlwm</a>
<button class="burger" type="button" aria-label="{attr(t['menu'])}" aria-expanded="false" aria-controls="sections"><span></span><span></span><span></span></button>
<nav id="sections" aria-label="{attr(t['nav_aria'])}">
{nav}
</nav>
<details class="lang">
<summary aria-label="Language"><span lang="{hl}">{code}</span></summary>
<ul>
{langs}
</ul>
</details>
</div></header>
<main id="main">
<section class="hero" id="top"><div class="wrap hero-grid">
<div class="hero-text">
<p class="eyebrow">{md_(t['eyebrow'])}</p>
<h1>{md_(t['h1'])}</h1>
<p class="sub">{md_(t['sub'])}</p>
<p class="lead">{md_(t['lead'])}</p>
<p class="cta"><a class="btn primary" href="{URLS['latest']}">{t['cta'][0]}</a><a class="btn" href="{URLS['repo']}">{t['cta'][1]}</a><a class="btn" href="{URLS['issues']}">{t['cta'][2]}</a></p>
<p class="credit-line">{md_(t['credit'])}</p>
</div>
<div class="hero-art"><img src="{up}be200-icon.png" width="256" height="256" alt="Eric-AirportItlwm"></div>
</div>
<div class="wrap"><dl class="stats">
<div><dt>{st[0]}</dt><dd><span class="num">2882</span> <span class="unit">Mbit/s</span></dd></div>
<div><dt>{st[1]}</dt><dd><span class="num">2.55</span> <span class="unit">Gbit/s</span></dd></div>
<div><dt>{st[2]}</dt><dd><span class="num">1.84</span> <span class="unit">Gbit/s</span></dd></div>
<div><dt>{st[3]}</dt><dd><span class="num">320</span> <span class="unit">{'ГГц' if code == 'ru' else 'MHz'}</span></dd></div>
</dl><p class="note">{md_(t['note'])}</p>
<ul class="chips"><li>macOS 26 Tahoe</li><li>macOS 15.2+ Sequoia</li><li>x86_64</li><li>GPL-2.0</li></ul></div>
</section>
<section class="lineage" id="lineage"><div class="wrap">
<h2>{md_(t['lin_h2'])}</h2>
<p class="big">{md_(t['lin_big'])}</p>
<ol class="chain">
{chain}
</ol>
<p>{md_(t['lin_flow'])}</p>
<h3>{md_(t['cred_h3'])}</h3>
<ul class="credits">
{cred}
</ul></div></section>
<section id="works"><div class="wrap"><h2>{md_(t['works_h2'])}</h2>
<div class="table-wrap"><table><thead><tr>{th(t['th_works'])}</tr></thead><tbody>
{chr(10).join(works_rows)}
</tbody></table></div></div></section>
<section id="cards"><div class="wrap"><h2>{md_(t['cards_h2'])}</h2>
<div class="table-wrap"><table class="cards"><thead><tr>{th(t['th_cards'])}</tr></thead><tbody>
{cards_html}
</tbody></table></div><p>{md_(t['cards_p'])}</p></div></section>
<section id="install"><div class="wrap"><h2>{md_(t['install_h2'])}</h2><ol class="steps">
{steps}
</ol><p>{md_(t['country'])}</p>
<h3>{md_(t['boot_h3'])}</h3><div class="table-wrap"><table><thead><tr>{th(t['th_boot'])}</tr></thead><tbody>
{boot_rows}
</tbody></table></div></div></section>
<section id="continuity"><div class="wrap"><h2>{md_(t['cont_h2'])}</h2>
<p>{dev}</p>
<h3>{md_(t['hot_h3'])}</h3><p>{md_(t['hot_p'])}</p>
<h3>{md_(t['awdl_h3'])}</h3><p>{md_(t['awdl_p'])}</p><ul>
{awdl_li}
</ul><p>{md_(t['awdl_p2'])}</p></div></section>
<section id="report"><div class="wrap"><h2>{md_(t['rep_h2'])}</h2><p>{md_(t['rep_p'])}</p><p><a class="btn" href="{URLS['newissue']}">{t['rep_btn']}</a></p></div></section>
<section id="build"><div class="wrap"><h2>{md_(t['build_h2'])}</h2>
<div class="code"><button type="button" class="copy" data-copied="{attr(t['copied'])}" hidden>{t['copy']}</button><pre><code>git clone https://github.com/acidanthera/MacKernelSDK.git MacKernelSDK
git -C MacKernelSDK checkout 3f750085caa17ec3a7880f11c11bf4f48cd6a164
python3 scripts/prepare_tahoe_sdk.py
xcodebuild -project itlwm.xcodeproj -scheme AirportItlwm-Tahoe   -configuration Release ARCHS=x86_64 CODE_SIGNING_ALLOWED=NO build
xcodebuild -project itlwm.xcodeproj -scheme AirportItlwm-Sequoia -configuration Release ARCHS=x86_64 CODE_SIGNING_ALLOWED=NO build</code></pre></div>
<p>{md_(t['build_p'])}</p></div></section>
<section id="license"><div class="wrap"><h2>{md_(t['lic_h2'])}</h2><p>{md_(t['lic_p'])}</p></div></section>
</main>
<footer><div class="wrap"><p>Eric-AirportItlwm · <a href="{URLS['repo']}">{t['foot'][0]}</a> · <a href="{URLS['releases']}">{t['foot'][1]}</a> · <a href="{URLS['issues']}">{t['foot'][2]}</a></p></div></footer>
</body>
</html>
'''
    # Every link that leaves the site opens in a new tab; the language menu and in-page anchors stay put.
    doc = re.sub(r'<a ((?:class="[^"]*" )?href="https?://[^"]*")', r'<a target="_blank" rel="noopener noreferrer" \1', doc)
    return doc


def main():
    if not PARSERS:
        print('warning: budoux is not installed; Chinese pages get no line-break hints', file=sys.stderr)
    for code, folder, native, hl in LANGS:
        assert set(S[code]) == set(S['en-US']), (code, set(S['en-US']) ^ set(S[code]))
        d = os.path.join(DOCS, folder) if folder else DOCS
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, 'index.html'), 'w', encoding='utf-8', newline='\n') as f:
            f.write(page(code, folder, native, hl))
    # The first version of the Chinese page lived at /zh/.
    os.makedirs(os.path.join(DOCS, 'zh'), exist_ok=True)
    with open(os.path.join(DOCS, 'zh', 'index.html'), 'w', encoding='utf-8', newline='\n') as f:
        f.write('<!DOCTYPE html>\n<html lang="zh-Hans"><head><meta charset="utf-8">'
                '<meta http-equiv="refresh" content="0; url=../zh-hans/">'
                '<link rel="canonical" href="%szh-hans/"><title>Eric-AirportItlwm</title></head>'
                '<body><a href="../zh-hans/">简体中文</a></body></html>\n' % BASE)


if __name__ == '__main__':
    main()
