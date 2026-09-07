#!/usr/bin/env python3
"""Build the public results report from committed measurements; --check detects drift."""
import argparse
from collections import Counter
from html import escape
import json
from pathlib import Path
import re
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
REPO = "https://github.com/YaCnDehfuli/detection-under-load/blob/main/"
INK, MUTED, BG = "#172b3a", "#435568", "#ffffff"


def load(name):
    return json.loads((ROOT / "benchmark" / name).read_text())


def text(x, y, label, size=17, anchor="start", color=INK):
    return f'<text x="{x}" y="{y}" font-size="{size}" text-anchor="{anchor}" fill="{color}">{escape(str(label))}</text>'


def svg(title, height, parts):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="900" height="{height}" viewBox="0 0 900 {height}" role="img" aria-label="{escape(title)}">'
            f'<rect width="900" height="{height}" fill="{BG}"/><g font-family="Arial, sans-serif" font-variant-numeric="tabular-nums">'
            + "".join(parts) + '</g></svg>\n')


def table(headers, rows):
    return '<div class="table"><table><thead><tr>' + ''.join(f'<th>{escape(str(v))}</th>' for v in headers) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join(f'<td>{escape(str(v))}</td>' for v in row) + '</tr>' for row in rows) + '</tbody></table></div>'


def source(path, label=None):
    return f'<a href="{REPO}{path}">{escape(label or path)}</a>'


def figure(path, title, caption):
    return f'<figure><img src="figures/{path}" alt="{escape(title)}"><figcaption>{caption}</figcaption></figure>'


def build():
    results, sensitivity, chain, crosscheck = (load(x) for x in ("results.json", "sensitivity.json", "chain.json", "crosscheck.json"))
    manifest = yaml.safe_load((ROOT / "benchmark/manifest.yml").read_text())
    counts = Counter(label for rule in results['summary']['rules'] for label in rule['classes'].values())
    tiers = sensitivity['tiers']
    captures = sensitivity['per_capture']
    totals = [sum(len(c['tiers'][t]['published_firing']) for c in captures.values()) for t in tiers]
    nano = next(c for c in captures.values() if c['tool'] == 'nanodump')
    nanovalues = [len(nano['tiers'][t]['published_firing']) for t in tiers]
    rules = {d['id']: d for p in sorted((ROOT / 'rules').glob('*.yml')) if (d := yaml.safe_load(p.read_text()))}
    pair_total = sum(counts.values())
    h = results['headline']

    # Pair taxonomy: denominator includes the three authored rules in the augmented run.
    names = [('detected', 'Detected', '#35765a'), ('miss-logic', 'Logic miss', '#a55e30'), ('out-of-scope', 'Out of scope', '#746388'), ('miss-telemetry', 'Telemetry gap', '#397b95')]
    parts = [text(28, 35, f'{pair_total} rule/capture pairs', 23)]
    scale = 510 / max(counts.values())
    for i, (key, label, color) in enumerate(names):
        y = 70 + i * 64; v = counts[key]
        parts += [text(28, y + 26, label), f'<rect x="220" y="{y}" width="{v * scale:.2f}" height="36" fill="{color}"/>', text(230 + v * scale, y + 26, v)]
    parts += [f'<line x1="220" y1="337" x2="760" y2="337" stroke="{MUTED}"/>', text(220, 363, '0', 14), text(490, 389, 'Rule/capture pairs (count)', 16, 'middle')]
    pair_svg = svg('Rule and capture outcome taxonomy', 410, parts)

    # This is published firing, not the narrower intrusion-linked credited population.
    parts = [text(28, 35, 'Detections surviving operator-controlled changes', 23), text(28, 62, 'Published rule/capture detections (count)', 16)]
    xs = [95 + i * 166 for i in range(len(tiers))]
    base, top = 340, 100
    maxv = max(totals)
    for v in [0, maxv]:
        y = base - (base - top) * v / maxv
        parts += [f'<line x1="80" y1="{y}" x2="800" y2="{y}" stroke="#d6dee4"/>', text(66, y + 5, v, 15, 'end')]
    points = ' '.join(f'{x},{base-(base-top)*v/maxv:.2f}' for x, v in zip(xs, totals))
    parts += [f'<polyline points="{points}" fill="none" stroke="#276784" stroke-width="4"/>']
    labels = ['Baseline', 'Rename', 'Relocate', 'Strip PE data', 'Rotate identity']
    for x, tier, label, v in zip(xs, tiers, labels, totals):
        y = base - (base - top) * v / maxv
        parts += [f'<circle cx="{x}" cy="{y:.2f}" r="5" fill="#276784"/>', text(x, y - 13, v, 21, 'middle'), text(x, 370, tier, 17, 'middle'), text(x, 395, label, 15, 'middle')]
    parts += [text(220, 300, f'nanodump: {nanovalues[0]} → {nanovalues[1]} at rename', 19, color='#9d3d39'), text(450, 436, 'Mutation tier (cumulative operator changes)', 16, 'middle')]
    ladder_svg = svg('Published detections surviving mutation tiers', 458, parts)

    # Exact published per_100k values and each technique's own corpus denominator.
    benign = chain['benign']
    ordered = sorted(benign, key=lambda rid: benign[rid]['per_100k'], reverse=True)
    short = {'4b447e9d-1c82-47f6-9a01-a1bb0a22d684': 'Unexpected LSASS caller', '34f6cc31-bd6b-482d-b81f-88828475af05': 'SeDebugPrivilege enabled', '470590c3-ea57-4548-99c6-fb44fc592539': 'Unbacked remote thread', 'b12cefde-6646-4e7d-b8cb-ddcb5443648d': 'User download execution', 'ee2324b0-6673-4767-9e34-c84cdd893483': 'Comsvcs MiniDump', '743c314e-3154-4e7c-b209-8211c9b1d2af': 'PowerShell MiniDump'}
    peak = max(v['per_100k'] for v in benign.values())
    parts = [text(28, 35, 'Authored rules on non-target telemetry', 23)]
    for i, rid in enumerate(ordered):
        record = benign[rid]; y = 70 + i * 69; width = record['per_100k'] / peak * 400
        parts += [text(28, y + 23, short[rid]), f'<rect x="310" y="{y}" width="{width:.2f}" height="28" fill="#326b83"/>', text(320 + width, y + 22, record['per_100k']), text(310, y + 48, f"{record['fires']} fires / {record['events']:,} events", 14, color=MUTED)]
    parts += [text(310, 512, '0', 14), text(530, 541, 'Non-target fires per 100,000 events', 17, 'middle')]
    fp_svg = svg('Authored-rule non-target fire rates', 560, parts)

    method_pins = table(['Input repository', 'Pinned commit'], [(name, value['commit']) for name, value in manifest['sources'].items()])
    archive_pins = table(['Capture', 'Tool', 'SHA-256 of archive'], [(c['id'], c['tool'], c['sha256']) for c in manifest['lsass_campaigns']])
    taxonomy = table(['Outcome', 'Pairs', 'Interpretation'], [(label, counts[key], description) for (key, label, _), description in zip(names, ['At least one event matched.', 'Required telemetry was present, but the rule did not match.', 'The rule required a named tool that was not used.', 'The recording lacks an event type or required field.'])])
    pertool = table(['Tool'] + [t + ' ' + label for t, label in zip(tiers, labels)], [(c['tool'], *[len(c['tiers'][t]['published_firing']) for t in tiers]) for c in captures.values()])
    authored = table(['Authored rule', 'Technique scope', 'LSASS captures hit', 'Non-target fires', 'Events', 'Fires / 100k'], [(chain['titles'][rid], benign[rid]['technique'], f"{sum(rid in c['detected'] for c in chain['campaigns'].values())}/{len(chain['campaigns'])}", benign[rid]['fires'], f"{benign[rid]['events']:,}", benign[rid]['per_100k']) for rid in ordered])
    days = sorted(chain['intrusion'])
    transfer = table(['Authored rule'] + days, [(chain['titles'][rid], *[chain['intrusion'][day]['fired'].get(rid, {}).get('matches', 0) for day in days]) for rid in ordered])
    both = set.intersection(*(set(chain['intrusion'][day]['fired']) for day in days))
    disagreements = sum(len(c['only_this_harness']) + len(c['only_zircolite']) + len(c['count_mismatches']) for c in crosscheck)
    event_total = sum(c['events'] for c in chain['intrusion'].values())
    controls = sum(len(v) for c in captures.values() for v in c['control'].values())
    limit = (ROOT / 'README.md').read_text().split('## Limitations\n', 1)[1].split('\n## ', 1)[0]
    # Preserve the limitation wording while turning its one local link into an absolute source link.
    limit = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', lambda m: m[1] + ' (' + REPO + m[2] + ')', limit)
    limit_html = ''.join('<p>' + escape(p.replace('\n', ' ')) + '</p>' for p in limit.strip().split('\n\n'))
    html = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Detection Under Load — Sigma coverage under operator changes</title>
<meta name="description" content="A reproducible study of published Sigma coverage, miss taxonomy, operator-controlled renaming and transfer to APT29 captures.">
<link rel="stylesheet" href="report.css"></head><body><main>
<header><p class="eyebrow">Detection engineering · Research report · ATT&amp;CK T1003.001</p>
<h1>What survives<br>a renamed dumping tool?</h1>
<p class="abstract">{h['rules_published']} published Sigma rules were tested against {h['captures']} LSASS-dump captures containing {results['total_events']:,} events. Renaming operator-controlled artifacts removes {totals[0]-totals[1]} of {totals[0]} published rule/capture detections; relocation removes {totals[1]-totals[2]} more. Distinguishing missing telemetry from logic failures makes those coverage losses interpretable.</p>
<p class="byline">Yasin Dehfouli · {source('README.md', 'Repository and quickstart')}</p></header>
<section><h2>Method</h2><p>The seven captures share one lab, victim host and Sysmon configuration. Source commits and archive digests pin the input bytes. The native harness compiles Sigma conditions and applies the Sysmon and Windows logsource pipelines; the independent engine check below tests agreement.</p>
{method_pins}<details><summary>Capture archive SHA-256 pins</summary>{archive_pins}</details>
<div class="method-grid"><div><h3>Cumulative mutation ladder</h3><ol><li>T0: recorded baseline.</li><li>T1: rename artifacts the operator brought.</li><li>T2: relocate those artifacts.</li><li>T3: clear PE version resources.</li><li>T4: rotate recorded artifact fingerprints.</li></ol></div>
<aside><h3>Control, beside the ladder</h3><p>The control rewrites <code>CurrentDirectory</code>, which no rule in the technique-scoped selection reads. The committed record shows {controls} firing or credit changes in this selection across {len(captures)} captures. A wide-population rule does read the field; its response is recorded separately. The control is not a mutation rung.</p></aside></div>
<p>Behaviour reported by the operating system is not rewritten. “Benign” eligibility excludes captures with the target technique or its siblings and drops captures with no ATT&amp;CK mapping. These are non-target attack simulations, not a measured clean production baseline.</p><p class="source">Sources: {source('benchmark/manifest.yml')}, {source('docs/method.md')}, {source('benchmark/selection.json')}.</p></section>
<section><h2>Coverage results</h2><p>The augmented run has {h['rules_selected']} rules: {h['rules_published']} published externally and {h['rules_selected']-h['rules_published']} authored here. Its {pair_total} rule/capture pairs separate what the data cannot show from what the rules fail to match.</p>
{figure('coverage-report.svg', 'Counts of the four rule/capture outcomes', source('benchmark/results.json') + ': augmented rule population, all capture pairs.')}
{taxonomy}<p>A telemetry gap is not charged as a logic miss. An out-of-scope rule is not evidence that a relevant detector failed. This distinction is the basis for investigating the remaining logic failures.</p></section>
<section><h2>Robustness results</h2><p>This ladder counts published rules firing in each capture in the <code>{escape(sensitivity['population'])}</code> selection. Authored rules are excluded. Intrusion-linked credited matches are a separate reading in the source data; the headline here uses firing counts throughout.</p>
{figure('mutation-ladder.svg', 'Published rule/capture detections surviving five mutation tiers', source('benchmark/sensitivity.json') + ': per_capture → tiers → published_firing. nanodump is annotated directly.')}
{pertool}<p>Relocation suppresses rules through directory exclusions. T3 and T4 cause no additional loss in this selected population; that does not establish immunity to changing version resources or fingerprints in other rule populations. The broader selection and its compensating rules are documented in {source('benchmark/selection.md')}.</p></section>
<section><h2>Authored rules</h2><p>{len(benign)} authored rules were evaluated separately, after inspecting the coverage failures. Each non-target rate uses the corpus eligible for that rule's own technique. The PowerShell rule also carries T1059.001 and requires script-block logging; its scored detection scope here is T1003.001.</p>
{authored}{figure('authored-rates.svg', 'Each authored rule’s non-target fire rate', source('benchmark/chain.json') + ': benign → fires, events and per_100k; exact committed rates shown.')}
<p>Low rates on these quiet captures do not establish production false-positive rates or permit fine-grained ranking of the rules. The LSASS caller rule's eight non-target fires include six Azure guest-agent events and two PowerShell events; PowerShell remains unfiltered because Out-Minidump uses it.</p><p class="source">Definitions: {source('rules/', 'authored Sigma rules')}. {source('docs/reference.md#where-the-rules-run', 'Converted SPL and Kusto queries')} express the logic; conversion is not deployment.</p></section>
<section><h2>Cross-validation</h2><p>Zircolite was used as an independent check across {len(crosscheck)} campaigns and the documented 23 <code>process_access</code> rules. The committed comparison has {disagreements} harness-only results, Zircolite-only results or count mismatches in total. Agreement covers this evaluated subset, not every Sigma feature.</p>
{table(['Campaign tool', 'Harness-only', 'Zircolite-only', 'Count mismatches'], [(c['tool'],len(c['only_this_harness']),len(c['only_zircolite']),len(c['count_mismatches'])) for c in crosscheck])}<p class="source">{source('benchmark/crosscheck.json')}; procedure and rule scope in {source('docs/reference.md#evalcrosscheckpy', 'the evaluator reference')}.</p></section>
<section><h2>Transfer test</h2><p>The same authored rules were applied without tuning to {event_total:,} APT29 events across two days and several hosts. {len(both)} of {len(benign)} rules fire on both days. The table reports matching events, not reconstructed intrusion steps.</p>
{transfer}<p>This is a transfer test on another dataset. It does not establish a deployment result or end-to-end intrusion reconstruction.</p><p class="source">{source('benchmark/chain.json')}: intrusion. Day 1 has {chain['intrusion'][days[0]]['events']:,} events; day 2 has {chain['intrusion'][days[1]]['events']:,}.</p></section>
<section><h2>Limitations</h2>{limit_html}</section>
<footer><p>{source('docs/reference.md', 'Pipeline and command reference')} · {source('docs/decisions.md', 'Design decisions')} · {source('LICENSE', 'MIT license')}</p><p>Figures and report tables are generated from committed results by <code>docs/generate_report.py</code>; CI checks for drift. No research result was remeasured to build this page.</p></footer>
</main></body></html>\n'''
    return {DOCS / 'index.html': html, DOCS / 'figures/coverage-report.svg': pair_svg, DOCS / 'figures/mutation-ladder.svg': ladder_svg, DOCS / 'figures/authored-rates.svg': fp_svg}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    stale = []
    for path, content in build().items():
        if args.check:
            if not path.exists() or path.read_text() != content:
                stale.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    if stale:
        print('Generated report files are stale: ' + ', '.join(stale), file=sys.stderr)
        return 1
    print('Report and three figures are current.' if args.check else 'Generated report and three figures.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
