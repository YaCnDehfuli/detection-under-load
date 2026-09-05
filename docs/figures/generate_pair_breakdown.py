#!/usr/bin/env python3
"""Generate docs/figures/pair-breakdown.svg from benchmark/results.json.

Counts every rule × capture class in per_capture. Stdlib only.

    python docs/figures/generate_pair_breakdown.py
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
RESULTS = REPO / "benchmark" / "results.json"
OUT = HERE / "pair-breakdown.svg"

INK = "#2f3a42"
LINE = "#5a6570"
TEXT = "#f3efe6"
MUTED = "#e4ddd0"
BG = "#7d8289"
ORDER = (
    ("detected", "detected", "#4d5f52"),
    ("miss-logic", "logic miss", "#6a5a4a"),
    ("out-of-scope", "out of scope", "#5a4f6a"),
    ("miss-telemetry", "telemetry gap", "#4a5f6c"),
)


def _esc(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _count_pairs(payload: dict) -> Counter:
    counts: Counter = Counter()
    for capture in payload["per_capture"].values():
        for rule in capture["rules"].values():
            counts[rule["class"]] += 1
    return counts


def main() -> None:
    payload = json.loads(RESULTS.read_text(encoding="utf-8"))
    counts = _count_pairs(payload)
    total = sum(counts.values())
    rows = [(key, label, counts[key]) for key, label, _fill in ORDER]
    missing = set(counts) - {key for key, _label, _fill in ORDER}
    if missing:
        raise SystemExit(f"unexpected pair classes in results.json: {sorted(missing)}")

    width, height = 880, 360
    pad_l, pad_r, pad_t, pad_b = 148, 72, 64, 36
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    n = len(rows)
    gap = 18
    bar_h = (plot_h - (n - 1) * gap) / n
    max_n = max(row[2] for row in rows)

    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="{total} rule and capture pairs by miss class">',
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="{BG}"/>',
        f'<text x="{width/2:.1f}" y="28" text-anchor="middle" '
        f'font-family="ui-sans-serif, Helvetica, Arial, sans-serif" '
        f'font-size="16" font-weight="700" fill="{TEXT}">'
        f"{total} rule × capture pairs</text>",
        f'<text x="{width/2:.1f}" y="48" text-anchor="middle" '
        f'font-family="ui-sans-serif, Helvetica, Arial, sans-serif" '
        f'font-size="12" fill="{MUTED}">'
        "from benchmark/results.json per_capture classes</text>",
    ]

    fills = {key: fill for key, _label, fill in ORDER}
    for i, (key, label, value) in enumerate(rows):
        y = pad_t + i * (bar_h + gap)
        bar_w = (value / max_n) * plot_w if max_n else 0
        parts.append(
            f'<text x="{pad_l - 12}" y="{y + bar_h / 2 + 4:.1f}" text-anchor="end" '
            f'font-family="ui-sans-serif, Helvetica, Arial, sans-serif" '
            f'font-size="13" fill="{TEXT}">{_esc(label)}</text>'
        )
        parts.append(
            f'<rect x="{pad_l}" y="{y:.1f}" width="{bar_w:.1f}" height="{bar_h:.1f}" '
            f'rx="6" ry="6" fill="{fills[key]}" stroke="{INK}" stroke-width="1.2"/>'
        )
        parts.append(
            f'<text x="{pad_l + bar_w + 10:.1f}" y="{y + bar_h / 2 + 4:.1f}" '
            f'font-family="ui-sans-serif, Helvetica, Arial, sans-serif" '
            f'font-size="14" font-weight="700" fill="{TEXT}">{value}</text>'
        )

    parts.append(
        f'<line x1="{pad_l}" y1="{pad_t - 8}" x2="{pad_l}" y2="{pad_t + plot_h}" '
        f'stroke="{LINE}" stroke-width="1.4"/>'
    )
    parts.append("</svg>")
    OUT.write_text("\n".join(parts) + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({', '.join(f'{k}={counts[k]}' for k, _l, _f in ORDER)}; n={total})")


if __name__ == "__main__":
    main()
