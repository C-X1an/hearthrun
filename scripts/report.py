#!/usr/bin/env python3
"""Render an escaped offline inspection report; never synthesize a live result."""
import argparse
import html
import json
from pathlib import Path


def render(data: dict, illustrative: bool = False) -> str:
    if not illustrative and not data.get('evidence_run_id'):
        raise ValueError('Real report requires evidence_run_id; use illustrative mode for fixtures')
    banner = 'ILLUSTRATIVE OFFLINE FIXTURE - NOT A LIVE EXECUTION' if illustrative else 'RECORDED EXECUTION - inspect linked raw evidence'
    body = html.escape(json.dumps(data, indent=2, ensure_ascii=True))
    return ('<!doctype html><html lang="en"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
            '<title>HearthRun inspection</title><style>body{font:16px system-ui;max-width:70rem;'
            'margin:3rem auto;padding:1rem;line-height:1.6}pre{white-space:pre-wrap;overflow-wrap:anywhere;'
            'padding:1rem;border:1px solid}strong{display:block;border:2px solid;padding:1rem}</style>'
            f'<main><h1>HearthRun inspection</h1><strong>{banner}</strong>'
            '<p>This report is data, not a claim that containment acceptance passed.</p>'
            f'<h2>Record</h2><pre>{body}</pre></main></html>')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('input', type=Path)
    p.add_argument('output', type=Path)
    p.add_argument('--illustrative', action='store_true')
    args = p.parse_args()
    args.output.write_text(render(json.loads(args.input.read_text()), args.illustrative))
