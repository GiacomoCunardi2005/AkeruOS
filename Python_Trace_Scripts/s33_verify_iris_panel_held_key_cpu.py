#!/usr/bin/env python3
"""Replay a held iris request and verify the original panel waits for release."""
from pathlib import Path

base = Path(__file__).with_name('s33_verify_iris_panel_key_cpu.py')
effective_source = base.read_text()
changes = {
    'iris_panel_key_cpu_%Y%m%dT%H%M%SZ': 'iris_panel_held_key_cpu_%Y%m%dT%H%M%SZ',
    "action='iris-panel-key'": "action='iris-panel-held-key'",
    'cmp r0,0\\n mov r0,0\\n bne key_done\\n mov r0,1':
        'cmp r0,3\\n mov r0,0\\n bge key_done\\n mov r0,1',
    'w[18]==2 and w[19]==2': 'w[18]==2 and w[19]==4',
    "(out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())":
        "(out / 'verifier_snapshot.py').write_text(effective_source)",
    "status='PASS_IRIS_PANEL_KEY_FIXTURES'": "status='PASS_IRIS_PANEL_HELD_KEY_FIXTURES'",
    "assert draw in segment and call in segment and segment.index(draw)<segment.index(call)":
        "assert draw in segment and call in segment and segment.index(draw)<segment.index(call)\n            wait='0x2c5144 ' if key==9 else '0x2c5174 '\n            assert sum(line.startswith(wait) for line in segment.splitlines()) == 3\n            assert segment.index(wait) < segment.rindex('0x2c50b8 ')",
}
for old, new in changes.items():
    assert effective_source.count(old) == 1, old
    effective_source = effective_source.replace(old, new)
exec(compile(effective_source, str(base), 'exec'), {'__name__': '__main__', '__file__': str(base), 'effective_source': effective_source})
