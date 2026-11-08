#!/usr/bin/env python3
"""Continue the bounded GUI experiment with controlled FEE03E4 bit seeds."""
from pathlib import Path

base = Path(__file__).with_name('s33_verify_gui_exposure_return_fee03c0_cpu.py')
effective_source = base.read_text()
changes = {
    'assert seed in (0xa5a0,0xa5a1)': 'assert seed in (0x2525,0xe525)',
    'exposure_return_fee03c0_{seed:04x}': 'exposure_return_fee03e4_{seed:04x}',
    'gui-exposure-return-fee03c0': 'gui-exposure-return-fee03e4',
    "'fee03c0_initial': seed": "'fee03c0_initial': 0xa5a1, 'fee04b0_initial': 0xa5a4, 'fee03e4_initial': seed",
    "p.write_bytes(struct.pack('<H',seed)+bytes(6)); maps+=mapping(p,0xfee03c0,2)":
        "p.write_bytes(struct.pack('<H',0xa5a1)+bytes(6)); maps+=mapping(p,0xfee03c0,2)\n  p=out/'fee04b0.bin'; p.write_bytes(struct.pack('<H',0xa5a4)+bytes(6)); maps+=mapping(p,0xfee04b0,2)\n  p=out/'fee03e4.bin'; p.write_bytes(struct.pack('<H',seed)+bytes(6)); maps+=mapping(p,0xfee03e4,2)",
    "(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes());":
        "(out/'verifier_snapshot.py').write_text(effective_source);",
}
for old, new in changes.items():
    assert effective_source.count(old) == 1, old
    effective_source = effective_source.replace(old, new)
exec(compile(effective_source, str(base), 'exec'), {'__name__': '__main__', '__file__': str(base), 'effective_source': effective_source})
