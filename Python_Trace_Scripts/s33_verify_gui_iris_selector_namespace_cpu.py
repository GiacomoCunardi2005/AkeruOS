#!/usr/bin/env python3
"""Check how a diagnostic selector is interpreted by the list's open service."""
from pathlib import Path

base = Path(__file__).with_name('s33_verify_gui_exposure_submenu_routes_cpu.py')
effective_source = base.read_text()
changes = {
    'exposure_submenu_routes_cpu_%Y%m%dT%H%M%SZ': 'iris_selector_namespace_cpu_%Y%m%dT%H%M%SZ',
    'gui-exposure-submenu-routes': 'gui-iris-selector-namespace',
    '((0x3f,0),(0x3e,0),(0,0),(0,0))': '((0x3f,0),(0x3e,0),(0x50,0),(0,0))',
    'targets=[0x3f,0x3e,0,0]': 'targets=[0x3f,0x3e,0x50,0]',
    "(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())":
        "(out/'verifier_snapshot.py').write_text(effective_source)",
    "status='PASS_EXPOSURE_SUBMENU_ROUTES_LAB'": "status='PASS_IRIS_SELECTOR_NAMESPACE_LAB'",
    'no aperture route or return from diagnostics is implemented':
        'the third slot requests GUI ID 0x50; the fixture does not open it or invoke iris',
}
for old, new in changes.items():
    assert effective_source.count(old) == 1, old
    effective_source = effective_source.replace(old, new)
exec(compile(effective_source, str(base), 'exec'), {'__name__': '__main__', '__file__': str(base), 'effective_source': effective_source})
