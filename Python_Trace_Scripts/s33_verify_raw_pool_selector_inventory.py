#!/usr/bin/env python3
"""Inventory literal and linear GNU branch candidates in the 16 original S33 payloads."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, re, struct, subprocess, sys, tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'S33-sections/analysis_codex'))
from static_common import BS, PS, BD, ROOT, disasm

out = ROOT / 'Risultati/Mono_RAW' / datetime.now(timezone.utc).strftime('pool_selector_inventory_%Y%m%dT%H%M%SZ')
out.mkdir(parents=True)
tool_dir = ROOT / 'work/build-arc/binutils'
values = {'pool_selector': 0x366e34, 'pool_setter': 0x141cc4,
          'raw_selector': 0x366f90, 'raw_setter': 0x14a2b8}
targets = {0x141cc4: 'pool_setter', 0x14a2b8: 'raw_setter', 0xcbaf0: 'state_producer'}
encodings = {name: {'le': struct.pack('<I', value),
                    'arc': struct.pack('<HH', value >> 16, value & 0xffff)}
             for name, value in values.items()}
occurrences, branches = [], []
pattern = re.compile(r'^\s*([0-9a-f]+):\s+(?:[0-9a-f]{4}\s+)+([a-z][a-z0-9_.]*)\s+[^;]*;0x([0-9a-f]+)\b')
with tempfile.TemporaryDirectory(prefix='s33-selector-inventory-') as tmp:
 for b in BS:
  idx, base = b['index'], b['load_address_candidate']
  payload = PS[idx]
  for name, variants in encodings.items():
   for encoding, needle in variants.items():
    start = 0
    while (pos := payload.find(needle, start)) != -1:
     occurrences.append({'block':idx, 'address':hex(base+pos), 'value':name, 'encoding':encoding, 'aligned':(base+pos)%4==0})
     start = pos+1
  elf, back = Path(tmp) / f'{idx}.elf', Path(tmp) / f'{idx}.bin'
  subprocess.run([tool_dir/'objcopy', '-I','binary','-O','elf32-littlearc','-B','arc',
                  '--rename-section','.data=.text,alloc,load,readonly,code,contents',
                  '--change-section-vma',f'.data={base:#x}', '--strip-all',BD/b['file'],elf],check=True,capture_output=True)
  subprocess.run([tool_dir/'objcopy','--dump-section',f'.text={back}',elf],check=True,capture_output=True)
  assert back.read_bytes() == payload
  with subprocess.Popen([tool_dir/'objdump','-d','-m','arc:ARC700','-EL',elf],stdout=subprocess.PIPE,text=True) as proc:
   for line in proc.stdout:
    m=pattern.match(line)
    if not m: continue
    site, op, target = int(m[1],16), m[2], int(m[3],16)
    if op.startswith('b') and target in targets:
     branches.append({'block':idx,'site':hex(site),'op':op,'target':targets[target], 'instruction':line.strip()})
   assert proc.wait() == 0
assert [(x['block'],x['address']) for x in occurrences if x['value']=='pool_selector' and x['encoding']=='le'] == [(0,'0x141cdc')]
assert any(x['site']=='0xcbb0e' and x['target']=='pool_setter' for x in branches)
assert any(x['site']=='0xcbb5e' and x['target']=='pool_setter' for x in branches)
assert any(x['site']=='0x7cf81e' and x['target']=='raw_setter' for x in branches)
assert any(x['site']=='0x141c94' and x['target']=='pool_setter' for x in branches)
windows = [(0x141b80,0x141b90), (0x141c74,0x141c88), (0x141cc4,0x141cda),
           (0x141ce0,0x141ce8), (0xcbaf0,0xcbb64), (0xcbbc8,0xcbbd4),
           (0x14a2b8,0x14a2d4), (0x7cf7c0,0x7cf828)]
text = '\n'.join(disasm(a,b) for a,b in windows)
(out/'anchored_windows.txt').write_text(text)
result={'status':'PASS_DELIMITED_STATIC', 'firmware':'S33 V1.1',
        'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'payload_sha256':{str(b['index']):hashlib.sha256(PS[b['index']]).hexdigest() for b in BS},
        'occurrences':occurrences,'linear_branch_candidates':branches,
        'limitations':['Byte-search literals are not exhaustive indirect references, computed addresses or aliases.',
                       'Linear disassembly includes data and misaligned code; branch results are candidates, not necessarily instructions.',
                       'No runtime ordering, races, hardware RAM, pool capacity, file I/O or sensor acquisition proven.']}
(out/'inventory.json').write_text(json.dumps(result,indent=2)+'\n')
print('PASS:',out, 'literal occurrences:',len(occurrences),'branch candidates:',len(branches),flush=True)
