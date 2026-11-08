#!/usr/bin/env python3
"""Offline S33 V1.1 configuration initializer and five-word callback descriptor installation."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[(0x15DF98,0x15DFC2,'InitializerInputAndSizeGuard'),
 (0x15E560,0x15E5A8,'ConditionalCallbackDescriptorInstall'),
 (0x15E614,0x15E62A,'ExtraDescriptorFieldGuard'),
 (0x12F776,0x12F786,'FirstKnownConfigurationCaller'),
 (0x1649A8,0x1649B4,'SecondKnownConfigurationCaller')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/worker_callback_install';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={1435056: 3568784, 1243420: 4465848, 1461140: 4478224}
 for a,v in literals.items():assert word(a)==v
 tools=ROOT/'work/build-arc/binutils';listings=[]
 with tempfile.TemporaryDirectory(prefix='s33-release-') as td:
  elf,back=Path(td)/'0.elf',Path(td)/'0.bin'
  run([tools/'objcopy','-I','binary','-O','elf32-littlearc','-B','arc',
   '--rename-section','.data=.text,alloc,load,readonly,code,contents',
   '--change-section-vma',f'.data={info[0]["load_address_candidate"]:#x}',
   '--strip-all',bd/info[0]['file'],elf])
  run([tools/'objcopy','--dump-section',f'.text={back}',elf]);assert back.read_bytes()==ps[0]
  for a,b,label in WINDOWS:
   t=run([tools/'objdump','-d','-m','arc:ARC700','-EL',f'--start-address={a:#x}',f'--stop-address={b:#x}',elf])
   assert 'out of bounds' not in t.lower(),label
   listings.append('WINDOW '+label+'\n'+t.replace(str(elf),'verified-block0.elf'))
 listing='\n'.join(listings)
 def line(a):
  hits=[l for l in listing.splitlines() if re.match(rf'^\s*{a:x}:',l)]
  assert len(hits)==1,(hex(a),hits)
  return hits[0]
 edges=[(0x12F77C,0x15DF98),(0x1649AE,0x15DF98)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={1433506: 'mov_s\tr16,r0', 1433518: 'ld\tr0,[r16]', 1433522: 'cmp\tr0,328', 1433528: ';0x15dfc2', 1433532: ';0x15f0f8', 1434976: 'ld\tr0,[sp,160]', 1434982: ';0x15e720', 1434984: 'ld\tr0,[sp,168]', 1434990: ';0x15e720', 1434992: 'ld.as\tr1,[r16,68]', 1435000: 'ld_s\tr3,[r1,0x4]', 1435002: 'ld_s\tr2,[r1,0]', 1435004: 'st_s\tr3,[r0,0x34]', 1435008: 'st_s\tr2,[r0,0x30]', 1435010: 'ld_s\tr0,[r1,0x8]', 1435014: 'st_s\tr0,[r15,0x38]', 1435016: 'ld_s\tr0,[r1,0xc]', 1435018: 'ld_s\tr1,[r1,0x10]', 1435022: 'st_s\tr0,[r15,0x3c]', 1435026: 'st_s\tr1,[r0,0x40]', 1435158: ';0x15e4f8'}
 for a,n in checks.items():assert n in line(a),line(a)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  descriptor_mapping=[dict(source_offset=hex(i*4),destination=hex(0x367490+0x30+i*4)) for i in range(5)],
  observations=['Initializer 0x15df98 receives config pointer and checks first word equals 328',
   'Selected branch reads callback descriptor pointer from input+0x110 using scaled load',
   'Five source words populate control+0x30/+0x34/+0x38/+0x3c/+0x40',
   'Preferred and fallback callbacks traced previously come from source descriptor+8/+12',
   'Two callers pass configuration objects 0x4424b8 and 0x445510'],
  limits=['Actual contents and producers of the two input configurations remain unresolved',
   'Branch conditions are stack intermediates; user mode meaning not yet attributed',
   'Other initializer branches and failure rollback not fully audited',
   'No runtime callback identities, physical buffer lifetime or JPEG persistence proof'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
