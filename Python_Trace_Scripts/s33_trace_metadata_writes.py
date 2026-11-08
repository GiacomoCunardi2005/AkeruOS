#!/usr/bin/env python3
"""Offline V1.1 metadata update/deferred commit and lower-device write boundary."""
import json,re,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0x2A1054,0x2A10F4,'MetadataImmediateOrDeferredUpdate'),
 (0x2A10F4,0x2A1124,'DeferredWriteAndFlagClear'),
 (0x2A113C,0x2A1178,'DeferredWriteReturn'),
 (0x2A0C60,0x2A0D70,'LowerTransferPreparationAndResult'),
 (0x2A0C14,0x2A0C60,'SingleAttemptWriteAndRemainingCount'),
 (0x1FA090,0x1FA0C0,'GenericLowerDeviceWrite'),
 (0x1F3554,0x1F35B4,'SaveUnderlyingHandleInPrivateContext'),
 (0x2AC438,0x2AC494,'MetadataCaller'),
]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/metadata_writes';out.mkdir(parents=True,exist_ok=True)
 tools=ROOT/'work/build-arc/binutils';listings=[]
 with tempfile.TemporaryDirectory(prefix='s33-metadata-') as td:
  elf,back=Path(td)/'0.elf',Path(td)/'0.bin'
  run([tools/'objcopy','-I','binary','-O','elf32-littlearc','-B','arc',
   '--rename-section','.data=.text,alloc,load,readonly,code,contents','--change-section-vma',f'.data={info[0]["load_address_candidate"]:#x}',
   '--strip-all',bd/info[0]['file'],elf])
  run([tools/'objcopy','--dump-section',f'.text={back}',elf]);assert back.read_bytes()==ps[0]
  for a,b,label in WINDOWS:
   t=run([tools/'objdump','-d','-m','arc:ARC700','-EL',f'--start-address={a:#x}',f'--stop-address={b:#x}',elf])
   assert 'out of bounds' not in t.lower(),label
   listings.append(f'WINDOW {label}\n'+t.replace(str(elf),'verified-block0.elf'))
 listing='\n'.join(listings)
 def line(a):
  found=[l for l in listing.splitlines() if re.match(rf'^\s*{a:x}:',l)]
  assert len(found)==1,(hex(a),found)
  return found[0]
 edges=[(0x2AC488,0x2A1054),(0x2A107A,0x2A0C60),(0x2A10A8,0x2A0C60),
  (0x2A1114,0x2A0C60),(0x2A0D12,0x2A0C14),(0x2A0C4E,0x1FA090),
  (0x2A0C88,0x1F2348),(0x2A0D2E,0x1F2348),(0x2A0C9C,0x226204),(0x2A0CB6,0x226204)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={0x2A1098:';0x2a10b6',0x2A10B6:'st_s\tr3,[r15,0x38]',
  0x2A10B8:'r13,0',0x2A111A:';0x2a113e',0x2A111E:'st.as\tr0,[r14,107]',
  0x2A0C7C:'ld.as\tr14,[r15,105]',0x1F35AC:'st.as\tr15,[r13,105]',
  0x2A0C46:';0x2a0c5a',0x2A0C44:'r13,0x1',0x2A0C4E:';0x1fa090',
  0x2A0D1C:'ld_s\tr13,[r0,0xc]',0x1FA0A2:'ld_s\tr3,[r3,0x18]',0x1FA0B6:'jl_s\t[r3]'}
 for a,n in checks.items():assert n in line(a),line(a)
 assert 372+0x38==107*4==0x1AC
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],script_sha256=sha(Path(__file__).read_bytes()),
  block_sha256={str(b['index']):b['sha256'] for b in bs},windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  context_fields={'0x1a4':'underlying device file handle, stored by family installer','0x1ac':'pending flag in deferred branch',
   '0x1b0':'transfer position/index used by the selected metadata path','0x1b4':'buffer used by the selected metadata path',
   '0x3c':'nonzero selects deferred branch when state +0x2c4 is not 2','0x350':'controls bracketing lower-device controls'},
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],
  observations=['0x2a1054 may set pending flag and return zero without calling lower transfer',
   '0x2a10f4 clears pending flag only after lower transfer returns zero',
   'Operation 10 in 0x2a0c60 reaches lower device write via 0x2a0c14 and 0x1fa090',
   'Seek return is not locally checked before write in either preparation branch',
   'Write helper makes at most one driver call; remaining count and lower handle error field determine result',
   'Underlying device callbacks are distinct from the upper filesystem callback family'],
  limits=['Transfer units depend on configuration; not universally bytes or SD sectors',
   'No observed physical driver completion, card cache behavior or power-loss persistence',
   'A zero lower-handle error with remaining work is not excluded by this local body; no actual occurrence proved',
   'No complete close or shutdown barrier established'])
 (out/'gnu_verified.txt').write_text(listing);(out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges; pending flag 0x1ac and lower-device boundary')
if __name__=='__main__':main()
