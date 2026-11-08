#!/usr/bin/env python3
"""Offline S33 V1.1 worker descriptor callback selection and request copy contract."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[(0x15C4E8,0x15C4FC,'WorkDescriptorBase'),
 (0x15C612,0x15C65A,'BuildExclusiveCallbackFields'),
 (0x247398,0x24741C,'CopyDescriptorToRequestPayload'),
 (0x247310,0x247338,'RequestHeaderAndPayloadPointer'),
 (0x343280,0x3432E4,'WorkerSelectAndInvokeCallback'),
 (0x15C6C0,0x15C6F6,'DirectFirstCallbackSelection'),
 (0x15C740,0x15C764,'DirectFallbackCallbackAndStatusCheck'),
 (0x15C678,0x15C6AC,'RegisterSendWaitReceiveWorkerHelpers')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/worker_descriptor_callbacks';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={1427220: 3744552, 1427228: 3568784, 1427248: 2388752, 1427252: 2388792, 1427256: 2388836, 1427260: 3420800}
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
 edges=[(1427064, 2357644), (1427076, 2357764), (1427088, 2357988), (2388784, 2970156)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={1426674: ';0x15c714', 1426964: 'st\tr16,[r14]', 1427004: 'ld_s\tr0,[r0,0x38]', 1427008: 'st\tr18,[r14,4]', 1427012: ';0x15c64c', 1427014: 'st_s\tr0,[r14,0x38]', 1427022: 'st_s\tr0,[r14,0x38]', 1427026: 'ld_s\tr0,[r0,0x3c]', 1427028: 'st_s\tr0,[r14,0x34]', 2388976: 'ld_s\tr1,[r0,0x34]', 2388978: 'st.di\tr1,[r2,116]', 2388982: 'ld_s\tr1,[r0,0x38]', 2388984: 'st.di\tr1,[r2,120]', 2388772: 'add3\tr1,r0,0x8', 2388776: 'st.di\tr1,[r0,8]', 3420824: 'ld.di\tr3,[r2,8]', 3420834: 'ld_s\tr13,[r3,0x38]', 3420836: 'cmp_s\tr13,0', 3420858: 'ld_s\tr13,[r3,0x34]', 3420896: 'jl_s.d\t[r13]', 1427146: 'ld\tr9,[r0,56]', 1427284: 'ld\tr9,[r0,60]', 1427292: 'jl_s\t[r15]', 1427294: 'cmp_s\tr0,0', 1427296: ';0x15c764'}
 for a,n in checks.items():assert n in line(a),line(a)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  pointer_chain=dict(configuration='0x367490',descriptor='0x392328',request='0x424700',payload='0x424740',
   preferred_config_field='0x38',fallback_config_field='0x3c',
   preferred_request_cell='0x424778',fallback_request_cell='0x424774'),
  observations=['Selected descriptor builder initializes both callback fields exclusively from configuration+0x38 or +0x3c',
   'Descriptor+0x34/+0x38 are copied to request+116/+120 and request+8 points to request+64',
   'Worker loads preferred callback from payload+0x38, otherwise fallback from +0x34',
   'Direct path selects configuration+0x38 or +0x3c and checks call return locally',
   'Both paths share callback sources but full argument, concurrency and error equivalence is not established'],
  limits=['Callback writers and actual function identities remain unresolved',
   'No reader of final result 0x36ad58 is attributed by this report',
   'No runtime call, buffer lifetime guarantee or physical image persistence demonstrated'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
