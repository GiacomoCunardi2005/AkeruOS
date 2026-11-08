#!/usr/bin/env python3
"""Offline S33 V1.1 transfer callback slots and MMIO notification branches."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[(0x2C00E4,0x2C0116,'TransferParametersAndFirstObject'),
 (0x2C0130,0x2C014C,'SelectPreparationPath'),
 (0x2C018C,0x2C01AC,'TwoCallbackRegistrationBranches'),
 (0x2C01CE,0x2C01E4,'StartServiceAndCheckedStatus'),
 (0x2C0652,0x2C0660,'RemainingCountAndReturn'),
 (0x267170,0x267178,'CallbackSetterA'),
 (0x268BC4,0x268BCC,'CallbackSetterB'),
 (0x267F34,0x267F44,'NotificationAFirstGate'),
 (0x267F48,0x267F74,'NotificationAStatusAndFlag'),
 (0x267F7C,0x267F8C,'NotificationALoadAndBranch'),
 (0x2689F6,0x2689FC,'NotificationAIndirectCall'),
 (0x268A20,0x268A30,'NotificationBStatusGate'),
 (0x268A34,0x268A4A,'NotificationBRegisterAndLoad'),
 (0x268A50,0x268A58,'NotificationBIndirectCall'),
 (0x304368,0x304374,'SDCompletionEventPublisher')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/transfer_callbacks';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={2519492: 3584868, 2526740: 3584984, 2522928: 267255864, 2522948: 267255860, 2522996: 3584996, 2523000: 3584868, 2525724: 267386916, 2525744: 267386920, 2525772: 3584984, 2883864: 5319772, 3163032: 14680069}
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
 edges=[(2883980, 2526148), (2883998, 2519408), (2884050, 2518984), (2885206, 1545044), (3162986, 1412284)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={2883822: 'mov.f\tr15,r4', 2883832: 'ld_s\tr15,[r14,0xc]', 2883828: 'mov_s\tr17,r2', 2883888: 'ld_s\tr0,[r14,0x8]', 2883898: '0x10209', 2883984: 'mov_s\tr0,r17', 2884002: 'mov_s\tr0,r17', 2884058: ';0x2c0656', 2884062: 'mov_s\tr17,r0', 2885204: 'st_s\tr0,[r14,0x8]', 2885214: 'mov_s\tr0,r17', 2519412: 'st_s\tr0,[r1,0]', 2526152: 'st_s\tr0,[r1,0]', 2522936: 'btst_s\tr0,0x8', 2522956: 'and\tr0,r0,256', 2522976: 'sth.di', 2522986: 'stb_s\tr1,[r0,0]', 2523008: 'ld_s\tr0,[r14,0]', 2525686: 'jl_s\t[r0]', 2525732: 'btst_s\tr0,0x1', 2525756: 'sth.di', 2525762: 'ld_s\tr0,[r0,0]', 2525776: 'jl_s\t[r0]', 2525780: 'sth.di\tr0,[r13]', 3162990: 'mov\tr1,512'}
 for a,n in checks.items():assert n in line(a),line(a)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  observations=['First-object preparation chooses callback storage 0x36b364 or 0x36b3d8',
   'Both slots lead to guarded indirect calls after MMIO status checks',
   'Slot A branch also sets flag 0x36b3e4 before callback',
   'SD callback 0x304368 publishes mask 0x200 on event 0xe00005',
   'Start-service status is checked and preserved separately from later callbacks'],
  limits=['No runtime invocation, hardware interrupt provenance or physical persistence observed',
   'Second/third object start branches and callback arbitration remain incomplete'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
