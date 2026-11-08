#!/usr/bin/env python3
"""Offline stage control RMW map and start/handler/teardown ordering; no device I/O."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[];CHECKS={};LITERALS={};CONTROL_MAP=[]
# Constant-bit read/modify/write helpers, with the literal pool omitted.
for fn,reg,bit,kind in [(0x2E347C,0x0FFC2098,0,'set'),(0x2E3498,0x0FFC2098,1,'set'),
 (0x2E34B4,0x0FFC2098,1,'clear'),(0x2E3820,0x0FFC2098,12,'set'),
 (0x2E383C,0x0FFC2098,12,'clear'),(0x2E3610,0x0FFC20B8,0,'set')]:
 WINDOWS.extend([(fn,fn+8,f'Control{fn:x}Prologue'),(fn+12,fn+28,f'Control{fn:x}Body')])
 LITERALS[fn+8]=reg;CHECKS[fn+4]=f'mov_s\tr0,{hex(bit) if bit else "0"}'
 CHECKS[fn+12]='ldh.di\tr10,[r1]';CHECKS[fn+16]=f'{"bset" if kind=="set" else "bclr"}\tr10,r10,r0'
 CHECKS[fn+20]='sth.di\tr10,[r1]'
 CONTROL_MAP.append(dict(function=hex(fn),register=hex(reg),bit=bit,operation=kind,local_poll=False))
for fn,reg,bit in [(0x2E38A0,0x0FFC4000,0),(0x2E38D4,0x0FFC4000,1),
 (0x2E3BE0,0x0FFC3000,0),(0x2E3C14,0x0FFC3000,1)]:
 WINDOWS.extend([(fn,fn+16,f'Toggle{fn:x}Prologue'),(fn+20,fn+52,f'Toggle{fn:x}Body')])
 LITERALS[fn+16]=reg;CHECKS[fn+4]='cmp_s\tr0,0x1'
 CHECKS[fn+10]=f'mov_s\tr1,{hex(bit) if bit else "0"}'
 CHECKS[fn+24]='bset\tr10,r10,r1';CHECKS[fn+40]='bclr\tr10,r10,r1'
 CONTROL_MAP.append(dict(function=hex(fn),register=hex(reg),bit=bit,operation='set if r0==1 else clear',local_poll=False))
for fn,reg in [(0x2E3A24,0x0FFC400C),(0x2E3D74,0x0FFC300C)]:
 WINDOWS.extend([(fn,fn+20,f'Mask{fn:x}Prologue'),(fn+24,fn+60,f'Mask{fn:x}Body')])
 LITERALS[fn+20]=reg;CHECKS[fn+10]='cmp_s\tr0,0x1';CHECKS[fn+16]='not_s\tr15,r1'
 CHECKS[fn+28]='and_s\tr0,r0,r15';CHECKS[fn+30]='or_s\tr13,r13,r0'
 CONTROL_MAP.append(dict(function=hex(fn),register=hex(reg),operation='replace requested mask bits with r0==1',local_poll=False))
WINDOWS.extend([(0x24A75E,0x24A76A,'Start2000FirstControls'),(0x24A906,0x24A91E,'Start2000LastControls'),
 (0x24B280,0x24B296,'Start800Controls'),(0x24B2B4,0x24B2C2,'Start800CommandStore'),
 (0x24BACC,0x24BAE2,'Start1000Controls'),(0x24BB00,0x24BB0E,'Start1000CommandStore'),
 (0x24BCCE,0x24BCEE,'Handler800ControlsBeforeCallback'),(0x24BD0A,0x24BD2A,'Handler1000ControlsBeforeCallback'),
 (0x24B2C8,0x24B30C,'Teardown800'),(0x24BB14,0x24BB5E,'Teardown1000'),
 (0x2E35E4,0x2E35F0,'Mask2000Prologue'),(0x2E35F4,0x2E3610,'Mask2000Body')])
LITERALS.update({0x24B2B0:0x0FFC4004,0x24BAFC:0x0FFC3004,0x24A998:0x0000FFFF,
 0x2E35F0:0x0FFC20B8,0x24B528:0x36ADCC,0x24B52C:0x600C,0x24BD30:0x36ADCC,0x24BD34:0x600B})
CHECKS.update({0x24B284:'mov_s\tr13,0',0x24B28A:'mov_s\tr0,r13',0x24B290:'mov_s\tr0,r13',
 0x24B292:';0x24b2b0',0x24B2B8:'bset\tr10,r10,r13',0x24B2BC:'sth.di\tr10,[r0]',
 0x24BAD0:'mov_s\tr13,0',0x24BAD6:'mov_s\tr0,r13',0x24BADC:'mov_s\tr0,r13',
 0x24BADE:';0x24bafc',0x24BB04:'bset\tr10,r10,r13',0x24BB08:'sth.di\tr10,[r0]',
 0x24BCD8:'mov_s\tr0,0x1',0x24BCDE:'mov_s\tr0,0x1',0x24BCE4:'st_s\tr1,[r0,0]',
 0x24BD14:'mov_s\tr0,0x1',0x24BD1A:'mov_s\tr0,0x1',0x24BD20:'st_s\tr1,[r0,0x4]',
 0x24B2EA:'mov_s\tr1,0x10',0x24B2F0:'st_s\tr13,[r14,0]',
 0x24BB36:'mov_s\tr1,0x10',0x24BB3C:'st_s\tr13,[r14,0x4]',
 0x24A912:';0x24a998',0x2E3600:'not_s\tr14,r14',0x2E3602:'extw_s\tr14,r14',
 0x2E3608:'sth.di\tr0,[r13]'})
EDGES=[(0x24A75E,0x2E3498),(0x24A762,0x2E3820),(0x24A906,0x2E34B4),(0x24A90A,0x2E383C),
 (0x24A90E,0x2E35E4),(0x24A914,0x2E3610),(0x24A918,0x2E347C),
 (0x24B286,0x2E38D4),(0x24B28C,0x2E38A0),(0x24BAD2,0x2E3C14),(0x24BAD8,0x2E3BE0),
 (0x24BCD4,0x2E38D4),(0x24BCDA,0x2E38A0),(0x24BD10,0x2E3C14),(0x24BD16,0x2E3BE0),
 (0x24B2DC,0x2661D8),(0x24B2E6,0x2E3A24),(0x24B2F2,0x2E38D4),(0x24B2F8,0x2E38A0),
 (0x24BB28,0x2661D8),(0x24BB32,0x2E3D74),(0x24BB3E,0x2E3C14),(0x24BB44,0x2E3BE0)]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 for a,v in LITERALS.items():assert struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]==v,hex(a)
 tools=ROOT/'work/build-arc/binutils';listings=[]
 with tempfile.TemporaryDirectory(prefix='s33-stage-controls-') as td:
  elf,back=Path(td)/'0.elf',Path(td)/'0.bin'
  run([tools/'objcopy','-I','binary','-O','elf32-littlearc','-B','arc','--rename-section',
   '.data=.text,alloc,load,readonly,code,contents','--change-section-vma',
   f'.data={info[0]["load_address_candidate"]:#x}','--strip-all',bd/info[0]['file'],elf])
  run([tools/'objcopy','--dump-section',f'.text={back}',elf]);assert back.read_bytes()==ps[0]
  for a,b,label in WINDOWS:
   t=run([tools/'objdump','-d','-m','arc:ARC700','-EL',f'--start-address={a:#x}',f'--stop-address={b:#x}',elf])
   assert 'out of bounds' not in t.lower(),label
   listings.append('WINDOW '+label+'\n'+t.replace(str(elf),'verified-block0.elf'))
 listing='\n'.join(listings)
 def line(a):
  matches=[l for l in listing.splitlines() if re.match(rf'^\s*{a:x}:',l)]
  assert len(matches)==1,(hex(a),matches)
  return matches[0]
 for a,b in EDGES:assert f';0x{b:x}' in line(a),line(a)
 for a,n in CHECKS.items():assert n in line(a),line(a)
 # These are arithmetic consequences of the decoded calls, not a hardware model.
 assert ((~0x0000FFFF)&0xFFFF)==0
 out=ROOT/'Ghidra_Results/ghidra_reports/stage_control_transitions';out.mkdir(parents=True,exist_ok=True)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
 script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
 windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
 checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in EDGES],checked_instructions=len(CHECKS),
 checked_literals={hex(a):hex(v) for a,v in LITERALS.items()},control_map=CONTROL_MAP,
 observations=['Start800 clears bits1 and0 at0x0ffc4000 then sets bit0 at0x0ffc4004',
 'Start1000 clears bits1 and0 at0x0ffc3000 then sets bit0 at0x0ffc3004',
 'Corresponding handlers set bits1 and0 before publishing state3 and calling upper callback',
 'Teardown calls ID disable, clears local mask0x10 then sets control bits1 and0',
 'Start2000 toggles bits1/12 at0x0ffc2098, writes mask0 then sets bit0 at0x0ffc20b8 and0x0ffc2098'],
 limits=['No physical meaning assigned to control bits; clear/set are observed operations only',
 'Accessors have no local poll; untraced callees and hardware timing remain open',
 'Teardown skips state0 store if ID-disable call fails but continues control writes',
 'No proof of hardware quiescence, cache coherency, final buffer-use or runtime execution'])
 (out/'gnu_verified.txt').write_text(listing);(out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS:16 hashes, block0 roundtrip, {len(WINDOWS)} windows, {len(EDGES)} edges, {len(CHECKS)} instructions, {len(LITERALS)} pools, {len(CONTROL_MAP)} controls')
if __name__=='__main__':main()
