#!/usr/bin/env python3
"""Offline S33: three stage configurations, IRQ registrations, callback event bits."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[(0x266234,0x26627A,'Registrar6000'),(0x26627C,0x26628A,'DispatcherBinding'),
 (0x2662A0,0x266300,'Dispatcher6000BitsAndCallbacks'),(0x24A488,0x24A490,'Config2000InputBinding'),(0x24A562,0x24A56A,'Config2000StateBinding'),
 (0x24A6CC,0x24A6F0,'Start2000StateBinding'),(0x24B004,0x24B014,'Config800StateBinding'),
 (0x24B230,0x24B23C,'Start800StateBinding'),(0x24B7A0,0x24B7B0,'Config1000StateBinding'),
 (0x24BA5C,0x24BA68,'Start1000StateBinding'),(0x2442D4,0x2442E6,'Producer2000'),(0x24401E,0x24402A,'Producer800'),
 (0x2440C2,0x2440CC,'Producer1000'),(0x24A578,0x24A580,'Registration2000'),
 (0x24A5AE,0x24A5C2,'CopyConfigAndState1_2000'),(0x24A732,0x24A73A,'StartState2_2000'),
 (0x24A97C,0x24A996,'Handler2000'),(0x24B0E4,0x24B0EC,'Registration800'),
 (0x24B212,0x24B226,'CopyConfigCallbackAndState1_800'),(0x24B280,0x24B292,'StartState2_800'),
 (0x24B89E,0x24B8A6,'Registration1000'),(0x24BA42,0x24BA56,'CopyConfigCallbackAndState1_1000'),
 (0x24BACC,0x24BADE,'StartState2_1000'),(0x24BCB8,0x24BCF4,'Handler800'),
 (0x24BCF4,0x24BD30,'Handler1000'),(0x2444A0,0x2444AA,'Signal800'),
 (0x2444CC,0x2444E4,'Signal1000And2000'),
 (0x2E39FC,0x2E3A04,'Status800ReadPrologue'),(0x2E3A08,0x2E3A10,'Status800Read'),
 (0x2E3A60,0x2E3A68,'Mask800ReadPrologue'),(0x2E3A6C,0x2E3A74,'Mask800Read'),
 (0x2E3D4C,0x2E3D54,'Status1000ReadPrologue'),(0x2E3D58,0x2E3D60,'Status1000Read'),
 (0x2E3DB0,0x2E3DB8,'Mask1000ReadPrologue'),(0x2E3DBC,0x2E3DC4,'Mask1000Read'),
 (0x2E3578,0x2E3580,'Handler2000WritePrologue'),(0x2E3584,0x2E358C,'Handler2000Write')]
EDGES=[(0x24A57A,0x266234),(0x24A5B4,0x128C20),(0x24A97E,0x2E3578),
 (0x24B0E6,0x266234),(0x24B21A,0x128C20),(0x24B8A0,0x266234),(0x24BA4A,0x128C20),
 (0x24BCBC,0x2E39FC),(0x24BCC0,0x2E3A60),(0x24BCCE,0x2E3A10),
 (0x24BCF8,0x2E3D4C),(0x24BCFC,0x2E3DB0),(0x24BD0A,0x2E3D60),
 (0x2444A4,0x158CBC),(0x2444D2,0x158CBC),(0x2444DE,0x158CBC)]
CHECKS={0x266246:'asl_s\tr1,r1,0xd',0x266250:';0x26629c',
 0x266260:'add3\tr1,r2,r13',0x266264:'ldh.di\tr0,[r1,12]',0x26626C:'st.di\tr15,[r1,16]',
 0x266282:';0x26629c',0x2662A0:'ld.di\tr0,[r15,4]',0x2662B8:'ld.di\tr0,[r15]',
 0x2662AC:'ldb.di\tr1,[r14,15]',0x2662C0:'ldb.di\tr1,[r14,14]',
 0x2662CC:'ld.di\tr0,[r14,16]',0x2662D8:'jl_s\t[r0]',0x2662EA:'sth.di\tr0,[r2]',0x24A48E:'mov_s\tr14,r0',0x24A562:';0x24a8c8',0x24A6D2:';0x24a8c8',
 0x24B00A:';0x24b134',0x24B236:';0x24b29c',0x24B7A6:';0x24b900',0x24BA62:';0x24bae8',
 0x24A5BE:'mov_s\tr0,0x1',0x24B220:'mov_s\tr0,0x1',0x24BA50:'mov_s\tr0,0x1',
 0x24B280:'mov_s\tr0,0x2',0x24BACC:'mov_s\tr0,0x2',0x24A984:'mov_s\tr1,0x3',
 0x24BCE2:'mov_s\tr1,0x3',0x24BD1E:'mov_s\tr1,0x3',0x2442D8:';0x2444b4',0x2442DE:'st_s\tr1,[r0,0x48]',
 0x24401E:';0x244058',0x244020:'st_s\tr0,[r15,0x38]',
 0x2440C2:';0x2444ac',0x2440C4:'st_s\tr0,[r14,0x4c]',
 0x24A578:';0x24a8d0',0x24A57E:';0x24a8d4',
 0x24A5AE:';0x24a8d8',0x24A5B8:'mov_s\tr2,0x4c',0x24A5C0:'st_s\tr0,[r15,0]',
 0x24A732:'mov_s\tr0,0x2',0x24A738:'st_s\tr0,[r1,0]',
 0x24A982:';0x24a99c',0x24A986:'st_s\tr1,[r0,0]',
 0x24A988:';0x24a9a0',0x24A98A:'ld_s\tr0,[r0,0]',0x24A990:'jl_s\t[r0]',
 0x24B0E4:';0x24b158',0x24B0EA:';0x24b15c',
 0x24B212:'ld_s\tr0,[r14,0x38]',0x24B216:'st_s\tr0,[r15,0x8]',
 0x24B218:';0x24b298',0x24B21E:'mov_s\tr2,0x3c',0x24B222:'st_s\tr0,[r15,0]',
 0x24B282:'st_s\tr0,[r14,0]',0x24B89E:';0x24b924',0x24B8A4:';0x24b928',
 0x24BA42:'ld_s\tr0,[r13,0x4c]',0x24BA46:'st_s\tr0,[r14,0xc]',
 0x24BA48:';0x24bae4',0x24BA4E:'mov_s\tr2,0x50',0x24BA52:'st_s\tr0,[r14,0x4]',
 0x24BACE:'st_s\tr0,[r15,0x4]',0x24BCC4:'mov_s\tr13,r0',
 0x24BCC6:'btst_s\tr0,0x4',0x24BCCA:'btst_s\tr13,0x4',0x24BCE4:'st_s\tr1,[r0,0]',
 0x24BCE6:'ld_s\tr0,[r0,0x8]',0x24BCEC:'jl_s\t[r0]',
 0x24BD02:'btst_s\tr0,0x4',0x24BD06:'btst_s\tr13,0x4',0x24BD20:'st_s\tr1,[r0,0x4]',
 0x24BD22:'ld_s\tr0,[r0,0xc]',0x24BD28:'jl_s\t[r0]',
 0x2444A8:'bset_s\tr1,r1,0xb',0x2444D6:'bset_s\tr1,r1,0xc',0x2444E2:'bset_s\tr1,r1,0xd',
 0x2E3A08:'ldh.di\tr0,[r0]',0x2E3A6C:'ldh.di\tr0,[r0]',
 0x2E3D58:'ldh.di\tr0,[r0]',0x2E3DBC:'ldh.di\tr0,[r0]',0x2E3584:'sth.di\tr0,[r1]'}
LITERALS={0x26629C:0x424E00,0x244058:0x2444A0,0x2444AC:0x2444CC,0x2444B4:0x2444D8,0x2444C8:0x08200011,
 0x24A8C8:0x36ADC8,0x24A8D0:0x24A97C,0x24A8D4:0x600A,0x24A8D8:0x50C1F8,
 0x24A99C:0x36ADC8,0x24A9A0:0x50C240,0x24B134:0x36ADCC,0x24B158:0x24BCB8,
 0x24B15C:0x600C,0x24B298:0x50C254,0x24B29C:0x36ADCC,0x24B900:0x36ADCC,
 0x24B924:0x24BCF4,0x24B928:0x600B,0x24BAE4:0x50C290,0x24BAE8:0x36ADCC,
 0x24BD30:0x36ADCC,0x2E3A04:0x0FFC4008,0x2E3A68:0x0FFC400C,
 0x2E3D54:0x0FFC3008,0x2E3DB8:0x0FFC300C,0x2E3580:0x0FFC20B4}
CHAINS=[dict(mask='0x2000',producer='0x244234',input_offset=0x48,config_copy='0x50c1f8',
 callback_copy='0x50c240',callback_cell='0x50c240',callback='0x2444d8',state_cell='0x36adc8',
 initializer='0x24a488',start='0x24a6cc',handler='0x24a97c',registration_id='0x600a'),
 dict(mask='0x800',producer='0x243f48',input_offset=0x38,config_copy='0x50c254',
 callback_copy='0x50c28c',callback_cell='0x36add4',callback='0x2444a0',state_cell='0x36adcc',
 initializer='0x24b004',start='0x24b230',handler='0x24bcb8',registration_id='0x600c'),
 dict(mask='0x1000',producer='0x243f48',input_offset=0x4c,config_copy='0x50c290',
 callback_copy='0x50c2dc',callback_cell='0x36add8',callback='0x2444cc',state_cell='0x36add0',
 initializer='0x24b7a0',start='0x24ba5c',handler='0x24bcf4',registration_id='0x600b')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 def raw(a,n):
  for b in bs:
   off=a-b['load_address_candidate']
   if 0<=off<=len(ps[b['index']])-n:return ps[b['index']][off:off+n]
  raise ValueError(hex(a))
 table=raw(0x424E00,12+16*8)
 assert struct.unpack_from('<IIH',table)==(0x0FEF0228,0x0FEF022C,16)
 records=[]
 for i in range(16):
  event,status_bit,mask_bit,callback=struct.unpack_from('<HBBI',table,12+8*i)
  assert event==0x6010-i and status_bit==mask_bit==15-i and callback==0
  records.append(dict(index=i,id=hex(event),record=hex(0x424E0C+8*i),
   callback_cell=hex(0x424E10+8*i),status_bit=status_bit,mask_bit=mask_bit,initial_callback=callback))
 for chain in CHAINS:
  row=next(v for v in records if v['id']==chain['registration_id'])
  chain['registrar_callback_cell']=row['callback_cell'];chain['outer_status_mask']=hex(1<<row['status_bit'])
 for a,v in LITERALS.items():assert struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]==v,hex(a)
 tools=ROOT/'work/build-arc/binutils';listings=[]
 with tempfile.TemporaryDirectory(prefix='s33-stage-callbacks-') as td:
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
 for c in CHAINS:assert int(c['config_copy'],16)+c['input_offset']==int(c['callback_copy'],16)
 out=ROOT/'Ghidra_Results/ghidra_reports/stage_event_callbacks';out.mkdir(parents=True,exist_ok=True)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
 script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
 windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
 checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in EDGES],checked_instructions=len(CHECKS),
 checked_literals={hex(a):hex(v) for a,v in LITERALS.items()},stage_chains=CHAINS,registrar_table='0x424e00',registrar_records=records,
 outer_status_register='0x0fef0228',outer_mask_register='0x0fef022c',
 observations=['Three conditional config-to-callback chains resolved for bits0x800/1000/2000',
 'Each initializer publishes state1, start path state2, handler state3',
 '0x800/1000 handlers require bit4 in both status and mask halfword reads',
 'Registrar maps IDs600a/b/c to outer status and mask bits9/10/11; dispatcher invokes table callback',
 '0x2000 handler writes1 to0x0ffc20b4 then invokes configured callback if nonzero'],
 limits=['Registrar table and dispatcher are traced; actual runtime installation/execution is not observed',
 'No physical stage names or universal final-buffer-use claim',
 'Windows prove specific stores, calls and predicates; no complete initialization success/runtime mode proof'])
 (out/'gnu_verified.txt').write_text(listing);(out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS:16 hashes, block0 roundtrip, {len(WINDOWS)} windows, {len(EDGES)} edges, {len(CHECKS)} instructions, {len(LITERALS)} pools, 3 chains')
if __name__=='__main__':main()
