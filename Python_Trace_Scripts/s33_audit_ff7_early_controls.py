#!/usr/bin/env python3
"""Audit FF7 software masks, split stores and special small packing layouts."""
import argparse,hashlib,json,re,struct
from pathlib import Path
from s33_run_gnu_arc700 import ROOT
from s33_verify_sensor_mmio_dialog import aligned_window

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);args=ap.parse_args();src=args.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FF7_EARLY_CONTROLS_SPLITS_AND_SMALL_WINDOWS';assert all(sha(Path(p))==h for p,h in d['input_hashes'].items());assert all(sha(src/p)==h for p,h in d['files'].items());info=d['payload'];fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';body=Path(info['path']).read_bytes();assert body==fw.read_bytes()[info['firmware_offset']:info['firmware_offset']+info['size']]
 inputs={str(p):sha(p)for p in[Path(__file__),fw,src/'verified_evidence.json',ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']};instructions={}
 def decode(pc):
  if pc in instructions:return instructions[pc]
  text=aligned_window(body,info['base'],pc,pc+8);m=next(re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',s)for s in text.splitlines()if re.match(r'\s*'+f'{pc:x}'+r':',s));raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert body[pc-info['base']:pc-info['base']+len(raw)]==raw;i=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=info['firmware_offset']+pc-info['base']);instructions[pc]=i;return i
 for pc,op,arg in[(0x2e00d8,'and','r0,r0,-4'),(0x2e0100,'and','r0,r0,-13'),(0x2e0144,'and','r0,r0,-49'),(0x2e0174,'and','r0,r0,-16'),(0x2e011a,'asl_s','r1,r1,0x8'),(0x2e019a,'asl_s','r1,r1,0x4'),(0x2e01d8,'asl_s','r2,r1,0x4'),(0x2e02d4,'ldb_s','r0,[r0,0x8]'),(0x2e02d6,'bmsk_s','r2,r2,0x2')]:assert decode(pc)['opcode']==op and decode(pc)['operands']==arg
 singles={int(x['entry'],0):int(x['address'],0)for x in d['single_halfword_entries']};splits={int(x['entry'],0):(int(x['low_address'],0),int(x['high_address'],0))for x in d['split_argument_entries']}
 for e,a in singles.items():assert struct.unpack_from('<I',body,e+8-info['base'])[0]==a and decode(e+12)['opcode']=='sth.di'
 for e,(lo,hi)in splits.items():assert struct.unpack_from('<I',body,e+12-info['base'])[0]==lo and struct.unpack_from('<I',body,e+28-info['base'])[0]==hi and decode(e+22)['opcode']=='lsr_s'
 windows={s['name']:s for s in d['small_windows']};checks=[];events_total=0;scalar_events=0;window_events=0;scalars=set();cells=set();by_scenario={}
 for c in d['cases']:
  if not c['observer_enabled']:continue
  ev=c['completed_memory_events'];path=src/(c['name']+'.trace');err=src/(c['name']+'.stderr.log');inputs[str(path)]=sha(path);inputs[str(err)]=sha(err);raw_events=[json.loads(s.removeprefix('S33_MEM '))for s in err.read_text().splitlines()if s.startswith('S33_MEM ')];assert len(raw_events)==2*len(ev)and[e for e in raw_events if e['stage']=='result']==ev;pcs={e['pc']for e in ev};rows=[]
  for line in path.read_text().splitlines():
   m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
   if m and int(m[1],16)in pcs:rows.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',int(m[3],16)&65535))
  assert len(rows)==len(ev)
  for row,e in zip(rows,ev):assert row==(e['pc'],e['operation'],e['value'])and e['width_bytes']==2 and decode(e['pc'])['opcode']==('ldh.di'if e['operation']=='read'else'sth.di')
  if c['window_name']:
   w=windows[c['window_name']];raw=(src/c['input_file']).read_bytes()
   if w['name']=='nibble15':
    assert len(raw)==30;values=struct.unpack('<15H',raw);packed=[sum((values[i]&15)<<(4*(i+1))for i in range(3))]+[sum((values[3+4*j+k]&15)<<(4*k)for k in range(4))for j in range(3)];assert packed[0]&15==0
   else:
    assert len(raw)==9;arg=int(c['original_calls'][0]['arguments'][1],0);packed=[raw[0]|(raw[2]<<8),raw[4]|(raw[6]<<8),raw[8]|((arg&7)<<8)];assert packed[2]&0xf800==0
   assert[(e['address'],e['value'])for e in ev]==[(w['base']+4*i,v)for i,v in enumerate(packed)];data=(src/c['window_file']).read_bytes();off=w['base']%8;assert len(data)==off+4*w['count']+8 and data[:off]==b'\xa5'*off and data[-8:]==b'\xa5'*8
   for i,v in enumerate(packed):assert struct.unpack_from('<H',data,off+4*i)[0]==v and data[off+4*i+2:off+4*i+4]==b'\xa5\xa5'
   cells.update(e['address']for e in ev);window_events+=len(ev)
  else:
   state={int(a,0):struct.unpack_from('<H',bytes.fromhex(f['before']),int(a,0)%8)[0]for a,f in c['fixtures'].items()};calculated=[]
   def put(a,v):calculated.append(('write',a,v&65535));state[a]=v&65535
   def modify(a,v):calculated.append(('read',a,state[a]));put(a,v)
   for call in c['original_calls']:
    entry=int(call['entry'],0);v=list(map(lambda x:int(x,0),call['arguments']));x=v[0]
    if entry in singles:put(singles[entry],x)
    elif entry in splits:lo,hi=splits[entry];put(lo,x&65535);put(hi,x>>16)
    elif entry==0x2e0040:modify(0xff70800,state[0xff70800]|1)
    elif entry in[0x2e005c,0x2e0090,0x2e0258]:
     a={0x2e005c:0xff70838,0x2e0090:0xff70844,0x2e0258:0xff71000}[entry];modify(a,state[a]|1 if x==1 else state[a]&~1)
    elif entry in[0x2e00c4,0x2e00ec,0x2e0130]:
     a,mask,shift={0x2e00c4:(0xff70c00,3,0),0x2e00ec:(0xff70c00,12,2),0x2e0130:(0xff70c64,0x30,4)}[entry];modify(a,(state[a]&~mask)|((x<<shift)&mask))
    elif entry==0x2e015c:modify(0xff70c64,(state[0xff70c64]&~15)|(x&15));put(0xff70cc4,v[1])
    elif entry==0x2e0118:put(0xff70c60,x|(v[1]<<8))
    elif entry==0x2e0194:put(0xff70cc8,x|(v[1]<<4));put(0xff70ccc,v[2]|(v[3]<<8))
    else:assert entry==0x2e028c;put(0xff71004,x);put(0xff71008,v[1])
   assert[(e['operation'],e['address'],e['value'])for e in ev]==calculated;scalars.update(e['address']for e in ev);scalar_events+=len(ev)
  assert c['exit_code']==0 and c['full_original_paths_completed']and path.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes();by_scenario[c['scenario']]=[(e['address'],e['value'])for e in ev];events_total+=len(ev);checks.append(dict(case=c['name'],window_name=c['window_name'],events=len(ev),native_calls=len(c['original_calls'])))
 assert by_scenario['nibble15_0']==by_scenario['nibble15_1']and by_scenario['sparse5_0']==by_scenario['sparse5_1']==by_scenario['sparse5_2'];assert len(checks)==11 and events_total==331 and scalar_events==304 and window_events==27 and len(scalars)==37 and len(cells)==7 and len(d['pairs'])==11 and all(p['trace_identical']for p in d['pairs'])
 manifest=[]
 for w in d['small_windows']:manifest.append(dict(name=w['name'],writer_entry=hex(w['entry']),base=hex(w['base']),element_count=w['count'],stride_bytes=4,store_width_bits=16,last_cell_address=hex(w['base']+4*(w['count']-1)),physical_kind='unknown_register_array_or_memory_aperture',bulk_condition='always',concrete_control_registers_admitted_from_window_cells=0,hardware_verified=False,value_contract='cell0:nibbles input0..2 in bits4/8/12;cells1..3:four low-nibbles from input3..14'if w['name']=='nibble15'else'cell0=byte0|byte2<<8;cell1=byte4|byte6<<8;cell2=byte8|((r1&7)<<8)'))
 result=dict(status='PASS_FF7_EARLY_FIELDS_SPLITS_BUFFER_TRACE_AUDIT',date='2026-10-25',checks=checks,transfer_windows=manifest,scalar_addresses=list(map(hex,sorted(scalars))),window_cell_offsets=7,completed_memory_events=331,scalar_events=304,window_write_events=27,split_argument_functions=9,single_low16_functions=7,metamorphic_equivalences=3,independently_redecoded_instructions={hex(pc):i for pc,i in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=['Two ordered halfword writes do not prove atomic physical32bit registers.','OR-packed argument formulas have overlap because operands are not separately masked.','Nibble and sparse-byte window layouts are software contracts, not physical peripheral identities.'])
 assert all(sha(Path(p))==h for p,h in inputs.items());args.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS37scalar addresses,2windows/7cells,331events,11pairs;split order and packing audited')
if __name__=='__main__':main()
