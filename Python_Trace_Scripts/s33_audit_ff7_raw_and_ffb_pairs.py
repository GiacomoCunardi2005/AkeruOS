#!/usr/bin/env python3
"""Audit raw FF7 source buffers and FFB split writes/whole-halfword reads."""
import argparse,json,re,struct
from pathlib import Path
from s33_run_gnu_arc700 import ROOT
from s33_audit_ff7_packed_tables import sha
from s33_verify_sensor_mmio_dialog import aligned_window

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);args=ap.parse_args();src=args.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FF7_RAW_AND_FFB_PAIRS'and d['capture_streams_separate'];assert all(sha(Path(p))==h for p,h in d['input_hashes'].items());assert all(sha(src/p)==h for p,h in d['files'].items())
 info=d['payload'];body=Path(info['path']).read_bytes();fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';assert body==fw.read_bytes()[info['firmware_offset']:info['firmware_offset']+len(body)];inputs={str(p):sha(p)for p in[Path(__file__),Path(__file__).with_name('s33_audit_ff7_packed_tables.py'),src/'verified_evidence.json',fw,ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']};instructions={}
 def decode(pc):
  if pc in instructions:return instructions[pc]
  text=aligned_window(body,info['base'],pc,pc+8);m=next(re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)for line in text.splitlines()if re.match(r'\s*'+f'{pc:x}'+':',line));raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert raw==body[pc-info['base']:pc-info['base']+len(raw)];instructions[pc]=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=info['firmware_offset']+pc-info['base']);return instructions[pc]
 tables=[(0x2e0bd0,0xff7600c,12,0x2e0c04),(0x2e0c30,0xff76044,17,0x2e0c60),(0x2e0f30,0xff741dc,33,0x2e0f60),(0x2e0f70,0xff74044,33,0x2e0fa0),(0x2e0fb0,0xff74260,9,0x2e0fe0),(0x2e0ff0,0xff74284,9,0x2e1020)];table_map={e:(a,n,pc)for e,a,n,pc in tables}
 single=[(0x2e14bc,0x2e14e4,0xffb8000),(0x2e14d0,0x2e14f8,0xffb8004),(0x2e1560,0x2e1574,0xffb8028),(0x2e1684,0x2e1698,0xffb8048),(0x2e17a8,0x2e17bc,0xffb8068)];split=[(0x2e150c,0xffb8020),(0x2e1588,0xffb802c),(0x2e15dc,0xffb8034),(0x2e1630,0xffb8040),(0x2e16ac,0xffb804c),(0x2e1700,0xffb8054),(0x2e1754,0xffb8060),(0x2e17d0,0xffb806c),(0x2e1824,0xffb8074)];singles={e:a for e,_,a in single};splits=dict(split);getters={g:a for _,g,a in single};getters.update({e+44:a for e,a in split});getters.update({e+64:a+4 for e,a in split})
 assert d['ffb_singles']==list(map(list,single))and d['ffb_pairs']==list(map(list,split))
 for entry,a,n,pc in tables:
  s=next(s for s in d['tables']if s['entry']==entry);assert(s['base'],s['count'],s['store_pc'])==(a,n,pc);count=decode(entry+6);assert count['opcode']=='mov'and count['operands'].split(',')[0]=='lp_count'and int(count['operands'].split(',')[1],0)==n;assert decode(pc-18)['operands']=='r0,r0,'+hex(a)
 for entry,a in split:
  assert decode(entry+6)['opcode']=='lsr_s'and decode(entry+6)['operands']=='r0,r0,0x10';assert decode(entry+8)['opcode']=='bmsk_s'and decode(entry+8)['operands']=='r0,r0,0xc'
  for pc,target in[(entry+16,a+4),(entry+32,a)]:assert struct.unpack_from('<I',body,pc-info['base'])[0]==target
 checks=[];window_addresses=set();scalar_addresses=set();total=0;window_events=0;scalar_events=0
 for c in d['cases']:
  if not c['observer_enabled']:continue
  assert c['exit_code']==0 and c['fault']is None and c['full_original_calls_completed'];trace=src/(c['name']+'.trace');err=src/(c['name']+'.stderr.log');assert trace.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes();inputs[str(trace)]=sha(trace);inputs[str(err)]=sha(err)
  raw_events=[json.loads(line.removeprefix('S33_MEM '))for line in err.read_text().splitlines()if line.startswith('S33_MEM ')];events=[e for e in raw_events if e['stage']=='result'];assert len(raw_events)==2*len(events)and events==c['completed_memory_events'];state={int(a,0):struct.unpack_from('<H',bytes.fromhex(f['before']),int(a,0)%8)[0]for a,f in c['fixtures'].items()};expected=[]
  for call in c['original_calls']:
   entry=call['entry'];args_=call['arguments'];ret=None
   if entry in table_map:
    a,n,pc=table_map[entry];raw=(src/c['input_buffers'][str(args_[0])]['file']).read_bytes();assert len(raw)==2*n;ev=[(pc,'write',a+4*i,int.from_bytes(raw[2*i:2*i+2],'little'))for i in range(n)];window_addresses.update(a+4*i for i in range(n));window_events+=n
    if entry==0x2e0bd0:ev.extend([(0x2e0c18,'write',0xff7603c,args_[1]%65536),(0x2e0c28,'write',0xff76040,args_[2]%65536)]);scalar_addresses.update([0xff7603c,0xff76040]);scalar_events+=2
   elif entry in singles:ev=[(entry+12,'write',singles[entry],args_[0]%65536)];scalar_addresses.add(singles[entry]);scalar_events+=1
   elif entry in splits:
    a=splits[entry];ev=[(entry+20,'write',a+4,(args_[0]//65536)%8192),(entry+36,'write',a,args_[0]%65536)];scalar_addresses.update([a,a+4]);scalar_events+=2
   else:
    assert entry in getters;a=getters[entry];ret=state[a];ev=[(entry+12,'read',a,ret)];scalar_addresses.add(a);scalar_events+=1
   assert call['expected_return']==ret
   for _,op,a,v in ev:
    if op=='write':state[a]=v
   expected.extend(ev)
  assert[(e['pc'],e['operation'],e['address'],e['value'])for e in events]==expected;pcs={e['pc']for e in events};rows=[]
  for line in trace.read_text().splitlines():
   m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
   if m and int(m[1],16)in pcs:rows.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',int(m[3],16)&65535))
  assert rows==[(e['pc'],e['operation'],e['value'])for e in events]
  for e in events:assert e['width_bytes']==2 and decode(e['pc'])['opcode']==('ldh.di'if e['operation']=='read'else'sth.di')
  for a,f in c['fixtures'].items():
   a=int(a,0);before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes();assert struct.unpack_from('<H',after,a%8)[0]==state[a]and all(before[j]==after[j]for j in range(8)if j not in[a%8,a%8+1])
  for b in c['input_buffers'].values():assert(src/b['file']).read_bytes()==bytes.fromhex(b['bytes'])
  total+=len(events);checks.append(dict(case=c['name'],events=len(events)))
 assert len(checks)==32 and total==1012 and len(window_addresses)==113 and len(scalar_addresses)==25 and window_events==452 and scalar_events==560;assert len(d['pairs'])==32 and all(p['trace_identical']for p in d['pairs'])
 windows=[dict(name='ff7_raw_'+hex(e)[2:],base=hex(a),element_count=n,stride_bytes=4,store_width_bits=16,input_element_bits=16,writer_entry=hex(e),store_pc=hex(pc),last_cell_address=hex(a+4*(n-1)),physical_kind='unknown_register_array_or_memory_aperture',concrete_control_registers_admitted_from_window_cells=0,hardware_verified=False)for e,a,n,pc in tables]
 result=dict(status='PASS_FF7_RAW_FFB_AUDIT',date='2026-10-25',checks=checks,transfer_windows=windows,scalar_addresses=list(map(hex,sorted(scalar_addresses))),window_cell_addresses_count=113,completed_memory_events=1012,window_write_events=452,scalar_events=560,instructions={hex(p):i for p,i in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=d['limits']);assert all(sha(Path(p))==h for p,h in inputs.items());args.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS32scenarios/1012events,6raw windows/113cells,25scalar addresses')
if __name__=='__main__':main()
