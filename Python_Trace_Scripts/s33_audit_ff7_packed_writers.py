#!/usr/bin/env python3
"""Reconstruct packed values from raw buffers and original instruction bytes."""
import argparse,hashlib,json,re,struct
from pathlib import Path
from collections import defaultdict
from s33_run_gnu_arc700 import ROOT
from s33_verify_sensor_mmio_dialog import aligned_window

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);args=ap.parse_args();src=args.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FF7_PACKED_WRITER_CONTRACTS'and d['capture_streams_separate'];assert all(sha(Path(p))==h for p,h in d['input_hashes'].items());assert all(sha(src/p)==h for p,h in d['files'].items());info=d['payload'];fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';body=Path(info['path']).read_bytes();assert body==fw.read_bytes()[info['firmware_offset']:info['firmware_offset']+info['size']]
 inputs={str(p):sha(p)for p in[Path(__file__),fw,src/'verified_evidence.json',ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']};instructions={}
 def decode(pc):
  if pc in instructions:return instructions[pc]
  txt=aligned_window(body,info['base'],pc,pc+8);m=next(re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',s)for s in txt.splitlines()if re.match(r'\s*'+f'{pc:x}'+r':',s));raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert body[pc-info['base']:pc-info['base']+len(raw)]==raw;i=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=info['firmware_offset']+pc-info['base']);instructions[pc]=i;return i
 for pc,op,arg in[(0x2e0710,'bmsk_s','r2,r2,0x6'),(0x2e0712,'bmsk_s','r1,r1,0x6'),(0x2e0794,'bmsk_s','r2,r2,0x6'),(0x2e0796,'bmsk_s','r1,r1,0x6'),(0x2e089c,'ldb_s','r13,[r3,0x2]'),(0x2e0920,'ldb_s','r13,[r3,0x1]'),(0x2e08aa,'ldh','r0,[r0,64]'),(0x2e092e,'ldb','r0,[r0,32]'),(0x2e0756,'asl','r0,r16,0xa'),(0x2e075a,'or_s','r15,r15,r0')]:assert decode(pc)['opcode']==op and decode(pc)['operands']==arg
 specs={s['name']:s for s in d['specs']};expected_windows={'packed7_a':(0xff74044,17),'packed7_b':(0xff7408c,17),'paired8_a':(0xff740f0,17),'paired8_b':(0xff7413c,17),'paired8_c':(0xff74188,17),'raw12':(0xff7600c,12),'raw17':(0xff76044,17)};checks=[];total=0;table_events=0;params=0;cells=set();scalar=set();actual_by_case={}
 for c in d['cases']:
  if not c['observer_enabled']:continue
  s=specs[c['spec_name']];assert(s['base'],s['count'])==expected_windows[s['window']];events=c['completed_memory_events'];path=src/(c['name']+'.trace');err=src/(c['name']+'.stderr.log');inputs[str(path)]=sha(path);inputs[str(err)]=sha(err);raw_events=[json.loads(line.removeprefix('S33_MEM '))for line in err.read_text().splitlines()if line.startswith('S33_MEM ')];assert len(raw_events)==2*len(events)and[e for e in raw_events if e['stage']=='result']==events;pcs={e['pc']for e in events};rows=[]
  for line in path.read_text().splitlines():
   m=re.match(r'0x([0-9a-f]+)\s+stw\.di.*? - .*?<- (0x[0-9a-f]+)',line)
   if m and int(m[1],16)in pcs:rows.append((int(m[1],16),int(m[2],16)&65535))
  assert len(rows)==len(events)
  for row,e in zip(rows,events):assert row==(e['pc'],e['value'])and e['operation']=='write'and e['width_bytes']==2 and decode(e['pc'])['opcode']=='sth.di'
  raw=(src/c['input_file']).read_bytes();kind=s['kind']
  if kind=='raw16':packed=list(struct.unpack('<'+'H'*s['count'],raw))
  elif kind.endswith('wide'):
   vals=struct.unpack('<33H',raw);mask=127 if kind=='pair7_wide'else 255;packed=[(vals[2*i]&mask)|((vals[2*i+1]&mask)<<8)for i in range(16)]+[vals[32]]
  else:assert kind=='pair8_compact'and len(raw)==33;packed=[raw[2*i]|(raw[2*i+1]<<8)for i in range(16)]+[raw[32]]
  bulk=[e for e in events if e['pc']==s['pc']];assert[(e['address'],e['value'])for e in bulk]==[(s['base']+4*i,v)for i,v in enumerate(packed)]
  p1,p2=[int(v,0)for v in c['parameter_arguments']];pv=[((p1<<10)|p2)&65535]if kind=='pair7_wide'else[p1&65535,p2&65535]if s['name']=='raw12'else[]if s['name']=='raw17'else[p2&65535,p1&65535];pr=[e for e in events if e['pc']!=s['pc']];assert[(e['address'],e['value'])for e in pr]==list(zip(s['param_addresses'],pv))
  data=(src/c['window_file']).read_bytes();off=s['base']%8;assert c['window_data_offset']==off and len(data)==off+4*s['count']+8 and data[:off]==b'\xa5'*off and data[-8:]==b'\xa5'*8
  for i,v in enumerate(packed):assert struct.unpack_from('<H',data,off+4*i)[0]==v and data[off+4*i+2:off+4*i+4]==b'\xa5\xa5'
  assert c['exit_code']==0 and c['full_original_writer_completed']and path.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes();total+=len(events);table_events+=len(bulk);params+=len(pr);cells.update(e['address']for e in bulk);scalar.update(e['address']for e in pr);actual_by_case[(s['name'],c['input_pattern'])]=events;checks.append(dict(case=c['name'],kind=kind,window=s['window'],window_events=len(bulk),parameter_events=len(pr),mapper_file_data_offset=off))
 ignored=0
 for s in d['specs']:
  if s['kind'].endswith('wide'):
   a=actual_by_case[(s['name'],0)];b=actual_by_case[(s['name'],1)];assert[(e['address'],e['value'])for e in a]==[(e['address'],e['value'])for e in b];ignored+=1
 for letter in['a','b','c']:
  wide=actual_by_case[('paired8_'+letter+'_wide',0)];compact=actual_by_case[('paired8_'+letter+'_compact',0)];assert[(e['address'],e['value'])for e in wide[:16]]==[(e['address'],e['value'])for e in compact[:16]];assert wide[16]['value']==0xbeef and compact[16]['value']==0xef
 assert len(checks)==25 and total==455 and table_events==415 and params==40 and len(cells)==114 and len(scalar)==10 and ignored==5 and len(d['pairs'])==25 and all(p['trace_identical']for p in d['pairs'])
 windows=[]
 for name,(base,count)in expected_windows.items():
  ss=[s for s in d['specs']if s['window']==name];windows.append(dict(name=name,writer_entry=hex(ss[0]['entry']),writer_entries=[hex(s['entry'])for s in ss],base=hex(base),element_count=count,stride_bytes=4,store_width_bits=16,last_cell_address=hex(base+4*(count-1)),physical_kind='unknown_register_array_or_memory_aperture',bulk_condition='always; r1/r2 are parameter data, not a bulk skip flag',concrete_control_registers_admitted_from_window_cells=0,hardware_verified=False,value_contracts=[dict(entry=hex(s['entry']),input_kind=s['kind'],rule='cells0..15:two low7bits separated by8bit positions;cell16:rawu16tail'if s['kind']=='pair7_wide'else'cells0..15:two low8bits;cell16:rawu16tail'if s['kind']=='pair8_wide'else'cells0..15:adjacent byte pair;cell16:u8tail'if s['kind']=='pair8_compact'else'rawu16sequence')for s in ss]))
 result=dict(status='PASS_FF7_PACKED_BUFFER_BYTE_TRACE_AUDIT',date='2026-10-25',checks=checks,transfer_windows=windows,scalar_addresses=list(map(hex,sorted(scalar))),window_cell_offsets=114,completed_memory_events=455,window_write_events=415,scalar_events=40,ignored_input_bits_equivalences=5,wide_compact_distinct_tail_contracts=3,independently_redecoded_instructions={hex(pc):i for pc,i in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=['Packed rules apply to first16cells only; cell16 tail width differs between wide and compact input variants.','Mapper file prefix base%8 is a host mmap requirement, not a hardware address offset.','r1<<10 OR r2 parameter is not two independent masked fields; r2 high bits are not cleared before OR.'])
 assert all(sha(Path(p))==h for p,h in inputs.items());args.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS7windows/114cells,10parameter addresses,455events,25pairs;8 metamorphic checks')
if __name__=='__main__':main()
