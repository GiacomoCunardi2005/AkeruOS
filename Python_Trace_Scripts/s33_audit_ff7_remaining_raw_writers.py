#!/usr/bin/env python3
"""Independently audit FF7 raw9/33/17 outputs and ordered tail stores."""
import argparse,hashlib,json,re,struct
from pathlib import Path
from s33_run_gnu_arc700 import ROOT
from s33_verify_sensor_mmio_dialog import aligned_window

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);a=ap.parse_args();src=a.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FF7_REMAINING_RAW_WRITERS'and d['capture_streams_separate'];assert all(sha(Path(k))==v for k,v in d['input_hashes'].items());assert all(sha(src/k)==v for k,v in d['files'].items());p=d['payload'];body=Path(p['path']).read_bytes();fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';assert body==fw.read_bytes()[p['firmware_offset']:p['firmware_offset']+p['size']]
 inputs={str(q):sha(q)for q in[Path(__file__),fw,src/'verified_evidence.json',ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']};instructions={}
 def decode(pc):
  if pc in instructions:return instructions[pc]
  text=aligned_window(body,p['base'],pc,pc+8);line=next(x for x in text.splitlines()if re.match(r'\s*'+f'{pc:x}'+':',x));m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line);raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert raw==body[pc-p['base']:pc-p['base']+len(raw)];i=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=p['firmware_offset']+pc-p['base']);instructions[pc]=i;return i
 defs={'raw9_tail':(0x2e10f0,0xff760d0,9,4),'raw33_b':(0x2e1298,0xff76128,33,0),'raw17_c':(0x2e12d8,0xff761ac,17,0)};specs={s['name']:s for s in d['specs']};assert set(specs)==set(defs)
 for name,(entry,base,n,delta)in defs.items():
  s=specs[name];assert(s['entry'],s['base'],s['count'],s['pc'])==(entry,base,n,entry+0x30+delta)
  for pc,op,args in[(entry+6,'mov',f'lp_count,{hex(n)}'),(entry+0x1a+delta,'asl_s','r0,r13,0x2'),(entry+0x1c+delta,'ldw_s','r1,[r14,0]'),(entry+0x1e+delta,'add_s','r0,r0,'+hex(base)),(entry+0x34+delta,'add_s','r14,r14,0x2'),(entry+0x36+delta,'add_s','r13,r13,0x1'),(entry+0x38+delta,'extw_s','r13,r13')]:assert decode(pc)['opcode']==op and decode(pc)['operands']==args,(hex(pc),decode(pc))
  assert struct.unpack_from('<II',body,entry+0x28+delta-p['base'])==(entry+0x3a+delta,entry+0x1a+delta)
 assert struct.unpack_from('<I',body,0x2e1134-p['base'])[0]==0xff760f4 and struct.unpack_from('<I',body,0x2e1144-p['base'])[0]==0xff760f8
 for pc,args in[(0x2e1138,'r15,[r0]'),(0x2e1148,'r0,[r1]')]:assert decode(pc)['opcode']=='sth.di'and decode(pc)['operands']==args
 checks=[];total=0;window_events=0;param_events=0;cells=set();scalars=set()
 for c in d['cases']:
  if not c['observer_enabled']:continue
  entry,base,n,delta=defs[c['spec_name']];s=specs[c['spec_name']];path=src/(c['name']+'.trace');err=src/(c['name']+'.stderr.log');inputs[str(path)]=sha(path);inputs[str(err)]=sha(err);raw=(src/c['input_file']).read_bytes();assert len(raw)==2*n;values=struct.unpack('<'+'H'*n,raw);p1,p2=map(lambda x:int(x,0),c['parameter_arguments']);expected=[(entry+0x30+delta,'write',base+4*i,v)for i,v in enumerate(values)]
  if delta:expected.extend([(0x2e1138,'write',0xff760f4,p1&65535),(0x2e1148,'write',0xff760f8,p2&65535)])
  events=c['completed_memory_events'];raw_events=[json.loads(x.removeprefix('S33_MEM '))for x in err.read_text().splitlines()if x.startswith('S33_MEM ')];assert len(raw_events)==2*len(events)and[e for e in raw_events if e['stage']=='result']==events;assert[(e['pc'],e['operation'],e['address'],e['value'])for e in events]==expected
  pcs={e['pc']for e in events};traced=[]
  for line in path.read_text().splitlines():
   m=re.match(r'0x([0-9a-f]+)\s+stw\.di.*? - .*?<- (0x[0-9a-f]+)',line)
   if m and int(m[1],16)in pcs:traced.append((int(m[1],16),int(m[2],16)&65535))
  assert traced==[(e['pc'],e['value'])for e in events];assert all(e['width_bytes']==2 and decode(e['pc'])['opcode']=='sth.di'for e in events);data=(src/c['window_file']).read_bytes();off=base%8;assert len(data)==off+4*n+8 and data[:off]==b'\xa5'*off and data[-8:]==b'\xa5'*8
  for i,v in enumerate(values):assert struct.unpack_from('<H',data,off+4*i)[0]==v and data[off+4*i+2:off+4*i+4]==b'\xa5\xa5'
  for address,argument in[(0xff760f4,p1),(0xff760f8,p2)]if delta else[]:
   fixture=c['fixtures'][hex(address)];before=bytes.fromhex(fixture['before']);after=(src/fixture['file']).read_bytes();offset=address%8;assert struct.unpack_from('<H',after,offset)[0]==argument&65535 and all(before[i]==after[i]for i in range(8)if i not in[offset,offset+1]);scalars.add(address)
  assert c['expected_r0_after_return']==hex(p2 if delta else base+4*(n-1));assert c['exit_code']==0 and c['fault']is None and c['full_original_writer_completed'];assert path.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes();total+=len(events);window_events+=n;param_events+=2 if delta else 0;cells.update(base+4*i for i in range(n));checks.append(dict(case=c['name'],window_events=n,tail_events=2 if delta else 0))
 assert len(checks)==12 and total==244 and window_events==236 and param_events==8 and len(cells)==59 and len(scalars)==2 and len(d['pairs'])==12 and all(p['trace_identical']for p in d['pairs'])
 windows=[dict(name=name,writer_entry=hex(entry),base=hex(base),element_count=n,stride_bytes=4,store_width_bits=16,input_element_bits=16,input_stride_bytes=2,store_pc=hex(entry+0x30+delta),last_cell_address=hex(base+4*(n-1)),value_contract='rawu16sequence;all16 input bits transferred',bulk_condition='always;parameter arguments do not skip transfer',physical_kind='unknown_register_array_or_memory_aperture',concrete_control_registers_admitted_from_window_cells=0,hardware_verified=False)for name,(entry,base,n,delta)in defs.items()]
 result=dict(status='PASS_FF7_REMAINING_RAW_WRITERS_INDEPENDENT_AUDIT',date='2026-10-25',checks=checks,transfer_windows=windows,scalar_addresses=list(map(hex,sorted(scalars))),window_cell_addresses_count=59,completed_memory_events=244,window_write_events=236,parameter_events=8,independently_redecoded_instructions={hex(pc):i for pc,i in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=d['limits']);assert all(sha(Path(k))==v for k,v in inputs.items());a.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS12scenarios/244events,3windows/59cells,2tail parameters;all12tracepairs identical')
if __name__=='__main__':main()
