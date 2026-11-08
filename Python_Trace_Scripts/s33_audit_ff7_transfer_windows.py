#!/usr/bin/env python3
"""Audit bounded FF7 apertures against original bytes, buffers and clean event streams."""
import argparse,hashlib,json,re,struct
from pathlib import Path
from s33_run_gnu_arc700 import ROOT
from s33_verify_sensor_mmio_dialog import aligned_window

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);args=ap.parse_args();src=args.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FF7_BOUNDED_TRANSFER_WINDOWS'and d['capture_streams_separate']
 assert all(sha(Path(p))==h for p,h in d['input_hashes'].items());assert all(sha(src/p)==h for p,h in d['files'].items());info=d['payload'];fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';body=Path(info['path']).read_bytes();assert body==fw.read_bytes()[info['firmware_offset']:info['firmware_offset']+info['size']]
 inputs={str(p):sha(p)for p in[Path(__file__),fw,src/'verified_evidence.json',ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']};instructions={}
 def decode(pc):
  if pc in instructions:return instructions[pc]
  text=aligned_window(body,info['base'],pc,pc+8);m=next(re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',s)for s in text.splitlines()if re.match(r'\s*'+f'{pc:x}'+r':',s));raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert body[pc-info['base']:pc-info['base']+len(raw)]==raw
  i=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=info['firmware_offset']+pc-info['base']);instructions[pc]=i;return i
 for pool,value in[(0x2e0550,0xff74000),(0x2e0cb4,0xff76098),(0x2e1064,0xff760cc),(0x2e1098,0xff760cc),(0x2e10cc,0xff760cc)]:assert struct.unpack_from('<I',body,pool-info['base'])[0]==value
 definitions=[('halfword_a',0x2e0574,0xff72000,1024,16,0x2e058a,0x2e05a0),('halfword_b',0x2e0cd8,0xff73000,1024,16,0x2e0cee,0x2e0d04),('byte_a',0x2e1318,0xff78000,256,8,0x2e132e,0x2e1344),('byte_b',0x2e13a4,0xff79000,256,8,0x2e13ba,0x2e13d0),('byte_c',0x2e1430,0xff7a000,256,8,0x2e1446,0x2e145c)];specs={s['name']:s for s in d['specs']};windows=[]
 for name,entry,base,n,bits,count_pc,base_pc in definitions:
  s=specs[name];assert(s['entry'],s['base'],s['count'],s['input_bits'])==(entry,base,n,bits)
  assert decode(count_pc)['opcode']=='mov'and decode(count_pc)['operands']=='lp_count,'+str(n)
  assert decode(base_pc)['opcode']=='add_s'and decode(base_pc)['operands']=='r0,r0,'+hex(base)
  assert decode(s['store_pc'])['opcode']=='sth.di'
  windows.append(dict(name=name,writer_entry=hex(entry),store_pc=hex(s['store_pc']),base=hex(base),element_count=n,stride_bytes=4,store_width_bits=16,input_element_bits=bits,last_cell_address=hex(base+4*(n-1)),observed_cell_addresses=n,physical_kind='unknown_register_array_or_memory_aperture',bulk_condition='r1==0',parameter_only_path='r1!=0 skips bulk/control_RMW and writes3 parameters',concrete_control_registers_admitted_from_window_cells=0,hardware_verified=False))
 checks=[];scalar_seen=set();window_seen=set();total=0;scalar_events=0;bulk_events=0
 for c in d['cases']:
  if not c['observer_enabled']:continue
  s=specs[c['spec_name']];events=c['completed_memory_events'];path=src/(c['name']+'.trace');err=src/(c['name']+'.stderr.log');inputs[str(path)]=sha(path);inputs[str(err)]=sha(err)
  raw_events=[json.loads(line.removeprefix('S33_MEM '))for line in err.read_text().splitlines()if line.startswith('S33_MEM ')];assert len(raw_events)==2*len(events)and[e for e in raw_events if e['stage']=='result']==events
  pcs={e['pc']for e in events};rows=[]
  for line in path.read_text().splitlines():
   m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
   if m and int(m[1],16)in pcs:rows.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',int(m[3],16)&65535))
  assert len(rows)==len(events)
  for row,e in zip(rows,events):
   assert row==(e['pc'],e['operation'],e['value'])and e['width_bytes']==2;assert decode(e['pc'])['opcode']==('ldh.di'if e['operation']=='read'else'sth.di');total+=1
   if e['pc']==s['store_pc']:window_seen.add(e['address']);bulk_events+=1
   else:scalar_seen.add(e['address']);scalar_events+=1
  inp=(src/c['input_file']).read_bytes();bits=s['input_bits'];values=list(struct.unpack('<'+('H'if bits==16 else'B')*(s['count']+3),inp));writes=[e for e in events if e['pc']==s['store_pc']]
  expected=[]if c['parameters_only']else[(s['base']+4*i,v)for i,v in enumerate(values[:s['count']])];assert[(e['address'],e['value'])for e in writes]==expected
  tails=[e for e in events if e['pc']in s['tail_pcs']];assert[(e['address'],e['value'])for e in tails]==list(zip(s['tails'],values[-3:]));assert len(events)==(3 if c['parameters_only']else s['count']+7)
  actual=(src/c['window_file']).read_bytes();assert len(actual)==4*s['count']+8
  for i in range(s['count']):
   assert actual[4*i+2:4*i+4]==b'\xa5\xa5';assert struct.unpack_from('<H',actual,4*i)[0]==(0xa5a5 if c['parameters_only']else values[i])
  assert actual[-8:]==b'\xa5'*8 and c['exit_code']==0 and c['full_original_writer_completed'];assert path.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes()
  checks.append(dict(case=c['name'],window=s['name'],parameters_only=c['parameters_only'],events=len(events),window_writes=len(writes),parameters_written=3))
 assert len(checks)==20 and len(scalar_seen)==18 and len(window_seen)==2816 and total==5732 and scalar_events==100 and bulk_events==5632;assert len(d['pairs'])==20 and all(p['trace_identical']for p in d['pairs'])
 result=dict(status='PASS_FF7_TRANSFER_WINDOW_BYTES_BUFFER_TRACE_AUDIT',date='2026-10-25',checks=checks,transfer_windows=windows,scalar_addresses=list(map(hex,sorted(scalar_seen))),window_cell_addresses_count=2816,completed_memory_events=5732,scalar_events=100,window_write_events=5632,independently_redecoded_instructions={hex(pc):i for pc,i in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=['Bounded cell-write apertures, scalar parameters and physical control registers remain distinct categories.','Stride4 plus halfword writes does not establish32bit register width; model gaps do not prove reserved hardware.','Capture stdout/stderr separately to avoid diagnostic/profile output interleaving with JSON events.'])
 assert all(sha(Path(p))==h for p,h in inputs.items());args.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS5 windows/2816cells separately,18scalar addresses,5732events,20identical pairs')
if __name__=='__main__':main()
