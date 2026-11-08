#!/usr/bin/env python3
"""Derive FFC7000 RMW masks and argument halves from original instructions independently."""
import argparse,hashlib,json,re,struct
from pathlib import Path
from s33_run_gnu_arc700 import ROOT
from s33_verify_sensor_mmio_dialog import aligned_window

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);a=ap.parse_args();src=a.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FFC7000_MASKED_FIELDS';assert all(sha(Path(k))==v for k,v in d['input_hashes'].items());assert all(sha(src/k)==v for k,v in d['files'].items());p=d['payload'];body=Path(p['path']).read_bytes();fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';assert body==fw.read_bytes()[p['firmware_offset']:p['firmware_offset']+p['size']]
 inputs={str(q):sha(q)for q in[Path(__file__),fw,src/'verified_evidence.json',ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']};instructions={}
 def decode(pc):
  if pc in instructions:return instructions[pc]
  text=aligned_window(body,p['base'],pc,pc+8);line=next(x for x in text.splitlines()if re.match(r'\s*'+f'{pc:x}'+':',x));m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line);raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert raw==body[pc-p['base']:pc-p['base']+len(raw)];i=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=p['firmware_offset']+pc-p['base']);instructions[pc]=i;return i
 def pool(pc):return struct.unpack_from('<I',body,pc-p['base'])[0]
 def operand(pc,op):
  x=decode(pc);assert x['opcode']==op;return int(x['operands'].split(',')[-1],0)
 def exact(pc,op,args):assert decode(pc)['opcode']==op and decode(pc)['operands']==args,(hex(pc),decode(pc))
 def field(entry,po,rd,wr,arg,shift,keep,mask_pc=None,subtract_pc=None):
  width=16 if mask_pc is None else operand(entry+mask_pc,'bmsk_s')+1;assert width in[12,13,16];mask=(1<<width)-1;keep=keep&65535;assert keep==(~mask&65535);sub=0
  if subtract_pc is not None:sub=operand(entry+subtract_pc,'sub_s');assert sub==1
  return dict(address=hex(pool(entry+po)),read_pc=hex(entry+rd)if rd is not None else None,write_pc=hex(entry+wr),argument=arg,logical_shift=shift,width_bits=width,keep_mask=hex(keep),subtract_before_mask=sub)
 functions={}
 e=0x308438;exact(e+6,'mov_s','r14,r0');exact(e+8,'mov_s','r15,r1');functions[e]=[field(e,0x10,0x14,0x2c,0,0,pool(e+0x28),0x1e,0x1c),field(e,0x34,0x38,0x50,1,0,pool(e+0x4c),0x42,0x40)]
 for e in[0x308490,0x308598,0x3086b4]:
  exact(e+6,'mov_s','r13,r0');exact(e+0x1c,'extw_s','r1,r13');exact(e+0x3c,'lsr_s','r13,r13,0x10');functions[e]=[field(e,0xc,0x10,0x22,0,0,operand(e+0x14,'and')),field(e,0x2c,0x30,0x44,0,16,operand(e+0x34,'and'),0x3e)]
 for e in[0x3084dc,0x3085e4,0x308700]:
  exact(e+6,'mov_s','r14,r0');functions[e]=[field(e,0xc,0x10,0x22,0,0,operand(e+0x14,'and'),0x1c)]
 for e in[0x308508,0x308610,0x30872c]:
  exact(e+6,'mov_s','r14,r0');exact(e+8,'mov_s','r13,r1');exact(e+0x1c,'extw_s','r0,r14');exact(e+0x40,'lsr_s','r14,r14,0x10');exact(e+0x5c,'extw_s','r0,r13');exact(e+0x80,'lsr_s','r13,r13,0x10')
  functions[e]=[field(e,0x10,0x14,0x28,0,0,pool(e+0x24)),field(e,0x30,0x34,0x48,0,16,operand(e+0x38,'and'),0x42),field(e,0x50,0x54,0x68,1,0,pool(e+0x64)),field(e,0x70,0x74,0x88,1,16,operand(e+0x78,'and'),0x82)]
 functions[0x3086a0]=[field(0x3086a0,8,None,12,0,0,0)]
 # Scalar identities and original code are re-bound here; do not import verifier fields as an oracle.
 expected_addresses={*range(0xffc7000,0xffc7040,4),0xffc7050,*range(0xffc7100,0xffc711c,4)};assert{int(f['address'],0)for ff in functions.values()for f in ff}==expected_addresses and len(expected_addresses)==24
 for e,fields in functions.items():
  for f in fields:
   assert decode(int(f['write_pc'],0))['opcode']=='sth.di'
   if f['read_pc']is not None:assert decode(int(f['read_pc'],0))['opcode']=='ldh.di'
 checks=[];total=0;read_count=0;write_count=0;aux_srs=[]
 for c in d['cases']:
  if not c['observer_enabled']:continue
  trace=src/(c['name']+'.trace');err=src/(c['name']+'.stderr.log');inputs[str(trace)]=sha(trace);inputs[str(err)]=sha(err);assert trace.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes();raw=[json.loads(line.removeprefix('S33_MEM '))for line in err.read_text().splitlines()if line.startswith('S33_MEM ')];events=c['completed_memory_events'];assert len(raw)==2*len(events)and[e for e in raw if e['stage']=='result']==events
  for begin,end in zip(raw[::2],raw[1::2]):assert begin['stage']=='begin'and end['stage']=='result'and all(begin[k]==end[k]for k in['id','pc','operation','address','width_bytes'])
  state={int(k,0):struct.unpack_from('<H',bytes.fromhex(v['before']),int(k,0)%8)[0]for k,v in c['fixtures'].items()};expected=[];entries=set()
  for call in c['original_calls']:
   e=int(call['entry'],0);argv=list(map(lambda x:int(x,0),call['arguments']));assert call['expected_return']is None;entries.add(e)
   for f in functions[e]:
    addr=int(f['address'],0);mask=(1<<f['width_bits'])-1;value=((argv[f['argument']]>>f['logical_shift'])-f['subtract_before_mask'])&mask
    if f['read_pc']is not None:expected.append((int(f['read_pc'],0),'read',addr,state[addr]));value|=state[addr]&int(f['keep_mask'],0)
    expected.append((int(f['write_pc'],0),'write',addr,value));state[addr]=value
  assert entries==set(functions)and[(e['pc'],e['operation'],e['address'],e['value'])for e in events]==expected
  pcs={e['pc']for e in events};traced=[]
  for line in trace.read_text().splitlines():
   m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
   if m and int(m[1],16)in pcs:traced.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',int(m[3],16)&65535))
   if re.match(r'0x[0-9a-f]+\s+sr\s+',line):aux_srs.append(line)
  assert traced==[(e['pc'],e['operation'],e['value'])for e in events]and all(e['width_bytes']==2 for e in events)
  for key,f in c['fixtures'].items():
   addr=int(key,0);before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes();offset=addr%8;assert len(after)==8 and struct.unpack_from('<H',after,offset)[0]==state[addr]and all(before[i]==after[i]for i in range(8)if i not in[offset,offset+1])
  assert c['exit_code']==0 and c['fault']is None and c['full_original_calls_completed'];total+=len(events);read_count+=sum(e['operation']=='read'for e in events);write_count+=sum(e['operation']=='write'for e in events);checks.append(dict(case=c['name'],calls=len(c['original_calls']),events=len(events)))
 assert len(checks)==8 and total==376 and read_count==184 and write_count==192 and not aux_srs and len(d['pairs'])==8 and all(p['trace_identical']for p in d['pairs']);assert all(sha(Path(k))==v for k,v in inputs.items())
 result=dict(status='PASS_FFC7000_FIELDS_INDEPENDENT_AUDIT',date='2026-10-25',checks=checks,original_routine_entries=11,scalar_addresses=list(map(hex,sorted(expected_addresses))),software_operations={hex(e):dict(entry=hex(e),fields=fields,hardware_semantics='unknown')for e,fields in functions.items()},completed_memory_events=376,reads=184,writes=192,original_calls_observed=88,new_aux_sr_sites=0,independently_redecoded_instructions={hex(pc):i for pc,i in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=d['limits']);a.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS11entries/8scenarios/376events/24addresses,12/13bit masks and subtract-one independently derived')
if __name__=='__main__':main()
