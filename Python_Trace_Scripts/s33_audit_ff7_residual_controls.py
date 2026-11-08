#!/usr/bin/env python3
"""Reconstruct residual FF7 scalar formulas from source bytes and fixture arguments."""
import argparse,hashlib,json,re,struct
from pathlib import Path
from collections import defaultdict
from s33_run_gnu_arc700 import ROOT
from s33_verify_sensor_mmio_dialog import aligned_window

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);a=ap.parse_args();src=a.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FF7_RESIDUAL_SCALAR_CONTROLS';assert all(sha(Path(k))==v for k,v in d['input_hashes'].items());assert all(sha(src/k)==v for k,v in d['files'].items());p=d['payload'];body=Path(p['path']).read_bytes();fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';assert body==fw.read_bytes()[p['firmware_offset']:p['firmware_offset']+p['size']]
 inputs={str(q):sha(q)for q in[Path(__file__),fw,src/'verified_evidence.json',ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']};instructions={}
 def decode(pc):
  if pc in instructions:return instructions[pc]
  text=aligned_window(body,p['base'],pc,pc+8);line=next(x for x in text.splitlines()if re.match(r'\s*'+f'{pc:x}'+':',x));m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line);raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert raw==body[pc-p['base']:pc-p['base']+len(raw)];result=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=p['firmware_offset']+pc-p['base']);instructions[pc]=result;return result
 def pool(pc):return struct.unpack_from('<I',body,pc-p['base'])[0]
 def imm(pc,op):
  x=decode(pc);assert x['opcode']==op;return int(x['operands'].split(',')[-1],0)
 branches={0x2e050c,0x2e0b9c,0x2e0c70,0x2e0db4,0x2e0e2c,0x2e0e60,0x2e0e94,0x2e0ec8,0x2e0efc};singles={0x2e0d64,0x2e0d78,0x2e0d8c,0x2e0da0};splits={0x2e11d0,0x2e11f8,0x2e1220,0x2e1248,0x2e1270};unconditional={0x2e1150,0x2e116c,0x2e1188};checks=[];operations={};roles=defaultdict(set);flags=defaultdict(set);addresses=set();total=0;aux_srs=[]
 for c in d['cases']:
  if not c['observer_enabled']:continue
  trace=src/(c['name']+'.trace');err=src/(c['name']+'.stderr.log');inputs[str(trace)]=sha(trace);inputs[str(err)]=sha(err);assert trace.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes();events=c['completed_memory_events'];raw=[json.loads(x.removeprefix('S33_MEM '))for x in err.read_text().splitlines()if x.startswith('S33_MEM ')];assert len(raw)==2*len(events)and[e for e in raw if e['stage']=='result']==events
  for begin,end in zip(raw[::2],raw[1::2]):assert begin['stage']=='begin'and end['stage']=='result'and all(begin[k]==end[k]for k in['id','pc','operation','address','width_bytes'])
  state={int(k,0):struct.unpack_from('<H',bytes.fromhex(v['before']),int(k,0)%8)[0]for k,v in c['fixtures'].items()};expected=[]
  for call in c['original_calls']:
   entry=int(call['entry'],0);argv=list(map(lambda x:int(x,0),call['arguments']));ret=None;ev=[]
   if entry in branches:
    addr=pool(entry+16);cmp=imm(entry+4,'cmp_s');branch=decode(entry+6)['opcode'];assert branch in['beq.d','bne.d'];clear=argv[0]==cmp if branch=='beq.d'else argv[0]!=cmp;bit=imm(entry+10,'mov_s');off=36 if clear else 20;value=(state[addr]&~(1<<bit))if clear else(state[addr]|1<<bit);ev=[(entry+off,'read',addr,state[addr]),(entry+off+8,'write',addr,value)];kind=f'RMW_bit{bit}_set_iff_arg'+('!='if branch=='beq.d'else'==')+str(cmp);flags[entry].add(argv[0])
   elif entry==0x2e0de8:
    addr=pool(entry+8);assert imm(entry+16,'lsr_s')==5 and imm(entry+22,'bmsk_s')==0;ret=(state[addr]>>5)&1;ev=[(entry+12,'read',addr,state[addr])];kind='read_bit5_normalized_0_or1'
   elif entry==0x2e0e00:
    addr=pool(entry+8);mask=imm(entry+20,'and');assert mask==0x20 and decode(entry+18)['opcode']=='j_s.d';ret=state[addr]&mask;ev=[(entry+12,'read',addr,state[addr])];kind='read_mask0x20_return0_or32_not_boolean'
   elif entry==0x2e0e18:
    addr=pool(entry+8);value=imm(entry+4,'mov_s');assert value==0x20;ev=[(entry+12,'write',addr,value)];kind='unconditional_store16_constant0x20_argument_ignored'
   elif entry in singles:
    addr=pool(entry+8);ev=[(entry+12,'write',addr,argv[0]&65535)];kind='store_argument0_low16'
   elif entry==0x2e1030:
    aa=[pool(entry+12),pool(entry+24)];ev=[(entry+16,'write',aa[0],argv[0]&65535),(entry+28,'write',aa[1],argv[1]&65535)];kind='store_argument0_low16_then_argument1_low16'
   elif entry in unconditional:
    addr=pool(entry+8);bit=imm(entry+4,'mov_s');op=decode(entry+16)['opcode'];assert op in['bset','bclr'];value=state[addr]|1<<bit if op=='bset'else state[addr]&~(1<<bit);ev=[(entry+12,'read',addr,state[addr]),(entry+20,'write',addr,value)];kind=f'unconditional_RMW_{op}_bit{bit}_argument_ignored'
   elif entry==0x2e11a4:
    addr=pool(entry+12);keep=imm(entry+20,'and')&65535;replace=imm(entry+26,'and');assert keep==0xff03 and replace==0xfc;value=(state[addr]&keep)|(argv[0]&replace);ev=[(entry+16,'read',addr,state[addr]),(entry+34,'write',addr,value)];kind='replace_bits2_to7_with_rawarg_and0xFC_preserve_low2_high8'
   else:
    assert entry in splits;lo,hi=pool(entry+12),pool(entry+28);assert hi==lo+4 and decode(entry+8)['opcode']=='extw_s'and decode(entry+22)['opcode']=='lsr_s'and decode(entry+22)['operands']=='r13,r13,0x10';ev=[(entry+16,'write',lo,argv[0]&65535),(entry+32,'write',hi,argv[0]>>16)];kind='argument0_low16_then_logical_high16_two_ordered_stores'
   assert call['expected_return']==(hex(ret)if ret is not None else None);operations[hex(entry)]=dict(entry=hex(entry),software_operation=kind,addresses=list(map(hex,sorted({addr for _,_,addr,_ in ev}))),hardware_semantics='unknown')
   for _,op,addr,value in ev:
    assert addr in state and 0<=value<=65535;addresses.add(addr);roles[addr].add(kind)
    if op=='write':state[addr]=value
   expected.extend(ev)
  assert[(e['pc'],e['operation'],e['address'],e['value'])for e in events]==expected;pcs={e['pc']for e in events};observed=[]
  for line in trace.read_text().splitlines():
   m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
   if m and int(m[1],16)in pcs:observed.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',int(m[3],16)&65535))
   if re.match(r'0x[0-9a-f]+\s+sr\s+',line):aux_srs.append(line)
  assert observed==[(e['pc'],e['operation'],e['value'])for e in events]
  for e in events:assert e['width_bytes']==2 and decode(e['pc'])['opcode']==('ldh.di'if e['operation']=='read'else'sth.di')
  for k,f in c['fixtures'].items():
   addr=int(k,0);before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes();offset=addr%8;assert len(after)==8 and struct.unpack_from('<H',after,offset)[0]==state[addr]and all(before[i]==after[i]for i in range(8)if i not in[offset,offset+1])
  assert c['exit_code']==0 and c['fault']is None and c['full_original_calls_completed'];total+=len(events);checks.append(dict(case=c['name'],calls=len(c['original_calls']),events=len(events)))
 assert len(checks)==8 and total==1216 and len(addresses)==23 and len(operations)==26 and not aux_srs;assert all(flags[e]=={0,1,2,3,0x80000000,0xffffffff}for e in branches);assert len(d['pairs'])==8 and all(p['trace_identical']for p in d['pairs']);assert all(sha(Path(k))==v for k,v in inputs.items())
 result=dict(status='PASS_FF7_RESIDUAL_CONTROLS_INDEPENDENT_AUDIT',date='2026-10-25',checks=checks,original_routine_entries=26,completed_memory_events=total,original_calls_observed=sum(c['calls']for c in checks),scalar_addresses=list(map(hex,sorted(addresses))),software_operations=operations,scalar_roles={hex(k):sorted(v)for k,v in roles.items()},new_aux_sr_sites=0,independently_redecoded_instructions={hex(pc):i for pc,i in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=d['limits']);a.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS26entries/8scenarios/1216events/23addresses,masked returns and unconditional bits independently audited')
if __name__=='__main__':main()
