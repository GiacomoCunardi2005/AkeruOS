#!/usr/bin/env python3
"""Reconstruct FFC control behavior from original opcode operands, pools and CPU traces."""
import argparse,json,re,struct
from pathlib import Path
from collections import defaultdict,Counter
from s33_run_gnu_arc700 import ROOT
from s33_audit_ff7_packed_tables import sha
from s33_verify_sensor_mmio_dialog import aligned_window

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);args=ap.parse_args();src=args.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FFC_CONTROL_TAIL_4000'and d['capture_streams_separate'];assert all(sha(Path(p))==h for p,h in d['input_hashes'].items())and all(sha(src/p)==h for p,h in d['files'].items());info=d['payload'];body=Path(info['path']).read_bytes();fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';original=fw.read_bytes();assert body==original[info['firmware_offset']:info['firmware_offset']+len(body)]and original.find(body)==info['firmware_offset']and original.find(body,info['firmware_offset']+1)<0
 inputs={str(p):sha(p)for p in[Path(__file__),Path(__file__).with_name('s33_audit_ff7_packed_tables.py'),Path(__file__).with_name('s33_verify_sensor_mmio_dialog.py'),src/'verified_evidence.json',fw,ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']};instructions={};operations={};roles=defaultdict(set)
 def decode(pc):
  if pc in instructions:return instructions[pc]
  listing=aligned_window(body,info['base'],pc,pc+8);m=next(re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)for line in listing.splitlines()if re.match(r'\s*'+f'{pc:x}'+':',line));raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert raw==body[pc-info['base']:pc-info['base']+len(raw)];instructions[pc]=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=info['firmware_offset']+pc-info['base']);return instructions[pc]
 def pool(pc):return struct.unpack_from('<I',body,pc-info['base'])[0]
 def operand(pc,op):
  ins=decode(pc);assert ins['opcode']==op;return ins['operands']
 def immediate(pc,op):return int(operand(pc,op).split(',')[-1],0)
 rmw={0x2e3610,0x2e362c,0x2e3648,0x2e3664,0x2e3680,0x2e369c,0x2e36b8,0x2e36d4,0x2e36f0,0x2e3754,0x2e37b8,0x2e37d4,0x2e3820,0x2e383c};force_masks={0x2e370c,0x2e3730,0x2e3770,0x2e3794};eq1={0x2e38a0,0x2e38d4,0x2e3960,0x2e3994,0x2e39c8};lsb={0x2e3908,0x2e3934};splits={0x2e3a74,0x2e3ae8,0x2e3b5c,0x2e3b84};quads={0x2e3a9c,0x2e3b10};full_reads={0x2e35bc,0x2e39fc,0x2e3a60};bool_reads={0x2e355c,0x2e358c};shift_reads={0x2e3858,0x2e3870,0x2e3888};direct={0x2e3548,0x2e35d0,0x2e3a10};constant_writes={0x2e3578,0x2e35a8};checks=[];counts=Counter();seen=set();addresses=set();eq_flags=defaultdict(set);lsb_args=defaultdict(set);seed_values=set()
 for c in d['cases']:
  if not c['observer_enabled']:continue
  assert c['exit_code']==0 and c['fault']is None and c['full_original_calls_completed'];trace=src/(c['name']+'.trace');err=src/(c['name']+'.stderr.log');assert trace.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes();inputs[str(trace)]=sha(trace);inputs[str(err)]=sha(err);raw=[json.loads(line.removeprefix('S33_MEM '))for line in err.read_text().splitlines()if line.startswith('S33_MEM ')];events=[e for e in raw if e['stage']=='result'];assert events==c['completed_memory_events']and len(raw)==2*len(events)
  for b,e in zip(raw[::2],raw[1::2]):assert b['stage']=='begin'and e['stage']=='result'and all(b[k]==e[k]for k in['id','pc','operation','address','width_bytes'])
  state={int(k,0):struct.unpack_from('<H',bytes.fromhex(f['before']),int(k,0)%8)[0]for k,f in c['fixtures'].items()};seed_values.update(state.values());expected=[]
  for call in c['original_calls']:
   entry=call['entry'];argv=call['arguments'];ev=[];ret=None;kind='';seen.add(entry)
   if entry in direct|constant_writes:
    a=pool(entry+8);value=(immediate(entry+4,'mov_s')if entry in constant_writes else argv[0])%65536;ev=[(entry+12,'write',a,value)];kind='full16_constant_write_'+str(value)if entry in constant_writes else'argument_low16_full_store'
   elif entry in full_reads|bool_reads|shift_reads:
    a=pool(entry+8);ret=state[a]
    if entry in bool_reads:
     bit=immediate(entry+16,'btst_s');assert operand(entry+20,'mov.pnz')=='r0,0x1';ret=(ret>>bit)&1;kind=f'read16_return_boolean_bit{bit}'
    elif entry in shift_reads:
     bit=immediate(entry+16,'lsr_s');assert operand(entry+22,'bmsk_s')=='r0,r0,0';ret=(ret>>bit)&1;kind=f'read16_return_bit{bit}'
    else:kind='read16_return_full16'
    ev=[(entry+12,'read',a,state[a])]
   elif entry==0x2e35e4:
    a=pool(entry+12);assert operand(entry+20,'and')=='r0,r0,0xffff0000'and operand(entry+28,'not_s')=='r14,r14'and operand(entry+30,'extw_s')=='r14,r14'and operand(entry+32,'or_s')=='r0,r0,r14';ev=[(entry+16,'read',a,state[a]),(entry+36,'write',a,(65535-argv[0]%65536))];kind='read16_then_write_NOT_argument_low16_without_preserving_old_bits'
   elif entry in rmw:
    a=pool(entry+8);bit=immediate(entry+4,'mov_s');op=decode(entry+16)['opcode'];assert op in['bset','bclr'];value=state[a]|(1<<bit)if op=='bset'else state[a]&~(1<<bit);ev=[(entry+12,'read',a,state[a]),(entry+20,'write',a,value)];kind=f'RMW_bit{bit}_{op}'
   elif entry in force_masks:
    a=pool(entry+8);keep=immediate(entry+16,'and')&65535;mask=immediate(entry+20,'or');assert keep==65535-mask;ev=[(entry+12,'read',a,state[a]),(entry+26,'write',a,(state[a]&keep)|mask)];kind='RMW_force_mask_'+hex(mask)+'_to_ones_preserve_other_bits'
   elif entry in{0x2e37f0,0x2e3808}:
    a=pool(entry+12);assert operand(entry+4,'asl_s')=='r1,r1,0x8'and operand(entry+6,'or_s')=='r0,r0,r1';ev=[(entry+16,'write',a,(argv[0]|argv[1]*256)%65536)];kind='OR_arg0_arg1_shift8_truncate16_no_independent_field_masks'
   elif entry in eq1:
    a=pool(entry+16);assert operand(entry+4,'cmp_s')=='r0,0x1'and decode(entry+6)['opcode']=='bne.d';bit=immediate(entry+10,'mov_s');eq_flags[entry].add(argv[0]);offset=20 if argv[0]==1 else 36;value=(state[a]|(1<<bit))if argv[0]==1 else(state[a]&~(1<<bit));ev=[(entry+offset,'read',a,state[a]),(entry+offset+8,'write',a,value)];kind=f'RMW_bit{bit}_set_iff_argument_equals1_else_clear'
   elif entry in lsb:
    a=pool(entry+12);bit=immediate(entry+20,'bclr_s');assert immediate(entry+22,'asl')==bit and immediate(entry+26,'and')==1<<bit;lsb_args[entry].add(argv[0]);ev=[(entry+16,'read',a,state[a]),(entry+34,'write',a,(state[a]&~(1<<bit))|((argv[0]%2)<<bit))];kind=f'RMW_bit{bit}_replaced_from_argument_LSB'
   elif entry==0x2e3a24:
    a=pool(entry+20);assert operand(entry+10,'cmp_s')=='r0,0x1'and operand(entry+16,'not_s')=='r15,r1';eq_flags[entry].add(argv[0]);offset=24 if argv[0]==1 else 42;store=34 if argv[0]==1 else 50;value=(state[a]|argv[1])if argv[0]==1 else(state[a]&~argv[1]);ev=[(entry+offset,'read',a,state[a]),(entry+store,'write',a,value%65536)];kind='RMW_mask_arg1_set_iff_arg0_equals1_else_clear_low16'
   elif entry in splits:
    lo=pool(entry+12);hi=pool(entry+28);assert hi==lo+4 and operand(entry+8,'extw_s')=='r0,r0'and operand(entry+22,'lsr_s')=='r13,r13,0x10';ev=[(entry+16,'write',lo,argv[0]%65536),(entry+32,'write',hi,argv[0]//65536)];kind='argument0_low16_then_high16'
   else:
    assert entry in quads;aa=[pool(entry+x)for x in[16,32,48,64]];assert aa==[aa[0]+4*i for i in range(4)]and operand(entry+26,'lsr_s')=='r14,r14,0x10'and operand(entry+58,'lsr_s')=='r13,r13,0x10';vv=[argv[0]%65536,argv[0]//65536,argv[1]%65536,argv[1]//65536];ev=[(entry+20+16*i,'write',a,v)for i,(a,v)in enumerate(zip(aa,vv))];kind='argument0_low16_high16_then_argument1_low16_high16'
   assert call['expected_return']==ret;operations[hex(entry)]=dict(entry=hex(entry),software_operation=kind,addresses=list(map(hex,sorted({a for _,_,a,_ in ev}))),hardware_semantics='unknown')
   for _,op,a,value in ev:
    assert a in state and 0<=value<=65535;roles[a].add(kind);addresses.add(a)
    if op=='write':state[a]=value
   expected.extend(ev)
  assert [(e['pc'],e['operation'],e['address'],e['value'])for e in events]==expected;pcs={e['pc']for e in events};rows=[]
  for line in trace.read_text().splitlines():
   m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
   if m and int(m[1],16)in pcs:rows.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',int(m[3],16)&65535))
  assert rows==[(e['pc'],e['operation'],e['value'])for e in events]
  for e in events:assert e['width_bytes']==2 and decode(e['pc'])['opcode']==('ldh.di'if e['operation']=='read'else'sth.di');counts[e['operation']]+=1
  for key,f in c['fixtures'].items():
   a=int(key,0);before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes();assert len(after)==8 and struct.unpack_from('<H',after,a%8)[0]==state[a]and all(before[j]==after[j]for j in range(8)if j not in[a%8,a%8+1])
  checks.append(dict(case=c['name'],calls=len(c['original_calls']),events=len(events)))
 assert len(checks)==8 and sum(counts.values())==1128 and len(addresses)==27 and len(seen)==48;assert all(v=={0,1,2,0xffffffff}for v in eq_flags.values())and len(eq_flags)==6;assert all({0,1,2,3,0xffffffff}<=v for v in lsb_args.values())and len(lsb_args)==2;assert seed_values=={0,65535,64,128,256,448,0x55aa,0xa55a};assert len(d['pairs'])==8 and all(p['trace_identical']for p in d['pairs']);assert all(sha(Path(p))==h for p,h in inputs.items())
 result=dict(status='PASS_FFC_CONTROL_TAIL_4000_AUDIT',date='2026-10-25',checks=checks,original_routine_entries=48,completed_memory_events=1128,operation_counts=dict(counts),scalar_addresses=list(map(hex,sorted(addresses))),software_operations=operations,scalar_roles={hex(a):sorted(v)for a,v in roles.items()},instructions={hex(pc):v for pc,v in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=d['limits']);args.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS48entries/8scenarios/1128events/27addresses',dict(counts))
if __name__=='__main__':main()
