#!/usr/bin/env python3
"""Audit FFC3000 formulas and FFB original-helper-to-stack-to-MMIO dataflow separately."""
import argparse,json,re,struct
from pathlib import Path
from collections import defaultdict,Counter
from s33_run_gnu_arc700 import ROOT
from s33_audit_ff7_packed_tables import sha
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_verify_custom_aux_cfg import call_at

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);args=ap.parse_args();src=args.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FFC3000_FFB_COMPUTED'and d['capture_streams_separate'];assert all(sha(Path(p))==h for p,h in d['input_hashes'].items())and all(sha(src/p)==h for p,h in d['files'].items());info=d['payload'];body=Path(info['path']).read_bytes();fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';original=fw.read_bytes();assert body==original[info['firmware_offset']:info['firmware_offset']+len(body)]and original.find(body)==info['firmware_offset']and original.find(body,info['firmware_offset']+1)<0
 inputs={str(p):sha(p)for p in[Path(__file__),Path(__file__).with_name('s33_audit_ff7_packed_tables.py'),Path(__file__).with_name('s33_verify_sensor_mmio_dialog.py'),Path(__file__).with_name('s33_verify_custom_aux_cfg.py'),src/'verified_evidence.json',fw,ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']};instructions={};operations={};roles=defaultdict(set)
 def decode(pc):
  if pc in instructions:return instructions[pc]
  listing=aligned_window(body,info['base'],pc,pc+8);m=next(re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)for line in listing.splitlines()if re.match(r'\s*'+f'{pc:x}'+':',line));raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert raw==body[pc-info['base']:pc-info['base']+len(raw)];instructions[pc]=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=info['firmware_offset']+pc-info['base']);return instructions[pc]
 def pool(pc):return struct.unpack_from('<I',body,pc-info['base'])[0]
 def imm(pc,op):
  x=decode(pc);assert x['opcode']==op;return int(x['operands'].split(',')[-1],0)
 branch_entries={0x2e3bac,0x2e3be0,0x2e3c14,0x2e3c48,0x2e3c7c,0x2e3cb0,0x2e3ce4,0x2e3d18,0x2e2c8c};splits={0x2e3dc4,0x2e3e38,0x2e3eac,0x2e3ed4,0x2e3f48,0x2e3f70};quads={0x2e3dec,0x2e3e60,0x2e3efc};reads={0x2e3d4c,0x2e3db0};checks=[];counts=Counter();seen=set();addresses=set();flags=defaultdict(set);computed_provenance=[];aux_records=[]
 for c in d['cases']:
  if not c['observer_enabled']:continue
  assert c['exit_code']==0 and c['fault']is None and c['full_original_calls_completed'];trace=src/(c['name']+'.trace');err=src/(c['name']+'.stderr.log');assert trace.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes();inputs[str(trace)]=sha(trace);inputs[str(err)]=sha(err);lines=trace.read_text().splitlines();raw=[json.loads(line.removeprefix('S33_MEM '))for line in err.read_text().splitlines()if line.startswith('S33_MEM ')];events=[e for e in raw if e['stage']=='result'];assert events==c['completed_memory_events']and len(raw)==2*len(events)
  for b,e in zip(raw[::2],raw[1::2]):assert b['stage']=='begin'and e['stage']=='result'and all(b[k]==e[k]for k in['id','pc','operation','address','width_bytes'])
  state={int(k,0):struct.unpack_from('<H',bytes.fromhex(f['before']),int(k,0)%8)[0]for k,f in c['fixtures'].items()};expected=[];loads={};helper_writes={};helper_entered=False
  for n,line in enumerate(lines):
   if line.startswith('0x303a40 '):helper_entered=True
   m=re.match(r'0x([0-9a-f]+)\s+(ldw(?:_s)?|ldb_s)\s+.*? - .*?<- (0x[0-9a-f]+)',line)
   if m:loads[int(m[1],16)]=(int(m[3],16),n)
   m=re.match(r'0x([0-9a-f]+)\s+stw(?:_s)?\s+[^,]+,\[r13,(0x[0-9a-f]+|\d+)\].*?memory <- (0x[0-9a-f]+)',line)
   if m and 0x303a40<=int(m[1],16)<0x303d60:
    pc=int(m[1],16);offset=int(m[2],0);assert decode(pc)['opcode']in['sth','stw_s'];helper_writes[offset]=dict(pc=pc,value=int(m[3],16)&65535,trace_line=n+1)
   m=re.match(r'0x([0-9a-f]+)\s+sr\s+.*?\[65\].*?<- (0x[0-9a-f]+)',line)
   if m:
    pc=int(m[1],16);assert pc==0x303ade and int(m[2],16)==0 and decode(pc)['opcode']=='sr';aux_records.append(dict(case=c['name'],pc=pc,index=65,value=0,trace_line=n+1))
  for call in c['original_calls']:
   entry=call['entry'];argv=call['arguments'];ev=[];ret=None;kind='';seen.add(entry)
   if entry in branch_entries:
    a=pool(entry+16);cmpval=imm(entry+4,'cmp_s');branch=decode(entry+6)['opcode'];assert branch in['beq.d','bne.d'];take_clear=(argv[0]==cmpval)if branch=='beq.d'else(argv[0]!=cmpval);bit=imm(entry+10,'mov_s');off=36 if take_clear else 20;value=state[a]&~(1<<bit)if take_clear else state[a]|1<<bit;ev=[(entry+off,'read',a,state[a]),(entry+off+8,'write',a,value)];flags[entry].add(argv[0]);kind=f'RMW_bit{bit}_set_iff_arg'+('!='if branch=='beq.d'else'==')+str(cmpval)
   elif entry in reads:
    a=pool(entry+8);ret=state[a];ev=[(entry+12,'read',a,ret)];kind='read16_return_full16'
   elif entry==0x2e3d60:
    a=pool(entry+8);ev=[(entry+12,'write',a,argv[0]%65536)];kind='argument_low16_full_store'
   elif entry==0x2e3d74:
    a=pool(entry+20);assert imm(entry+10,'cmp_s')==1 and decode(entry+16)['opcode']=='not_s';off=24 if argv[0]==1 else 42;store=34 if argv[0]==1 else 50;new=(state[a]|argv[1])if argv[0]==1 else(state[a]&~argv[1]);ev=[(entry+off,'read',a,state[a]),(entry+store,'write',a,new%65536)];kind='RMW_arg1_mask_set_iff_arg0_equals1_else_clear'
   elif entry in splits:
    lo=pool(entry+12);hi=pool(entry+28);assert hi==lo+4 and decode(entry+8)['opcode']=='extw_s'and decode(entry+22)['operands']=='r13,r13,0x10';ev=[(entry+16,'write',lo,argv[0]%65536),(entry+32,'write',hi,argv[0]//65536)];kind='argument0_low16_then_high16'
   elif entry in quads:
    aa=[pool(entry+x)for x in[16,32,48,64]];assert aa==[aa[0]+4*i for i in range(4)]and decode(entry+26)['operands']=='r14,r14,0x10'and decode(entry+58)['operands']=='r13,r13,0x10';vv=[argv[0]%65536,argv[0]//65536,argv[1]%65536,argv[1]//65536];ev=[(entry+20+16*i,'write',a,v)for i,(a,v)in enumerate(zip(aa,vv))];kind='argument0_low16_high16_then_argument1_low16_high16'
   elif entry==0x2e2918:
    aa=[pool(entry+20+16*i)for i in range(6)];assert aa==list(range(0xffb9f10,0xffb9f28,4));ev=[(entry+24+16*i,'write',a,(argv[i//2]//(65536**(i%2)))%65536)for i,a in enumerate(aa)];kind='three_arguments_each_low16_then_high16_six_stores'
   else:
    assert entry==0x2e29b4 and helper_entered and c['computed_value_oracle']=='original_CPU_stack_loads_not_independent_math';assert call_at(body,0x2e2a1e-info['base'],info['base'])['target']==0x303a40;assert decode(0x303a50)['operands']=='r13,r0';raw_input=(src/c['input_buffers'][str(argv[0])]['file']).read_bytes();assert len(raw_input)==21;fields=struct.unpack('<6H9B',raw_input);input_pcs=[0x2e29ba]+[0x2e29c2+6*i for i in range(5)]+[0x2e29e0+6*i for i in range(8)]+[0x2e2a10]
    for i,pc in enumerate(input_pcs):assert loads[pc][0]==fields[i]and decode(pc)['opcode']==('ldw_s'if i<6 else'ldb_s')
    provenance=[]
    for i in range(38):
     source_pc=0x2e2a24+16*i;store_pc=source_pc+12;a=pool(store_pc-4);ins=decode(source_pc);assert ins['opcode']=='ldh';m=re.fullmatch(r'r0,\[sp,(\d+)\]',ins['operands']);assert m;offset=int(m[1]);loaded,load_n=loads[source_pc];producer=helper_writes[offset];assert producer['trace_line']<load_n+1 and loaded==producer['value'];value=loaded&65535;ev.append((store_pc,'write',a,value));provenance.append(dict(source_pc=hex(source_pc),store_pc=hex(store_pc),address=hex(a),structure_offset=offset,helper_store_pc=hex(producer['pc']),value=value));assert c['computed_slots'][i]==dict(source_pc=source_pc,store_pc=store_pc,address=a)
    assert {int(p['address'],0)for p in provenance}==set(range(0xffb9f2c,0xffb9fc4,4));computed_provenance.append(dict(case=c['name'],input_fields=list(fields),outputs=provenance,mathematically_independent=False));kind='original303A40_helper_halfword_outputs_to_38_fixed_MMIO_cells_math_unverified'
   assert call['expected_return']==ret;operations[hex(entry)]=dict(entry=hex(entry),software_operation=kind,addresses=list(map(hex,sorted({a for _,_,a,_ in ev}))),hardware_semantics='unknown')
   for _,op,a,value in ev:
    assert a in state and 0<=value<=65535;roles[a].add(kind);addresses.add(a)
    if op=='write':state[a]=value
   expected.extend(ev)
  assert[(e['pc'],e['operation'],e['address'],e['value'])for e in events]==expected;pcs={e['pc']for e in events};rows=[]
  for line in lines:
   m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
   if m and int(m[1],16)in pcs:rows.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',int(m[3],16)&65535))
  assert rows==[(e['pc'],e['operation'],e['value'])for e in events]
  for e in events:assert e['width_bytes']==2 and decode(e['pc'])['opcode']==('ldh.di'if e['operation']=='read'else'sth.di');counts[c['group']+'_'+e['operation']]+=1
  for key,f in c['fixtures'].items():
   a=int(key,0);before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes();assert len(after)==8 and struct.unpack_from('<H',after,a%8)[0]==state[a]and all(before[j]==after[j]for j in range(8)if j not in[a%8,a%8+1])
  for b in c['input_buffers'].values():assert(src/b['file']).read_bytes()==bytes.fromhex(b['before'])
  checks.append(dict(case=c['name'],calls=len(c['original_calls']),events=len(events)))
 assert len(checks)==12 and sum(counts.values())==1288 and len(addresses)==73 and len(seen)==24 and len(computed_provenance)==4 and len(aux_records)==4;assert all(flags[e]=={0,1,2,3,0x80000000,0xffffffff}for e in branch_entries if e!=0x2e2c8c)and flags[0x2e2c8c]=={0,1,2,0xffffffff};assert len(d['pairs'])==12 and all(p['trace_identical']for p in d['pairs']);assert all(sha(Path(p))==h for p,h in inputs.items())
 result=dict(status='PASS_FFC3000_FFB_COMPUTED_AUDIT',date='2026-10-25',checks=checks,original_routine_entries=24,completed_memory_events=1288,operation_counts=dict(counts),scalar_addresses=list(map(hex,sorted(addresses))),software_operations=operations,scalar_roles={hex(a):sorted(v)for a,v in roles.items()},computed_output_provenance=computed_provenance,computed_math_verified=False,aux_records=aux_records,instructions={hex(pc):v for pc,v in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=d['limits']);args.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS24entries/12scenarios/1288events/73addresses;38computed slots traced,math explicitly unverified',dict(counts))
if __name__=='__main__':main()
