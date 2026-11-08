#!/usr/bin/env python3
"""Independently reconstruct FFB/FFC accesses from original code and call arguments."""
import argparse,json,re,struct
from pathlib import Path
from collections import defaultdict
from s33_run_gnu_arc700 import ROOT
from s33_audit_ff7_packed_tables import sha
from s33_verify_sensor_mmio_dialog import aligned_window

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);args=ap.parse_args();src=args.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FFB_PACKED_FFC'and d['capture_streams_separate'];assert all(sha(Path(p))==h for p,h in d['input_hashes'].items());assert all(sha(src/p)==h for p,h in d['files'].items());info=d['payload'];body=Path(info['path']).read_bytes();fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';original=fw.read_bytes();assert body==original[info['firmware_offset']:info['firmware_offset']+len(body)]and original.find(body)==info['firmware_offset']and original.find(body,info['firmware_offset']+1)<0
 inputs={str(p):sha(p)for p in[Path(__file__),Path(__file__).with_name('s33_audit_ff7_packed_tables.py'),src/'verified_evidence.json',fw,ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']};instructions={};operations={};roles=defaultdict(set)
 def decode(pc):
  if pc in instructions:return instructions[pc]
  listing=aligned_window(body,info['base'],pc,pc+8);m=next(re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)for line in listing.splitlines()if re.match(r'\s*'+f'{pc:x}'+':',line));raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert raw==body[pc-info['base']:pc-info['base']+len(raw)];instructions[pc]=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=info['firmware_offset']+pc-info['base']);return instructions[pc]
 def pool(pc):return struct.unpack_from('<I',body,pc-info['base'])[0]
 ffc_pairs={0x2e2d88,0x2e2dc4,0x2e2e00,0x2e2e3c,0x2e2e78,0x2e2eb4,0x2e2ef0,0x2e2f2c,0x2e2f68,0x2e30c8,0x2e30f0,0x2e3168,0x2e3190,0x2e3208,0x2e3230,0x2e32a8,0x2e32d0}
 ffc_singles={0x2e2db0,0x2e2dec,0x2e2e28,0x2e2e64,0x2e2ea0,0x2e2edc,0x2e2f18,0x2e2f54,0x2e2f90,0x2e3118,0x2e312c,0x2e3140,0x2e3154,0x2e31b8,0x2e31cc,0x2e31e0,0x2e31f4,0x2e3258,0x2e326c,0x2e3280,0x2e3294,0x2e32f8,0x2e330c,0x2e3320,0x2e3334}
 ffc_bits={0x2e2fa4,0x2e2fc0,0x2e2fdc,0x2e2ff8,0x2e3014,0x2e3030,0x2e304c,0x2e3068,0x2e3084,*range(0x2e3348,0x2e34d0,28)}
 ffb_direct={0x2e18ac,0x2e1928};ffb_pairs={0x2e18d4,0x2e1950};ffb_getters={0x2e18c0,0x2e193c,0x2e1900,0x2e1914,0x2e197c,0x2e1990};pack4={0x2e19a4,0x2e19d8,0x2e1a0c,0x2e1a40};unpack={0x2e1a74,0x2e1af4};ffc_reads=set(range(0x2e34d0,0x2e3548,20));checks=[];total=0;seen=set();all_addresses=set();group_events=defaultdict(int)
 for c in d['cases']:
  if not c['observer_enabled']:continue
  assert c['exit_code']==0 and c['fault']is None and c['full_original_calls_completed'];trace=src/(c['name']+'.trace');err=src/(c['name']+'.stderr.log');assert trace.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes();inputs[str(trace)]=sha(trace);inputs[str(err)]=sha(err)
  raw_events=[json.loads(line.removeprefix('S33_MEM '))for line in err.read_text().splitlines()if line.startswith('S33_MEM ')];events=[e for e in raw_events if e['stage']=='result'];assert len(raw_events)==2*len(events)and events==c['completed_memory_events']
  for begin,end in zip(raw_events[::2],raw_events[1::2]):assert begin['stage']=='begin'and end['stage']=='result'and all(begin[k]==end[k]for k in['id','operation','pc','address','width_bytes'])
  state={int(a,0):struct.unpack_from('<H',bytes.fromhex(f['before']),int(a,0)%8)[0]for a,f in c['fixtures'].items()};expected=[];buffer_expected={int(a):bytearray.fromhex(b['before'])for a,b in c['output_buffers'].items()}
  for call in c['original_calls']:
   entry=call['entry'];argv=call['arguments'];ev=[];ret=None;kind='';seen.add(entry)
   if entry in ffb_direct|ffc_singles:
    a=pool(entry+8);ev=[(entry+12,'write',a,argv[0]%65536)];kind='direct_argument_low16'
   elif entry in ffb_pairs:
    hi=pool(entry+16);lo=pool(entry+32);assert hi==lo+4;assert decode(entry+6)['operands']=='r0,r0,0x10'and decode(entry+6)['opcode']=='lsr_s';assert decode(entry+8)['opcode']=='bmsk_s'and decode(entry+8)['operands']=='r0,r0,0xc';ev=[(entry+20,'write',hi,argv[0]//65536%8192),(entry+36,'write',lo,argv[0]%65536)];kind='high13_then_low16'
   elif entry in ffc_pairs:
    lo=pool(entry+12);hi=pool(entry+28);assert hi==lo+4;assert decode(entry+8)['opcode']=='extw_s'and decode(entry+22)['opcode']=='lsr_s'and decode(entry+22)['operands']=='r13,r13,0x10';ev=[(entry+16,'write',lo,argv[0]%65536),(entry+32,'write',hi,argv[0]//65536)];kind='low16_then_high16'
   elif entry==0x2e1878:
    a=pool(0x2e18a0);assert a==0xffb8090
    for pc,operand in[(0x2e1880,'r13,r13'),(0x2e1886,'r2,r2,0x2'),(0x2e188c,'r3,r3,0x3'),(0x2e1892,'r1,r4,0x4')]:assert decode(pc)['opcode'].startswith('asl')and decode(pc)['operands']==operand
    value=0
    for i,x in enumerate(argv):value|=x*(2**i)
    ev=[(0x2e18a4,'write',a,value%65536)];kind='OR_five_arguments_shift0_1_2_3_4_then_low16'
   elif entry in pack4:
    a=pool(entry+20);b=pool(entry+40);assert b==a+4;assert decode(entry+6)['opcode']=='asl_s'and decode(entry+6)['operands']=='r1,r1,0x8';assert decode(entry+28)['opcode']=='asl'and decode(entry+28)['operands']=='r14,r16,0x8';ev=[(entry+24,'write',a,(argv[0]|(argv[1]*256))%65536),(entry+44,'write',b,(argv[2]|(argv[3]*256))%65536)];kind='OR_argument_pairs_shift8_then_low16'
   elif entry in unpack:
    addresses=[pool(entry+x)for x in[12,44,72,100]];assert addresses==[addresses[0]+4*i for i in range(4)];pcs=[16,24,48,56,76,84,104,112];ev=[(entry+pc,'read',addresses[i//2],state[addresses[i//2]])for i,pc in enumerate(pcs)];ptr=argv[0]-8;assert len(buffer_expected[ptr])==32;vals=[]
    for a in addresses:vals.extend([state[a]%256,state[a]//256])
    struct.pack_into('<8H',buffer_expected[ptr],8,*vals);kind='reread_each_halfword_for_low8_high8_to_eight_RAM_halfwords'
    for pc in[entry+20,entry+52,entry+80,entry+108]:assert decode(pc)['opcode']=='extb_s'
   elif entry in ffb_getters|{0x2e1ba8,0x2e1bc0,0x2e1bd8,0x2e1bf0,0x2e1c24,0x2e1c70}|ffc_reads:
    a=pool(entry+8);ev=[(entry+12,'read',a,state[a])];mask=255 if entry in{0x2e1ba8,0x2e1bc0,0x2e1bd8,0x2e1bf0}else 1 if entry==0x2e1c24 else 16383 if entry==0x2e1c70 else 65535;ret=state[a]&mask;kind=f'read16_return_low{mask.bit_length()}'
    if mask<65535:assert decode(entry+20)['opcode']==('extb_s'if mask==255 else'bmsk_s')
   elif entry in{0x2e1b74,0x2e1c3c}:
    a=pool(entry+16);bit=int(decode(entry+10)['operands'].split(',')[1],0);is_set=argv[0]!=0;off=20 if is_set else 36;old=state[a];new=(old|(1<<bit))if is_set else(old&~(1<<bit));assert decode(entry+off+4)['opcode']==('bset'if is_set else'bclr');ev=[(entry+off,'read',a,old),(entry+off+8,'write',a,new)];kind=f'RMW_bit{bit}_set_any_nonzero_else_clear'
   elif entry==0x2e1c08 or entry in ffc_bits:
    a=pool(entry+8);bit=int(decode(entry+4)['operands'].split(',')[1],0);op=decode(entry+16)['opcode'];assert op in['bset','bclr'];new=state[a]|(1<<bit)if op=='bset'else state[a]&~(1<<bit);ev=[(entry+12,'read',a,state[a]),(entry+20,'write',a,new)];kind=f'RMW_bit{bit}_{op}'
   else:
    assert entry==0x2e30a0;a=pool(entry+12);assert decode(entry+20)['opcode']=='and'and decode(entry+20)['operands']=='r0,r0,-16';assert decode(entry+24)['opcode']=='bmsk_s'and decode(entry+24)['operands']=='r14,r14,0x3';ev=[(entry+16,'read',a,state[a]),(entry+30,'write',a,(state[a]//16)*16+argv[0]%16)];kind='RMW_replace_low4_from_argument'
   assert call['expected_return']==ret
   addresses=sorted({a for _,_,a,_ in ev});operations[hex(entry)]=dict(entry=hex(entry),software_operation=kind,addresses=list(map(hex,addresses)),hardware_semantics='unknown')
   for _,op,a,value in ev:
    assert a in state and 0<=value<=65535;roles[a].add(kind);all_addresses.add(a)
    if op=='write':state[a]=value
   expected.extend(ev)
  assert[(e['pc'],e['operation'],e['address'],e['value'])for e in events]==expected;pcs={e['pc']for e in events};rows=[]
  for line in trace.read_text().splitlines():
   m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
   if m and int(m[1],16)in pcs:rows.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',int(m[3],16)&65535))
  assert rows==[(e['pc'],e['operation'],e['value'])for e in events]
  for e in events:assert e['width_bytes']==2 and decode(e['pc'])['opcode']==('ldh.di'if e['operation']=='read'else'sth.di')
  for key,f in c['fixtures'].items():
   a=int(key,0);before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes();assert len(after)==8 and struct.unpack_from('<H',after,a%8)[0]==state[a]and all(before[j]==after[j]for j in range(8)if j not in[a%8,a%8+1])
  for key,b in c['output_buffers'].items():assert(src/b['file']).read_bytes()==buffer_expected[int(key)]and bytes.fromhex(b['expected'])==buffer_expected[int(key)]
  group_events[c['group']]+=len(events);total+=len(events);checks.append(dict(case=c['name'],calls=len(c['original_calls']),events=len(events),RAM_buffers_verified=len(buffer_expected)))
 assert len(checks)==16 and total==1576 and dict(group_events)==dict(ffb=672,ffc=904)and len(all_addresses)==68 and len(seen)==98;assert len(d['pairs'])==16 and all(p['trace_identical']for p in d['pairs']);assert all(sha(Path(p))==h for p,h in inputs.items())
 result=dict(status='PASS_FFB_PACKED_FFC_AUDIT',date='2026-10-25',checks=checks,original_routine_entries=len(seen),completed_memory_events=total,group_events=dict(group_events),scalar_addresses=list(map(hex,sorted(all_addresses))),software_operations=operations,scalar_roles={hex(a):sorted(v)for a,v in roles.items()},instructions={hex(pc):v for pc,v in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=d['limits']);args.output.write_text(json.dumps(result,indent=2)+'\n');print(f'PASS: {len(checks)} scenarios/{total} events/{len(all_addresses)} addresses/{len(seen)} original entries')
if __name__=='__main__':main()
