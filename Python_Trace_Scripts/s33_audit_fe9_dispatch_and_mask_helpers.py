#!/usr/bin/env python3
"""Audit bounded FE9 selectors separately from sampled, unbound generic MMIO helpers."""
import argparse,json,re,struct,hashlib
from pathlib import Path
from collections import Counter
from s33_run_gnu_arc700 import ROOT
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_verify_custom_aux_cfg import call_at
from s33_trace_state_dispatch import verified_payloads

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);args=ap.parse_args();src=args.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FE9_SELECTORS_UNBOUND_MASK_HELPERS'and d['capture_streams_separate'];assert all(sha(Path(k))==v for k,v in d['input_hashes'].items())and all(sha(src/k)==v for k,v in d['files'].items());p=d['payload'];body=Path(p['path']).read_bytes();fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';assert body==fw.read_bytes()[p['firmware_offset']:p['firmware_offset']+p['size']];inputs={str(q):sha(q)for q in[Path(__file__),Path(__file__).with_name('s33_verify_sensor_mmio_dialog.py'),Path(__file__).with_name('s33_verify_custom_aux_cfg.py'),Path(__file__).with_name('s33_trace_state_dispatch.py'),fw,src/'verified_evidence.json',src/'caller_census.json',ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']};instructions={}
 def decode(pc):
  if pc in instructions:return instructions[pc]
  text=aligned_window(body,p['base'],pc,pc+12);line=next(x for x in text.splitlines()if re.match(r'\s*'+f'{pc:x}'+':',x));m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line);raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert raw==body[pc-p['base']:pc-p['base']+len(raw)];instructions[pc]=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=p['firmware_offset']+pc-p['base']);return instructions[pc]
 def exact(pc,op,argv):assert decode(pc)['opcode']==op and decode(pc)['operands']==argv,(hex(pc),decode(pc))
 def imm(pc,op):
  x=decode(pc);assert x['opcode']==op;return int(x['operands'].split(',')[-1],0)
 def pool(pc):return struct.unpack_from('<I',body,pc-p['base'])[0]
 def target(pc):
  independent=call_at(body,pc-p['base'],p['base']);x=decode(pc);assert x['opcode'].split('.')[0]in['bl','bl_s'];assert independent and int(re.search(r';(?:0x)?([0-9a-f]+)',x['operands'])[1],16)==independent['target'];return independent['target']
 def lsb16(mask):
  for bit in range(16):
   if (mask>>bit)&1:return bit
  return 15
 families=[dict(first=0x30989c,masked=[0x3098b8,0x309918,0x309944,0x309970,0x30999c,0x3099e4],flag=0x3098e4,split=0x3099c8,get=0x309a10),dict(first=0x309ab4,masked=[0x309ad0,0x309b30,0x309b5c,0x309b88,0x309bb4,0x309be0],flag=0x309afc,split=0x309c0c,get=0x309c28)];firsts={f['first']for f in families};masked={x:f for f in families for x in f['masked']};flaggers={f['flag']:f for f in families};splits={f['split']for f in families};getters={f['get']:f for f in families};dispatch={};tables={}
 for f in families:
  e=f['first'];exact(e,'mov_s','r1,0');assert imm(e+8,'cmp_s')==16 and imm(e+20,'mov_s')==15;exact(e+12,'btst','r0,r1');exact(e+24,'mov_s','r0,r1')
  for entry in f['masked']:
   exact(entry+12,'ldh.di','r0,[r14]');exact(entry+16,'bic','r2,r0,r13');assert target(entry+20)==e;exact(entry+24,'extw_s','r0,r13');exact(entry+26,'asl_s','r15,r15,r0');exact(entry+28,'and_s','r13,r13,r15');exact(entry+30,'or_s','r2,r2,r13');exact(entry+32,'extw_s','r2,r2');exact(entry+34,'sth.di','r2,[r14]')
  entry=f['flag'];assert imm(entry+4,'cmp_s')==0 and decode(entry+6)['opcode']=='bne.d';exact(entry+10,'extw_s','r0,r2');assert target(entry+12)==e and target(entry+32)==e;exact(entry+20,'bclr','r10,r10,r0');exact(entry+40,'bset','r10,r10,r0')
  entry=f['split'];exact(entry+16,'add_s','r14,r14,0x4');exact(entry+18,'lsr_s','r13,r13,0x10');exact(entry+12,'sth.di','r0,[r14]');exact(entry+20,'sth.di','r13,[r14]')
  entry=f['get'];assert target(entry+14)==e;exact(entry+10,'and','r2,r0,r13');exact(entry+20,'asr_s','r2,r2,r0');exact(entry+26,'extw_s','r0,r2')
 assert body[0x30989c-p['base']:0x3098b8-p['base']]==body[0x309ab4-p['base']:0x309ad0-p['base']]
 for entry in[0x309a2c,0x309c44]:
  assert imm(entry+8,'cmp_s')==3 and decode(entry+10)['opcode']=='bhi.d';exact(entry+20,'ldh.as.x','r1,[r12,r1]');exact(entry+26,'j_s','[r12]');table_pc=entry+28;table=struct.unpack_from('<4h',body,table_pc-p['base']);assert table==(4,41,20,32);aa=pool(entry+40);bb=pool(entry+72);assert pool(entry+96)==bb and pool(entry+116)==aa and pool(entry+132)==0x55aa;width=imm(entry+52,'bmsk_s')+1;mask=(1<<width)-1;assert (~imm(entry+48,'and'))&65535==mask and imm(entry+84,'bmsk_s')+1==width and ((~imm(entry+80,'and'))&65535)==mask;exact(entry+108,'bic_s','r0,r0,r13');dispatch[entry]=(aa,bb,mask);tables[hex(entry)]=dict(address=hex(table_pc),signed_halfwords=list(table),targets=list(map(hex,[table_pc+2*x for x in table])),low_field_width=width,pool_addresses=[hex(aa),hex(bb)],invalid_return='0x55aa')
 assert dispatch=={0x309a2c:(0xfe9013c,0xfe90140,1023),0x309c44:(0xfe9813c,0xfe98140,2047)};assert pool(0x30988c)==0xffc7070;exact(0x309890,'ldh.di','r0,[r0]')
 census=json.loads((src/'caller_census.json').read_text());bs,ps,bd=verified_payloads(ROOT);targets={int(x,0)for x in census['targets']};assert targets==({0x309884,*dispatch,*firsts,*masked,*flaggers,*splits,*getters});calls=[];pointers=[]
 for info in bs:
  blob=ps[info['index']];loadbase=info['load_address_candidate'];assert sha(bd/info['file'])==census['payload_sha256'][str(bd/info['file'])]
  for off in range(0,len(blob)-7,2):
   candidate=call_at(blob,off,loadbase)
   if candidate and candidate['target']in targets:calls.append(dict(payload=info['index'],**candidate))
  for t in sorted(targets):
   for kind,needle in[('LE',struct.pack('<I',t)),('ME',struct.pack('<HH',t>>16,t&65535))]:
    off=blob.find(needle)
    while off>=0:pointers.append(dict(payload=info['index'],address=hex(loadbase+off),target=hex(t),kind=kind));off=blob.find(needle,off+1)
 assert calls==census['call_candidates']and pointers==census['pointer_candidates']and len(calls)==37 and not pointers;qualified=[];excluded=[]
 for candidate in calls:
  if candidate['pc']==0x30aa10:
   x=decode(0x30aa0a);assert x['opcode']=='and'and x['operands']=='r3,r0,0xfc00'and len(bytes.fromhex(x['bytes_hex']))==8;excluded.append(dict(candidate=candidate,reason='Inside8byteAND instruction at30AA0A;not aninstruction boundary onthat localcode path'));continue
  assert candidate['payload']==0 and target(candidate['pc'])==candidate['target'];qualified.append(candidate)
 assert len(qualified)==36 and len(excluded)==1;checks=[];seen=set();counts=Counter();admitted=set();samples=set();masks_seen=set();selectors_seen={e:set()for e in dispatch};zero_flag_checks=0;operations={}
 for c in d['cases']:
  if not c['observer_enabled']:continue
  path=src/(c['name']+'.trace');err=src/(c['name']+'.stderr.log');inputs[str(path)]=sha(path);inputs[str(err)]=sha(err);assert path.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes();state={int(k,0):struct.unpack_from('<H',bytes.fromhex(v['before']),int(k,0)%8)[0]for k,v in c['fixtures'].items()};expected=[]
  for call in c['original_calls']:
   entry=int(call['entry'],0);argv=[int(x,0)for x in call['arguments']];ret=None;ev=[];seen.add(entry)
   if entry in dispatch:
    aa,bb,mask=dispatch[entry];v,mode=argv;selectors_seen[entry].add(mode);delta=entry-0x309a2c
    if mode==0:ev=[(0x309a58+delta,'read',aa,state[aa]),(0x309a66+delta,'write',aa,(state[aa]&~mask)|(v&mask))];ret=0
    elif mode==1:ev=[(0x309aa4+delta,'read',aa,state[aa])];ret=state[aa]
    elif mode==2:ev=[(0x309a78+delta,'read',bb,state[bb]),(0x309a66+delta,'write',bb,(state[bb]&~mask)|(v&mask))];ret=0
    elif mode==3:ev=[(0x309a90+delta,'read',bb,state[bb]),(0x309a66+delta,'write',bb,state[bb]&(~v&65535))];ret=0
    else:ret=0x55aa
    kind='fixed_pool_selector0_write_lowfield_1_read_full16_2_write_second_lowfield_3_clear_argument_mask'
   elif entry==0x309884:ev=[(0x309890,'read',0xffc7070,state[0xffc7070])];ret=state[0xffc7070];kind='fixed_pool_read_full16'
   elif entry in firsts:ret=lsb16(argv[0]);masks_seen.add(argv[0]);kind='first_set_bit_low16_or15_if_none'
   elif entry in masked:
    a,v,mask=argv;shift=lsb16(mask);new=((state[a]&~mask)|((v*(2**shift))&mask))%65536;ev=[(entry+12,'read',a,state[a]),(entry+34,'write',a,new)];kind='unbound_RMW_clear_mask_then_insert_value_shifted_by_first_low16_bit'
   elif entry in flaggers:
    a,flag,mask=argv;bit=lsb16(mask);rd=16 if flag==0 else 36;wr=24 if flag==0 else 44;new=state[a]|(1<<bit)if flag else state[a]&~(1<<bit);ev=[(entry+rd,'read',a,state[a]),(entry+wr,'write',a,new)];zero_flag_checks+=int(mask in[0,0x10000,0x80000000]);kind='unbound_set_clear_only_first_low16_mask_bit_zero_mask_selects15'
   elif entry in splits:a,v=argv;ev=[(entry+12,'write',a,v%65536),(entry+20,'write',a+4,v//65536)];kind='unbound_two_halfword_stores_low16_then_high16'
   else:
    assert entry in getters;a,mask=argv;ret=((state[a]&mask)//(2**lsb16(mask)))%65536;ev=[(entry+6,'read',a,state[a])];kind='unbound_read_mask_shift_from_first_low16_mask_bit'
   assert call['expected_return']==ret;operations[hex(entry)]=dict(entry=hex(entry),operation=kind,address_binding='original_pool'if entry in dispatch or entry==0x309884 else'unbound_r0_or_no_MMIO')
   for _,op,a,v in ev:
    assert 0<=v<=65535
    if op=='write':state[a]=v
   expected.extend(ev)
  captured=[json.loads(line.removeprefix('S33_MEM '))for line in err.read_text().splitlines()if line.startswith('S33_MEM ')];events=c['completed_memory_events'];assert len(captured)==2*len(events)and[e for e in captured if e['stage']=='result']==events
  for b,e in zip(captured[::2],captured[1::2]):assert b['stage']=='begin'and e['stage']=='result'and all(b[k]==e[k]for k in['id','pc','operation','address','width_bytes'])
  assert[(e['pc'],e['operation'],e['address'],e['value'])for e in events]==expected;pcs={e['pc']for e in events};traced=[];loads={}
  for line in path.read_text().splitlines():
   m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
   if m and int(m[1],16)in pcs:traced.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',int(m[3],16)&65535))
   m=re.match(r'0x([0-9a-f]+)\s+ldw\.as\.x\s+.*? - .*?<- (0x[0-9a-f]+)',line)
   if m:loads.setdefault(int(m[1],16),[]).append(int(m[2],16))
   assert not re.match(r'0x[0-9a-f]+\s+(sr|lr)\s',line)
  assert traced==[(e['pc'],e['operation'],e['value'])for e in events]
  for e in events:assert e['width_bytes']==2 and decode(e['pc'])['opcode']==('ldh.di'if e['operation']=='read'else'sth.di');counts[c['group']+'_'+e['operation']]+=1
  if c['group']=='fixed':
   for entry in dispatch:assert loads[entry+20]==[41,4,41,20,32]
   admitted.update(e['address']for e in events)
  else:assert c['address_binding']=='unbound_synthetic_lab_address_no_catalog_admission';samples.update(e['address']for e in events)
  for key,f in c['fixtures'].items():
   a=int(key,0);before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes();off=a%8;assert len(after)==8 and struct.unpack_from('<H',after,off)[0]==state[a]and all(before[j]==after[j]for j in range(8)if j not in[off,off+1])
  assert c['exit_code']==0 and c['fault']is None and c['full_original_calls_completed'];checks.append(dict(case=c['name'],group=c['group'],calls=len(c['original_calls']),events=len(events)))
 assert len(checks)==12 and sum(counts.values())==4184 and len(seen)==23 and admitted=={0xffc7070,0xfe9013c,0xfe90140,0xfe9813c,0xfe98140}and samples=={0xffb8000,0xffb8004}and len(masks_seen)==24 and zero_flag_checks==96;assert all(v=={0,1,2,3,4,255,0x7fffffff,0x80000000,0xffffffff}for v in selectors_seen.values());assert all(q['trace_identical']for q in d['pairs'])and len(d['pairs'])==12;assert all(sha(Path(k))==v for k,v in inputs.items())
 result=dict(status='PASS_FE9_SELECTORS_UNBOUND_MASK_HELPERS_AUDIT',date='2026-10-25',checks=checks,completed_memory_events=4184,operation_counts=dict(counts),new_bound_scalar_addresses=list(map(hex,sorted(admitted))),generic_sample_addresses_not_admitted=list(map(hex,sorted(samples))),generic_helper_address_domains_closed=False,software_operations=operations,selector_tables=tables,caller_census=dict(payloads=16,raw_BL_candidates=37,qualified_instruction_calls=qualified,excluded_candidates=excluded,pointer_candidates=0,global_caller_reachability_proven=False),zero_or_high_only_mask_flag_cases=96,independently_redecoded_instructions={hex(pc):v for pc,v in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=d['limits']);args.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS23entries/12scenarios/4184events;5bound addresses,4048generic events excluded fromadmission;36BL+1LIMMfalsecandidate')
if __name__=='__main__':main()
