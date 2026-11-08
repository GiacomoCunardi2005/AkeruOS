#!/usr/bin/env python3
"""Reconstruct masks and order from original scalar-tail opcodes, literals and CPU input loads."""
import argparse,json,re,struct,hashlib
from pathlib import Path
from s33_run_gnu_arc700 import ROOT
from s33_verify_sensor_mmio_dialog import aligned_window

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);args=ap.parse_args();src=args.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FFC7000_SCALAR_TAIL'and d['capture_streams_separate'];assert all(sha(Path(k))==v for k,v in d['input_hashes'].items())and all(sha(src/k)==v for k,v in d['files'].items());p=d['payload'];body=Path(p['path']).read_bytes();fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';assert body==fw.read_bytes()[p['firmware_offset']:p['firmware_offset']+p['size']]
 inputs={str(q):sha(q)for q in[Path(__file__),Path(__file__).with_name('s33_verify_sensor_mmio_dialog.py'),fw,src/'verified_evidence.json',ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']};instructions={};bindings=[];operations={};roles={}
 def decode(pc):
  if pc in instructions:return instructions[pc]
  text=aligned_window(body,p['base'],pc,pc+10);line=next(x for x in text.splitlines()if re.match(r'\s*'+f'{pc:x}'+':',x));m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line);raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert raw==body[pc-p['base']:pc-p['base']+len(raw)];instructions[pc]=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=p['firmware_offset']+pc-p['base']);return instructions[pc]
 def exact(pc,op,argv):assert decode(pc)['opcode']==op and decode(pc)['operands']==argv,(hex(pc),decode(pc))
 def imm(pc,op):
  x=decode(pc);assert x['opcode']==op;return int(x['operands'].split(',')[-1],0)
 def pool(pc):return struct.unpack_from('<I',body,pc-p['base'])[0]
 def literal(pc,reg):
  x=decode(pc);assert x['opcode']=='ld_s'and x['operands'].startswith(reg+',[pcl,');loc=int(re.search(r';(?:0x)?([0-9a-f]+)',x['operands'])[1],16);value=pool(loc);bindings.append(dict(pc=hex(pc),pool_pc=hex(loc),value=hex(value)));return value
 a7718=literal(0x30950e,'r14');a771c=literal(0x309562,'r13');a7720=literal(0x3095a0,'r13');a7724=literal(0x3095e6,'r14');assert[a7718,a771c,a7720,a7724]==[0xffc7718,0xffc771c,0xffc7720,0xffc7724]
 fields={}
 for entry,address,rd,wr,keep0,mask0,rd1,wr1,keep1,shift1,mask1 in[(0x309504,a7718,0x309520,0x30952e,0x309524,0x309528,0x309532,0x30954e,0x309536,0x30953e,0x309542),(0x3095dc,a7724,0x3095f0,0x3095fe,0x3095f4,0x3095f8,0x309602,0x309616,0x309606,0x30960a,0x30960e)]:
  lowmask=(1<<(imm(mask0,'bmsk_s')+1))-1;highmask=imm(mask1,'and');shift=imm(shift1,'asl');assert lowmask==((~imm(keep0,'and'))&65535)and highmask==((~imm(keep1,'and'))&65535)and shift==8;fields[entry]=[(address,rd,wr,lowmask,0,0),(address,rd1,wr1,highmask,shift,1)]
 masklo=(~imm(0x309572,'and'))&65535;maskhi=(~pool(0x309598))&65535;assert masklo==255 and maskhi==65280 and masklo==((~imm(0x3095ae,'and'))&65535)and maskhi==((~pool(0x3095d0))&65535);assert imm(0x30958c,'asl_s')==imm(0x3095c4,'asl_s')==8;exact(0x309584,'and_s','r0,r0,r1');exact(0x3095c0,'and_s','r1,r1,r0')
 fields[0x309558]=[(a771c,0x30956c,0x30957a,masklo,0,0),(a771c,0x30957e,0x30959c,maskhi,8,1),(a7720,0x3095a8,0x3095b6,masklo,0,2),(a7720,0x3095ba,0x3095d4,maskhi,8,3)]
 nibblemask=(~imm(0x309636,'mov'))&65535;assert nibblemask==15;fields[0x309620]=[]
 for load,rd,wr,maskpc,index in[(0x309628,0x309630,0x309642,0x30963c,4),(0x309646,0x309650,0x30965e,0x309658,5),(0x309662,0x30966c,0x30967a,0x309674,6)]:assert (1<<(imm(maskpc,'bmsk_s')+1))-1==nibblemask;fields[0x309620].append((literal(load,'r15'),rd,wr,nibblemask,0,index))
 for entry in[0x3096b8,0x3096e0,0x309738,0x309760,0x3097b8,0x3097e0]:
  a=literal(entry+8,'r13');short=decode(entry+20)['opcode']=='bclr_s';mask=(1<<(imm(entry+(22 if short else 24),'bmsk_s')+1))-1
  if short:assert imm(entry+20,'bclr_s')==0 and mask==1
  else:assert mask==((~imm(entry+20,'and'))&65535)==3
  fields[entry]=[(a,entry+16,entry+(28 if short else 30),mask,0,0)]
 flags={}
 for entry in[0x309684,0x309704,0x309784,0x309804,0x309850]:assert imm(entry+4,'cmp_s')==1 and decode(entry+6)['opcode']=='bne.d';flags[entry]=(literal(entry+2,'r2'),imm(entry+10,'mov_s'))
 readaddress=literal(0x30983a,'r0');assert readaddress==0xffc7080;exact(0x30984c,'bmsk_s','r0,r0,0');checks=[];outputs={};all_addresses=set();reads=writes=0;seen=set();flag_values={e:set()for e in flags};input_checks=0
 for c in d['cases']:
  if not c['observer_enabled']:continue
  path=src/(c['name']+'.trace');err=src/(c['name']+'.stderr.log');inputs[str(path)]=sha(path);inputs[str(err)]=sha(err);assert path.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes();raw=(src/c['input_file']).read_bytes();assert len(raw)==7 and raw.hex()==c['input_bytes_hex'];state={int(k,0):struct.unpack_from('<H',bytes.fromhex(f['before']),int(k,0)%8)[0]for k,f in c['fixtures'].items()};expected=[]
  for call in c['original_calls']:
   entry=int(call['entry'],0);argv=[int(x,0)for x in call['arguments']];seen.add(entry);ev=[];ret=None
   if entry in fields:
    buffer=entry in[0x309558,0x309620]
    if entry==0x309558:assert argv==[0x700000,0x700002]
    if entry==0x309620:assert argv==[0x700004]
    for a,rd,wr,mask,shift,index in fields[entry]:
     value=raw[index]if buffer else argv[index];new=(state[a]&(~mask&65535))|((value*(2**shift))&mask);ev.extend([(rd,'read',a,state[a]),(wr,'write',a,new)]);state[a]=new
    kind='ordered_buffer_byte_field_RMW'if buffer else'ordered_argument_masked_field_RMW';operations[hex(entry)]=dict(entry=hex(entry),operation=kind,fields=[dict(address=hex(a),read_pc=hex(rd),write_pc=hex(wr),mask=hex(mask),destination_shift=shift,input_byte_offset=index if buffer else None,argument=index if not buffer else None)for a,rd,wr,mask,shift,index in fields[entry]])
   elif entry in flags:
    a,bit=flags[entry];flag_values[entry].add(argv[0]);off=20 if argv[0]==1 else 36;new=(state[a]|1<<bit)if argv[0]==1 else(state[a]&~(1<<bit));ev=[(entry+off,'read',a,state[a]),(entry+off+8,'write',a,new)];state[a]=new;operations[hex(entry)]=dict(entry=hex(entry),operation='bit_set_iff_argument_equals1_else_clear',address=hex(a),bit=bit)
   else:assert entry==0x309838;ret=state[readaddress]&1;ev=[(0x309844,'read',readaddress,state[readaddress])];operations[hex(entry)]=dict(entry=hex(entry),operation='read16_return_bit0',address=hex(readaddress))
   assert call['expected_return']==ret
   for _,_,a,_ in ev:roles.setdefault(hex(a),set()).add(hex(entry))
   expected.extend(ev)
  captured=[json.loads(line.removeprefix('S33_MEM '))for line in err.read_text().splitlines()if line.startswith('S33_MEM ')];events=c['completed_memory_events'];assert len(captured)==2*len(events)and[e for e in captured if e['stage']=='result']==events
  for b,e in zip(captured[::2],captured[1::2]):assert b['stage']=='begin'and e['stage']=='result'and all(b[k]==e[k]for k in['id','pc','operation','address','width_bytes'])
  assert[(e['pc'],e['operation'],e['address'],e['value'])for e in events]==expected;pcs={e['pc']for e in events};traced=[];loads={}
  for line in path.read_text().splitlines():
   m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
   if m and int(m[1],16)in pcs:traced.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',int(m[3],16)&65535))
   m=re.match(r'0x([0-9a-f]+)\s+ldb_s\s+.*? - .*?<- (0x[0-9a-f]+)',line)
   if m:loads.setdefault(int(m[1],16),[]).append(int(m[2],16))
   assert not re.match(r'0x[0-9a-f]+\s+(sr|lr)\s',line)
  assert traced==[(e['pc'],e['operation'],e['value'])for e in events]
  for pc,index in[(0x309570,0),(0x309586,1),(0x3095ac,2),(0x3095c2,3),(0x309634,4),(0x309654,5),(0x309670,6)]:assert loads[pc]==[raw[index]]and decode(pc)['opcode']=='ldb_s';input_checks+=1
  for e in events:assert e['width_bytes']==2 and decode(e['pc'])['opcode']==('ldh.di'if e['operation']=='read'else'sth.di')
  for key,f in c['fixtures'].items():
   a=int(key,0);before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes();off=a%8;assert len(after)==8 and struct.unpack_from('<H',after,off)[0]==state[a]and all(before[j]==after[j]for j in range(8)if j not in[off,off+1])
  assert c['exit_code']==0 and c['fault']is None and c['full_original_calls_completed'];outputs[c['pattern']]=expected;all_addresses.update(e['address']for e in events);reads+=sum(e['operation']=='read'for e in events);writes+=sum(e['operation']=='write'for e in events);checks.append(dict(case=c['name'],calls=len(c['original_calls']),events=len(events)))
 assert len(checks)==9 and reads==342 and writes==333 and len(all_addresses)==18 and len(seen)==16 and input_checks==63;assert outputs[6]==outputs[8]and all(v=={0,1,2,0xffffffff}for v in flag_values.values());assert len(d['pairs'])==9 and all(x['trace_identical']for x in d['pairs']);assert all(sha(Path(k))==v for k,v in inputs.items())
 result=dict(status='PASS_FFC7000_SCALAR_TAIL_AUDIT',date='2026-10-25',checks=checks,completed_memory_events=675,reads=reads,writes=writes,scalar_addresses=list(map(hex,sorted(all_addresses))),scalar_operation_entries={a:sorted(v)for a,v in roles.items()},software_operations=operations,original_entries=16,independent_input_load_checks=63,metamorphic_equivalences=1,literal_bindings=bindings,independently_redecoded_instructions={hex(pc):v for pc,v in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=d['limits']);args.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS16entries/9scenarios/675events/18addresses;63input loads and1equivalence')
if __name__=='__main__':main()
