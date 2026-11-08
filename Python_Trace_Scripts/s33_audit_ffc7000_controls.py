#!/usr/bin/env python3
"""Independently audit FFC7000 branch polarity and byte intermediate stores."""
import argparse,hashlib,json,re,struct
from pathlib import Path
from s33_run_gnu_arc700 import ROOT
from s33_verify_sensor_mmio_dialog import aligned_window

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);a=ap.parse_args();src=a.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FFC7000_CONDITIONAL_AND_BYTE_CONTROLS';assert all(sha(Path(k))==v for k,v in d['input_hashes'].items());assert all(sha(src/k)==v for k,v in d['files'].items());p=d['payload'];body=Path(p['path']).read_bytes();fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';assert body==fw.read_bytes()[p['firmware_offset']:p['firmware_offset']+p['size']]
 isa_source=Path(d['extb_reference']['source']);isa_text=isa_source.read_text();start=isa_text.index('(dmfi extb\n');assert '(zext SI (cast QI C))'in isa_text[start:start+200]
 inputs={str(q):sha(q)for q in[isa_source,Path(__file__),fw,src/'verified_evidence.json',ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']};instructions={}
 def decode(pc):
  if pc in instructions:return instructions[pc]
  text=aligned_window(body,p['base'],pc,pc+8);line=next(x for x in text.splitlines()if re.match(r'\s*'+f'{pc:x}'+':',x));m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line);raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert raw==body[pc-p['base']:pc-p['base']+len(raw)];i=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=p['firmware_offset']+pc-p['base']);instructions[pc]=i;return i
 def pool(pc):return struct.unpack_from('<I',body,pc-p['base'])[0]
 def exact(pc,op,args):assert decode(pc)['opcode']==op and decode(pc)['operands']==args,(hex(pc),decode(pc))
 def imm(pc,op):
  i=decode(pc);assert i['opcode']==op;return int(i['operands'].split(',')[-1],0)
 for e in[0x3087bc,0x3088d0]:
  exact(e+6,'mov_s','r13,r1');assert imm(e+10,'cmp_s')==1 and decode(e+12)['opcode']=='bne.d';exact(e+16,'not_s','r15,r1')
 exact(0x3087d8,'b.d','14\t;0x3087e6');exact(0x3087dc,'and_s','r0,r0,r15');exact(0x3087e4,'or_s','r0,r0,r13');exact(0x3088ee,'or_s','r13,r13,r0');exact(0x3088fe,'and_s','r0,r0,r15')
 for e in[0x308920,0x3089a0]:
  for pc,args in[(e+6,'r13,r0'),(e+8,'r18,r1'),(e+10,'r16,r2'),(e+12,'r17,r3')]:exact(pc,'mov_s',args)
  assert imm(e+0x1c,'and')==-256;exact(e+0x20,'extb_s','r13,r13');exact(e+0x5c,'extb','r1,r16');assert pool(e+0x44)&65535==255;exact(e+0x32,'asl','r1,r18,0x8');exact(e+0x6e,'asl','r1,r17,0x8')
 exact(0x308a26,'mov_s','r13,r0');exact(0x308a28,'mov_s','r16,r1');assert imm(0x308a38,'and')==-256;exact(0x308a3c,'extb_s','r13,r13');assert imm(0x308a54,'and')&65535==255 and imm(0x308a60,'and')==0xff00;exact(0x308a5c,'asl','r1,r16,0x8')
 operations={};checks=[];addresses=set();high_bit_byte_stores=[];reads=0;writes=0;aux_srs=[]
 for c in d['cases']:
  if not c['observer_enabled']:continue
  path=src/(c['name']+'.trace');err=src/(c['name']+'.stderr.log');inputs[str(path)]=sha(path);inputs[str(err)]=sha(err);assert path.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes();raw=[json.loads(line.removeprefix('S33_MEM '))for line in err.read_text().splitlines()if line.startswith('S33_MEM ')];events=c['completed_memory_events'];assert len(raw)==2*len(events)and[e for e in raw if e['stage']=='result']==events
  for begin,end in zip(raw[::2],raw[1::2]):assert begin['stage']=='begin'and end['stage']=='result'and all(begin[k]==end[k]for k in['id','pc','operation','address','width_bytes'])
  state={int(k,0):struct.unpack_from('<H',bytes.fromhex(v['before']),int(k,0)%8)[0]for k,v in c['fixtures'].items()};expected=[]
  for call in c['original_calls']:
   entry=int(call['entry'],0);argv=list(map(lambda x:int(x,0),call['arguments']));ev=[];ret=None
   if entry==0x3087bc:
    addr=pool(entry+20);value=(state[addr]&~argv[1])if argv[0]==1 else(state[addr]|argv[1]);ev=[(entry+24 if argv[0]==1 else entry+34,'read',addr,state[addr]),(entry+44,'write',addr,value&65535)];kind='arg1_mask_CLEAR_iff_arg0_equals1_else_SET'
   elif entry in[0x3087f0,0x308808,0x30890c,0x3088a4]:
    addr=pool(entry+8);mask=(1<<(imm(entry+20,'bmsk_s')+1))-1 if entry==0x3088a4 else 65535;ret=state[addr]&mask;ev=[(entry+12,'read',addr,state[addr])];kind='read_return_full16'if mask==65535 else'read_return_low5'
   elif entry in[0x308820,0x308854]:
    addr=pool(entry+16);assert imm(entry+4,'cmp_s')==1 and decode(entry+6)['opcode']=='bne.d';bit=imm(entry+10,'mov_s');off=20 if argv[0]==1 else 36;value=state[addr]|1<<bit if argv[0]==1 else state[addr]&~(1<<bit);ev=[(entry+off,'read',addr,state[addr]),(entry+off+8,'write',addr,value)];kind=f'RMW_bit{bit}_set_iff_arg0_equals1_else_clear'
   elif entry==0x308888:
    addr=pool(entry+8);bit=imm(entry+4,'mov_s');assert bit==0 and decode(entry+16)['opcode']=='bset';ev=[(entry+12,'read',addr,state[addr]),(entry+20,'write',addr,state[addr]|1<<bit)];kind='unconditional_RMW_set_bit0_argument_ignored'
   elif entry==0x3088bc:
    addr=pool(entry+8);ev=[(entry+12,'write',addr,argv[0]&65535)];kind='store_argument_low16_despite_low5_getter'
   elif entry==0x3088d0:
    addr=pool(entry+20);is_set=argv[0]==1;value=state[addr]|argv[1]if is_set else state[addr]&~argv[1];ev=[(entry+24 if is_set else entry+42,'read',addr,state[addr]),(entry+34 if is_set else entry+50,'write',addr,value&65535)];kind='arg1_mask_SET_iff_arg0_equals1_else_CLEAR'
   elif entry in[0x308920,0x3089a0]:
    for i,po,rd1,wr1,rd2,wr2 in[(0,0x14,0x18,0x26,0x2a,0x48),(1,0x50,0x54,0x64,0x68,0x78)]:
     addr=pool(entry+po);byte=struct.unpack('B',bytes([argv[2*i]&255]))[0];first=((state[addr]&0xff00)|byte)&65535;last=(first&255)|((argv[2*i+1]&255)<<8);ev.extend([(entry+rd1,'read',addr,state[addr]),(entry+wr1,'write',addr,first),(entry+rd2,'read',addr,first),(entry+wr2,'write',addr,last)])
     if byte&128:assert first&0xff00==state[addr]&0xff00;high_bit_byte_stores.append(dict(case=c['name'],entry=hex(entry),address=hex(addr),intermediate=hex(first),final=hex(last),followed_by_high8_replacement=True))
    kind='two_cells_each_zeroextended_lowbyte_RMW_then_separate_masked_highbyte_RMW'
   else:
    assert entry==0x308a20;aa=[pool(entry+16),pool(entry+44)];byte=struct.unpack('B',bytes([argv[0]&255]))[0];first=((state[aa[0]]&0xff00)|byte)&65535;second=(state[aa[1]]&255)|((argv[1]&255)<<8);ev=[(entry+20,'read',aa[0],state[aa[0]]),(entry+34,'write',aa[0],first),(entry+48,'read',aa[1],state[aa[1]]),(entry+76,'write',aa[1],second)]
    if byte&128:assert first&0xff00==state[aa[0]]&0xff00;high_bit_byte_stores.append(dict(case=c['name'],entry=hex(entry),address=hex(aa[0]),intermediate=hex(first),final=hex(first),followed_by_high8_replacement=False))
    kind='zeroextended_lowbyte_RMW_first_cell_then_masked_highbyte_in_different_cell'
   assert call['expected_return']==(hex(ret)if ret is not None else None);operations[hex(entry)]=dict(entry=hex(entry),software_operation=kind,addresses=list(map(hex,sorted({addr for _,_,addr,_ in ev}))),hardware_semantics='unknown')
   for _,op,addr,value in ev:
    assert addr in state and 0<=value<=65535;addresses.add(addr)
    if op=='write':state[addr]=value
   expected.extend(ev)
  assert[(e['pc'],e['operation'],e['address'],e['value'])for e in events]==expected;pcs={e['pc']for e in events};traced=[]
  for line in path.read_text().splitlines():
   m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
   if m and int(m[1],16)in pcs:traced.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',int(m[3],16)&65535))
   if re.match(r'0x[0-9a-f]+\s+sr\s+',line):aux_srs.append(line)
  assert traced==[(e['pc'],e['operation'],e['value'])for e in events]
  for e in events:assert e['width_bytes']==2 and decode(e['pc'])['opcode']==('ldh.di'if e['operation']=='read'else'sth.di')
  for key,f in c['fixtures'].items():
   addr=int(key,0);before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes();offset=addr%8;assert len(after)==8 and struct.unpack_from('<H',after,offset)[0]==state[addr]and all(before[i]==after[i]for i in range(8)if i not in[offset,offset+1])
  assert c['exit_code']==0 and c['fault']is None and c['full_original_calls_completed'];reads+=sum(e['operation']=='read'for e in events);writes+=sum(e['operation']=='write'for e in events);checks.append(dict(case=c['name'],calls=len(c['original_calls']),events=len(events)))
 assert len(checks)==8 and reads==280 and writes==224 and len(addresses)==13 and len(operations)==13 and not aux_srs and len(high_bit_byte_stores)==20 and sum(n['followed_by_high8_replacement']for n in high_bit_byte_stores)==16;assert len(d['pairs'])==8 and all(x['trace_identical']for x in d['pairs']);assert all(sha(Path(k))==v for k,v in inputs.items())
 result=dict(status='PASS_FFC7000_CONTROLS_INDEPENDENT_AUDIT',date='2026-10-25',checks=checks,selected_original_entries=13,scalar_addresses=list(map(hex,sorted(addresses))),software_operations=operations,completed_memory_events=reads+writes,reads=reads,writes=writes,original_calls_observed=232,high_bit_byte_first_writes=high_bit_byte_stores,new_aux_sr_sites=0,extb_zero_extension_reference=d['extb_reference'],independently_redecoded_instructions={hex(pc):i for pc,i in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=d['limits']);a.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS13entries/8scenarios/504events/13addresses;inverse mask polarity and20high-bit byte inputs preserve prior high8')
if __name__=='__main__':main()
