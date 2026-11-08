#!/usr/bin/env python3
"""Independently bind wrapper constants, original table and loop field semantics to CPU traces."""
import argparse,hashlib,json,re,struct
from pathlib import Path
from s33_run_gnu_arc700 import ROOT
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_verify_custom_aux_cfg import call_at

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);a=ap.parse_args();src=a.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FFC7000_BOUND_LOOP_WRITERS';assert all(sha(Path(k))==v for k,v in d['input_hashes'].items());assert all(sha(src/k)==v for k,v in d['files'].items());p=d['payload'];body=Path(p['path']).read_bytes();fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';assert body==fw.read_bytes()[p['firmware_offset']:p['firmware_offset']+p['size']]
 inputs={str(q):sha(q)for q in[Path(__file__),Path(__file__).with_name('s33_verify_custom_aux_cfg.py'),fw,src/'verified_evidence.json',ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']};instructions={};bindings=[]
 def decode(pc):
  if pc in instructions:return instructions[pc]
  text=aligned_window(body,p['base'],pc,pc+10);line=next(x for x in text.splitlines()if re.match(r'\s*'+f'{pc:x}'+':',x));m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line);raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert raw==body[pc-p['base']:pc-p['base']+len(raw)];i=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=p['firmware_offset']+pc-p['base']);instructions[pc]=i;return i
 def exact(pc,op,args):assert decode(pc)['opcode']==op and decode(pc)['operands']==args,(hex(pc),decode(pc))
 def imm(pc,op):
  x=decode(pc);assert x['opcode']==op;return int(x['operands'].split(',')[-1],0)
 def pool(address):return struct.unpack_from('<I',body,address-p['base'])[0]
 def literal(pc,dest):
  i=decode(pc);assert i['opcode']=='ld_s'and i['operands'].startswith(dest+',[pcl,');poolpc=int(re.search(r';(0x[0-9a-f]+)',i['operands'])[1],0);value=pool(poolpc);bindings.append(dict(pc=hex(pc),pool_pc=hex(poolpc),value=hex(value)));return value
 raw_wrappers=[]
 for entry in[0x308f7c,0x308f98,0x308fb4,0x308fd0]:
  assert call_at(body,entry+8-p['base'],p['base'])['target']==0x308f48 and call_at(body,entry+16-p['base'],p['base'])['target']==0x308f48;exact(entry+12,'mov_s','r1,r13');exact(entry+20,'add','r1,r13,0x1a');raw_wrappers.append(dict(entry=entry,bases=[literal(entry+6,'r0'),literal(entry+14,'r0')],call_pcs=[entry+8,entry+16],input_byte_offsets=[0,26]))
 assert[b for w in raw_wrappers for b in w['bases']]==list(range(0xffc7314,0xffc74b4,0x34));count13=imm(0x308f4e,'mov');assert count13==13;exact(0x308f62,'ldw_s','r0,[r13,0]');exact(0x308f70,'sth.di','r0,[r14]');assert imm(0x308f74,'add_s')==4 and imm(0x308f76,'add_s')==2
 target=literal(0x3090d6,'r14');assert target==0x309090;low9_bases=[]
 for loadpc,callpc,offset in[(0x3090da,0x3090dc,0),(0x3090e0,0x3090e2,8),(0x3090e8,0x3090ea,16),(0x3090f0,0x3090f2,24)]:
  low9_bases.append(literal(loadpc,'r0'));exact(callpc,'jl_s.d','[r14]')
  if offset:assert imm(callpc+2,'add')==offset
  else:exact(callpc+2,'mov_s','r1,r13')
 assert low9_bases==[0xffc74bc+16*i for i in range(4)]and imm(0x309096,'mov')==4;keep=imm(0x3090ba,'and')&65535;lowmask=(1<<(imm(0x3090be,'bmsk_s')+1))-1;assert keep==0xfe00 and lowmask==0x1ff;assert imm(0x3090c8,'add_s')==4 and imm(0x3090ca,'add_s')==2
 table_address=literal(0x308ede,'r1');assert table_address==0x354e50;table=body[table_address-p['base']:table_address-p['base']+6];masks=struct.unpack_from('<2H',table);shifts=table[4:6];assert masks==(255,65280)and shifts==bytes([0,8]);assert imm(0x308eda,'mov')==9;exact(0x308f00,'asr_s','r15,r13');exact(0x308f02,'asl_s','r15,r15,0x2');assert imm(0x308f04,'add_s')==0xffc7300
 assert imm(0x308ff2,'mov')==4;fixed=[pool(0x309038),pool(0x309060)];assert fixed==[0xffc74b4,0xffc74b8]and pool(0x309054)==fixed[0]and pool(0x30907c)==fixed[1];maskA=imm(0x309042,'mov_s');maskB=imm(0x30906a,'mov_s');assert(maskA,maskB)==(15,7);exact(0x30900a,'asl_s','r13,r1,0x2')
 aux_pcs={0x308ef2:3,0x308ef8:2,0x308f58:3,0x308f5e:2,0x308ffe:3,0x309004:2,0x3090a0:3,0x3090a6:2};checks=[];outputs={};aux_records=[];all_addresses=set();reads=0;writes=0
 for c in d['cases']:
  if not c['observer_enabled']:continue
  path=src/(c['name']+'.trace');err=src/(c['name']+'.stderr.log');inputs[str(path)]=sha(path);inputs[str(err)]=sha(err);assert path.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes();buffers=[(src/item['file']).read_bytes()for item in c['input_files']];assert all(raw==bytes.fromhex(item['bytes'])for raw,item in zip(buffers,c['input_files']));state={int(k,0):struct.unpack_from('<H',bytes.fromhex(v['before']),int(k,0)%8)[0]for k,v in c['fixtures'].items()};expected=[];group=c['group'];entry=int(c['selected_entry'],0)
  def rmw(rd,wr,address,value):expected.extend([(rd,'read',address,state[address]),(wr,'write',address,value)]);state[address]=value
  if group=='byte9':
   assert entry==0x308ed4 and len(buffers[0])==9
   for i,value in enumerate(buffers[0]):
    address=0xffc7300+4*(i>>1);mask=masks[i&1];shift=shifts[i&1];rmw(0x308f18,0x308f38,address,(state[address]&~mask)|((value<<shift)&mask))
  elif group.startswith('raw13_'):
   w=next(w for w in raw_wrappers if w['entry']==entry);assert len(buffers[0])==52;values=struct.unpack('<26H',buffers[0])
   for j,address in enumerate(w['bases']):
    for i in range(count13):a0=address+4*i;value=values[13*j+i];expected.append((0x308f70,'write',a0,value));state[a0]=value
  elif group=='nibble_pair':
   assert entry==0x308fec and list(map(len,buffers))==[4,4]
   for i in range(4):
    for j,mask,rd,wr in[(0,maskA,0x30903c,0x309058),(1,maskB,0x309064,0x309080)]:
     address=fixed[j];shift=4*i;rmw(rd,wr,address,(state[address]&~(mask<<shift))|((buffers[j][i]<<shift)&(mask<<shift)))
  else:
   assert group=='low9_four'and entry==0x3090d0 and len(buffers[0])==32;values=struct.unpack('<16H',buffers[0])
   for j,address in enumerate(low9_bases):
    for i in range(4):a0=address+4*i;rmw(0x3090b4,0x3090c4,a0,(state[a0]&keep)|(values[4*j+i]&lowmask))
  captured=[json.loads(line.removeprefix('S33_MEM '))for line in err.read_text().splitlines()if line.startswith('S33_MEM ')];events=c['completed_memory_events'];assert len(captured)==2*len(events)and[e for e in captured if e['stage']=='result']==events
  for begin,end in zip(captured[::2],captured[1::2]):assert begin['stage']=='begin'and end['stage']=='result'and all(begin[k]==end[k]for k in['id','pc','operation','address','width_bytes'])
  assert[(e['pc'],e['operation'],e['address'],e['value'])for e in events]==expected;pcs={e['pc']for e in events};traced=[];loads={};sr_case=[];lines=path.read_text().splitlines()
  for no,line in enumerate(lines,1):
   m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
   if m and int(m[1],16)in pcs:traced.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',int(m[3],16)&65535))
   m=re.match(r'0x([0-9a-f]+)\s+(?:ldw(?:_s)?|ldb(?:_s)?)\s+.*? - .*?<- (0x[0-9a-f]+)',line)
   if m:loads.setdefault(int(m[1],16),[]).append(int(m[2],16))
   m=re.match(r'0x([0-9a-f]+)\s+sr\s+.*?\[([^\]]+)\].*? - .*?<- (0x[0-9a-f]+)',line)
   if m:
    pc=int(m[1],16);index=int(m[2],0);assert aux_pcs[pc]==index and decode(pc)['opcode']=='sr';record=dict(case=c['name'],trace_line=no,pc=pc,aux_index=index,trace_value=int(m[3],16));aux_records.append(record);sr_case.append(record)
  assert traced==[(e['pc'],e['operation'],e['value'])for e in events]
  for e in events:assert e['width_bytes']==2 and decode(e['pc'])['opcode']==('ldh.di'if e['operation']=='read'else'sth.di')
  if group=='byte9':assert loads[0x308efc]==list(buffers[0])and loads[0x308f26]==[masks[i&1]for i in range(9)]and loads[0x308f2a]==[shifts[i&1]for i in range(9)]and len(sr_case)==2
  elif group.startswith('raw13_'):assert loads[0x308f62]==list(struct.unpack('<26H',buffers[0]))and sum(bool(re.match(r'0x308f48\s+push_s',line))for line in lines)==2 and len(sr_case)==4
  elif group=='nibble_pair':assert loads[0x309040]==list(buffers[0])and loads[0x309068]==list(buffers[1])and len(sr_case)==2
  else:assert loads[0x3090b8]==list(struct.unpack('<16H',buffers[0]))and sum(bool(re.match(r'0x309090\s+push_s',line))for line in lines)==4 and len(sr_case)==8
  for key,f in c['fixtures'].items():
   address=int(key,0);before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes();off=address%8;assert len(after)==8 and struct.unpack_from('<H',after,off)[0]==state[address]and all(before[i]==after[i]for i in range(8)if i not in[off,off+1])
  assert c['exit_code']==0 and c['fault']is None and c['full_original_calls_completed'];outputs[(group,c['pattern'])]=[(e['address'],e['value'])for e in events if e['operation']=='write'];all_addresses.update(e['address']for e in events);reads+=sum(e['operation']=='read'for e in events);writes+=sum(e['operation']=='write'for e in events);checks.append(dict(case=c['name'],group=group,events=len(events),aux_sr_records=len(sr_case)))
 assert len(checks)==28 and reads==132 and writes==548 and len(all_addresses)==127 and len(aux_records)==112 and len(d['pairs'])==28 and all(x['trace_identical']for x in d['pairs']);assert outputs[('nibble_pair',2)]==outputs[('nibble_pair',3)]and outputs[('low9_four',2)]==outputs[('low9_four',3)]
 def window(name,base,count,writer,**extra):return dict(name=name,base=hex(base),element_count=count,stride_bytes=4,store_width_bits=16,last_cell_address=hex(base+4*(count-1)),writer_entry=hex(writer),physical_kind='unknown_register_array_or_memory_aperture',concrete_control_registers_admitted_from_window_cells=0,hardware_verified=False,**extra)
 windows=[window('ffc7000_byte9',0xffc7300,5,0x308ed4,access='read_modify_write_halfword_di',value_contract='nineu8inputs alternate low8/high8;last cell low8 only andpriorhigh8 preserved',original_mask_table=dict(address=hex(table_address),bytes_hex=table.hex()),source_input_bytes=9)]
 for w in raw_wrappers:
  for j,base in enumerate(w['bases']):windows.append(window('ffc7000_raw13_'+hex(base)[2:],base,13,0x308f48,access='write_halfword_di',wrapper_entry=hex(w['entry']),wrapper_call_pc=hex(w['call_pcs'][j]),input_byte_offset=w['input_byte_offsets'][j],value_contract='13rawu16input values copied with4byte destination stride;caller-bound base',source_binding='original_constant_destination_wrapper'))
 for j,base in enumerate(low9_bases):windows.append(window('ffc7000_low9_'+hex(base)[2:],base,4,0x309090,access='read_modify_write_halfword_di',wrapper_entry='0x3090d0',indirect_target_pool='0x309134',input_byte_offset=8*j,value_mask='0x1ff',keep_mask='0xfe00',value_contract='fourlow9halfwords;preserve high7;caller-bound destination',source_binding='original_indirect_target_and_constant_destination_wrapper'))
 cells=set().union(*[{int(w['base'],0)+4*i for i in range(w['element_count'])}for w in windows]);assert len(windows)==13 and len(cells)==125 and not cells&set(fixed);assert all(sha(Path(k))==v for k,v in inputs.items())
 result=dict(status='PASS_FFC7000_BOUND_LOOP_WRITERS_AUDIT',date='2026-10-25',checks=checks,completed_memory_events=680,reads=reads,writes=writes,transfer_windows=windows,new_window_cells=125,scalar_addresses=list(map(hex,fixed)),scalar_events=64,window_events=616,scalar_operations={hex(fixed[0]):dict(entry='0x308fec',operation='fourordered nibbleRMWs with masksF shifted0/4/8/12;all16bits eventually replaced'),hex(fixed[1]):dict(entry='0x308fec',operation='fourordered3bitRMWs atnibble spacing;preserve bits3/7/11/15')},original_table=dict(address=hex(table_address),bytes_hex=table.hex(),masks=list(masks),shifts=list(shifts)),original_wrapper_bindings=raw_wrappers,low9_wrapper_binding=dict(entry='0x3090d0',helper=hex(target),bases=list(map(hex,low9_bases))),literal_bindings=bindings,aux_sr_records=aux_records,aux_unique_pcs=8,metamorphic_equivalences=2,parameterized_helper_domains_closed=False,independently_redecoded_instructions={hex(pc):i for pc,i in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=d['limits']);a.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS28scenarios/680events,13caller-bound windows/125cells,2fixed scalars;112SRrecords/8PCs,table andloads audited')
if __name__=='__main__':main()
