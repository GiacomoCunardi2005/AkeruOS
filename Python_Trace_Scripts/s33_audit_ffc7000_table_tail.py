#!/usr/bin/env python3
"""Audit original packed-field parameter tables, fixed caller bindings and scalar update order."""
import argparse,hashlib,json,re,struct
from pathlib import Path
from s33_run_gnu_arc700 import ROOT
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_verify_custom_aux_cfg import call_at

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);a=ap.parse_args();src=a.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FFC7000_ORIGINAL_TABLE_TAIL';assert all(sha(Path(k))==v for k,v in d['input_hashes'].items())and all(sha(src/k)==v for k,v in d['files'].items());p=d['payload'];body=Path(p['path']).read_bytes();fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';assert body==fw.read_bytes()[p['firmware_offset']:p['firmware_offset']+p['size']]
 inputs={str(q):sha(q)for q in[Path(__file__),Path(__file__).with_name('s33_verify_custom_aux_cfg.py'),fw,src/'verified_evidence.json',ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']};instructions={};bindings=[]
 def decode(pc):
  if pc in instructions:return instructions[pc]
  text=aligned_window(body,p['base'],pc,pc+10);line=next(x for x in text.splitlines()if re.match(r'\s*'+f'{pc:x}'+':',x));m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line);raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert raw==body[pc-p['base']:pc-p['base']+len(raw)];i=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=p['firmware_offset']+pc-p['base']);instructions[pc]=i;return i
 def exact(pc,op,args):assert decode(pc)['opcode']==op and decode(pc)['operands']==args,(hex(pc),decode(pc))
 def imm(pc,op):
  x=decode(pc);assert x['opcode']==op;return int(x['operands'].split(',')[-1],0)
 def pool(pc):return struct.unpack_from('<I',body,pc-p['base'])[0]
 def literal(pc,reg):
  i=decode(pc);assert i['opcode']=='ld_s'and i['operands'].startswith(reg+',[pcl,');loc=int(re.search(r';(0x[0-9a-f]+)',i['operands'])[1],0);value=pool(loc);bindings.append(dict(pc=hex(pc),pool_pc=hex(loc),value=hex(value)));return value
 table=body[0x354e50-p['base']:0x354e98-p['base']];assert table.hex()==d['original_parameter_table']['bytes_hex'];parameters={name:struct.unpack_from('<4I',table,offset)for name,offset in[('pack5',8),('skip16',24),('pack7',40),('pack8',56)]};assert parameters==dict(pack5=(0,8,31,7936),skip16=(0,8,255,65280),pack7=(0,8,127,32512),pack8=(0,8,255,65280))
 for loadpc,countpc,count,initpc in[(0x30910a,0x309102,4,0x30910e),(0x3092ea,0x3092e2,10,0x3092f0),(0x3093c2,0x3093ba,33,0x3093c6),(0x30946a,0x309462,9,0x30946e)]:assert literal(loadpc,'r0')==0x354e50 and imm(countpc,'mov')==count and imm(initpc,'mov_s')==0
 copies=[(0x309110,0x309112,0x309116,0x309118,8),(0x3092f2,0x3092f4,0x3092f8,0x3092fa,24),(0x3093c8,0x3093ca,0x3093ce,0x3093d0,40),(0x309470,0x309472,0x309476,0x309478,56)]
 for hi,lo,m0,m1,off in copies:
  for pc,reg,offset in[(hi,'r1',off+4),(lo,'r2',off),(m0,'r1',off+8),(m1,'r0',off+12)]:exact(pc,'ld_s',f'{reg},[r0,{hex(offset)}]')
 assert literal(0x30918e,'r14')==0x3090fc;pack5=[literal(pc,'r0')for pc in[0x309192,0x309198,0x30919e,0x3091a6]]
 for pc in[0x309194,0x30919a,0x3091a0,0x3091a8]:exact(pc,'jl_s.d','[r14]')
 exact(0x309196,'mov_s','r1,r13');exact(0x30919c,'add_s','r1,r13,0x4');exact(0x3091a2,'add','r1,r13,0x8');exact(0x3091aa,'add','r1,r13,0xc')
 assert literal(0x309436,'r14')==0x3093b4;pack7=[literal(pc,'r0')for pc in[0x30943a,0x309440,0x309448,0x309452]]
 for pc in[0x30943c,0x309442,0x30944a,0x309454]:exact(pc,'jl_s.d','[r14]')
 exact(0x30943e,'mov_s','r1,r13');exact(0x309444,'add','r1,r13,0x21');exact(0x30944c,'add1','r1,r13,0x21');exact(0x309450,'mov_s','r1,r13');exact(0x309456,'add_s','r1,r1,0x63')
 pack8=[literal(0x3094ee,'r0'),literal(0x3094f6,'r0')];assert call_at(body,0x3094f0-p['base'],p['base'])['target']==0x30945c and call_at(body,0x3094f8-p['base'],p['base'])['target']==0x30945c;exact(0x3094f4,'mov_s','r1,r13');exact(0x3094fc,'add','r1,r13,0x9')
 exact(0x3093ac,'mov_s','r1,r0');assert decode(0x3093ae)['opcode']=='b.d'and int(re.search(r';(0x[0-9a-f]+)',decode(0x3093ae)['operands'])[1],0)==0x3092dc;skipbase=literal(0x3093b2,'r0');assert skipbase==0xffc75b8 and imm(0x309350,'mov')==6 and imm(0x309354,'mov_s')==12;exact(0x30938a,'sub','r3,r16,0x2');exact(0x30938e,'add_s','r3,r3,r14')
 assert pack5==[0xffc74fc+8*i for i in range(4)]and pack7==[0xffc75e0+68*i for i in range(4)]and pack8==[0xffc76f0,0xffc7704];assert imm(0x3092a6,'mov')==33 and imm(0x3092be,'add_s')==0xffc7530;exact(0x3092bc,'ldw_s','r1,[r14,0]');exact(0x3092d0,'sth.di','r1,[r0]')
 scalar_addresses=[literal(0x3091bc,'r13'),literal(0x30920c,'r13'),literal(0x30922a,'r1'),literal(0x30923e,'r1'),literal(0x30925a,'r13')];assert scalar_addresses==[0xffc751c,0xffc7520,0xffc7524,0xffc7528,0xffc752c];assert imm(0x3091de,'mov')&65535==0xff00 and imm(0x3091f2,'and')&65535==255;assert imm(0x309268,'and')&65535==0xff00;exact(0x30926c,'extb_s','r15,r15');assert imm(0x309276,'cmp_s')==0 and decode(0x309278)['opcode']=='beq.d'and imm(0x30927c,'mov_s')==15
 aux_pcs={pc:idx for a0,b0 in[(0x309122,0x309128),(0x3092b0,0x3092b6),(0x309304,0x30930a),(0x309358,0x30935e),(0x3093da,0x3093e0),(0x309482,0x309488)]for pc,idx in[(a0,3),(b0,2)]};checks=[];outputs={};aux=[];all_addresses=set();reads=0;writes=0
 for c in d['cases']:
  if not c['observer_enabled']:continue
  path=src/(c['name']+'.trace');err=src/(c['name']+'.stderr.log');inputs[str(path)]=sha(path);inputs[str(err)]=sha(err);assert path.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes();raw=(src/c['input_file']).read_bytes();assert raw.hex()==c['input_bytes_hex'];state={int(k,0):struct.unpack_from('<H',bytes.fromhex(v['before']),int(k,0)%8)[0]for k,v in c['fixtures'].items()};expected=[];group=c['group']
  def rmw(rd,wr,address,value):expected.extend([(rd,'read',address,state[address]),(wr,'write',address,value)]);state[address]=value
  if group=='scalars':
   for call in c['original_calls']:
    entry=int(call['entry'],0);argv=list(map(lambda x:int(x,0),call['arguments']))
    if entry==0x3091b4:
     aa,bb=scalar_addresses[:2];first=(state[aa]&0xff00)|raw[0];rmw(0x3091d8,0x3091e8,aa,first);rmw(0x3091ec,0x309208,aa,(state[aa]&255)|(raw[1]<<8));rmw(0x309214,0x309220,bb,(state[bb]&0xff00)|raw[2])
    elif entry in[0x309228,0x30923c]:address=scalar_addresses[2 if entry==0x309228 else 3];value=argv[0]&65535;expected.append((entry+12,'write',address,value));state[address]=value
    else:
     assert entry==0x309250;address=scalar_addresses[4];rmw(0x309264,0x309272,address,(state[address]&0xff00)|(argv[0]&255));flag=argv[1]!=0;value=state[address]|0x8000 if flag else state[address]&0x7fff;rmw(0x30927e if flag else 0x30928e,0x309286 if flag else 0x309296,address,value)
  elif group=='raw33':
   assert len(raw)==66
   for i,value in enumerate(struct.unpack('<33H',raw)):address=0xffc7530+4*i;expected.append((0x3092d0,'write',address,value));state[address]=value
  else:
   shift0,shift1,mask0,mask1=parameters[group]
   if group=='skip16':segments=[(skipbase,[(i,i,0x309324,0x309348)for i in range(10)]+[(j,j-2,0x309374,0x30939e)for j in range(12,18)])]
   else:
    bases,count,rd,wr=(pack5,4,0x309154,0x309178)if group=='pack5'else(pack7,33,0x3093fc,0x309420)if group=='pack7'else(pack8,9,0x3094b4,0x3094d8);assert len(raw)==count*len(bases);segments=[(base0,[(i,j*count+i,rd,wr)for i in range(count)])for j,base0 in enumerate(bases)]
   for base0,operations in segments:
    for i,input_index,rd,wr in operations:
     address=base0+4*(i>>1);mask=[mask0,mask1][i&1];shift=[shift0,shift1][i&1];rmw(rd,wr,address,(state[address]&~mask)|((raw[input_index]<<shift)&mask))
  captured=[json.loads(line.removeprefix('S33_MEM '))for line in err.read_text().splitlines()if line.startswith('S33_MEM ')];events=c['completed_memory_events'];assert len(captured)==2*len(events)and[e for e in captured if e['stage']=='result']==events
  for begin,end in zip(captured[::2],captured[1::2]):assert begin['stage']=='begin'and end['stage']=='result'and all(begin[k]==end[k]for k in['id','pc','operation','address','width_bytes'])
  assert[(e['pc'],e['operation'],e['address'],e['value'])for e in events]==expected;pcs={e['pc']for e in events};traced=[];loads={};sr=[];lines=path.read_text().splitlines()
  for no,line in enumerate(lines,1):
   m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
   if m and int(m[1],16)in pcs:traced.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',int(m[3],16)&65535))
   m=re.match(r'0x([0-9a-f]+)\s+ld(?:w|b)?(?:_s)?\s+.*? - .*?<- (0x[0-9a-f]+)',line)
   if m:loads.setdefault(int(m[1],16),[]).append(int(m[2],16))
   m=re.match(r'0x([0-9a-f]+)\s+sr\s+.*?\[([^\]]+)\].*? - .*?<- (0x[0-9a-f]+)',line)
   if m:
    pc=int(m[1],16);idx=int(m[2],0);assert aux_pcs[pc]==idx and decode(pc)['opcode']=='sr';record=dict(case=c['name'],trace_line=no,pc=pc,aux_index=idx,trace_value=int(m[3],16));aux.append(record);sr.append(record)
  assert traced==[(e['pc'],e['operation'],e['value'])for e in events]
  for e in events:assert e['width_bytes']==2 and decode(e['pc'])['opcode']==('ldh.di'if e['operation']=='read'else'sth.di')
  if group in['pack5','pack7','pack8']:
   helper,input_pc,mask_pc,shift_pc,count,calls=(0x3090fc,0x30916a,0x309168,0x30916c,4,4)if group=='pack5'else(0x3093b4,0x309412,0x309410,0x309414,33,4)if group=='pack7'else(0x30945c,0x3094ca,0x3094c8,0x3094cc,9,2);q=parameters[group];assert loads[input_pc]==list(raw)and loads[mask_pc]==[q[2+(i&1)]for j in range(calls)for i in range(count)]and loads[shift_pc]==[q[i&1]for j in range(calls)for i in range(count)];assert sum(bool(re.match(f'0x{helper:x}'+r'\s+push_s',line))for line in lines)==calls and len(sr)==2*calls
  elif group=='skip16':
   q=parameters[group];assert loads[0x30933a]==list(raw[:10])and loads[0x309390]==list(raw[10:]);assert loads[0x309338]==[q[2+(i&1)]for i in range(10)]and loads[0x309388]==[q[2+(i&1)]for i in range(12,18)]and loads[0x30933c]==[q[i&1]for i in range(10)]and loads[0x309392]==[q[i&1]for i in range(12,18)];assert len(sr)==4
  elif group=='raw33':assert loads[0x3092bc]==list(struct.unpack('<33H',raw))and len(sr)==2
  else:assert loads[0x3091dc]==[raw[0]]and loads[0x3091f0]==[raw[1]]and loads[0x309218]==[raw[2]]and not sr
  for key,f in c['fixtures'].items():
   address=int(key,0);before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes();off=address%8;assert len(after)==8 and struct.unpack_from('<H',after,off)[0]==state[address]and all(before[j]==after[j]for j in range(8)if j not in[off,off+1])
  assert c['exit_code']==0 and c['fault']is None and c['full_original_calls_completed'];outputs[(group,c['pattern'])]=[(e['address'],e['value'])for e in events if e['operation']=='write'];all_addresses.update(e['address']for e in events);reads+=sum(e['operation']=='read'for e in events);writes+=sum(e['operation']=='write'for e in events);checks.append(dict(case=c['name'],group=group,events=len(events),aux_sr_records=len(sr)))
 assert len(checks)==24 and reads==772 and writes==912 and len(all_addresses)==132 and len(aux)==104;assert outputs[('pack5',2)]==outputs[('pack5',3)]and outputs[('pack7',2)]==outputs[('pack7',3)];assert len(d['pairs'])==24 and all(x['trace_identical']for x in d['pairs'])
 def win(name,base,count,writer,**extra):return dict(name=name,base=hex(base),element_count=count,stride_bytes=4,store_width_bits=16,last_cell_address=hex(base+4*(count-1)),writer_entry=hex(writer),physical_kind='unknown_register_array_or_memory_aperture',concrete_control_registers_admitted_from_window_cells=0,hardware_verified=False,**extra)
 windows=[]
 for group,bases,count,writer,wrapper,per,offset in[('pack5',pack5,2,0x3090fc,0x309188,4,8),('pack7',pack7,17,0x3093b4,0x309430,33,40),('pack8',pack8,5,0x30945c,0x3094e8,9,56)]:
  q=parameters[group]
  for j,base0 in enumerate(bases):windows.append(win('ffc7000_'+group+'_'+hex(base0)[2:],base0,count,writer,wrapper_entry=hex(wrapper),input_byte_offset=j*per,source_input_bytes=per,original_table_offset=offset,lane_shifts=list(q[:2]),lane_masks=list(map(hex,q[2:])),value_contract='Alternating byte-lane RMW;unselected bits andodd-final-cell highlane preserved',source_binding='original_fixed_destination_wrapper'))
 windows.append(win('ffc7000_raw33_7530',0xffc7530,33,0x3092a0,value_contract='33rawu16inputs copied withstride4',source_input_bytes=66))
 windows +=[win('ffc7000_skip16_low',skipbase,5,0x3092dc,wrapper_entry='0x3093ac',input_byte_offset=0,source_input_bytes=10,loop_index_range=[0,9],value_contract='Fivebyte pairs via10RMWs,table FF/FF00'),win('ffc7000_skip16_high',skipbase+24,3,0x3092dc,wrapper_entry='0x3093ac',input_byte_offset=10,source_input_bytes=6,loop_index_range=[12,17],value_contract='Threebyte pairs via6RMWs after one-cell destinationgap')]
 cells=set().union(*[{int(w['base'],0)+4*i for i in range(w['element_count'])}for w in windows]);assert len(windows)==13 and len(cells)==127 and not cells&set(scalar_addresses)and 0xffc75cc not in cells;assert all(sha(Path(k))==v for k,v in inputs.items())
 scalar_operations={hex(scalar_addresses[0]):dict(entry='0x3091b4',operation='inputbyte0 low8RMW thenbyte1 high8RMW'),hex(scalar_addresses[1]):dict(entry='0x3091b4',operation='inputbyte2 low8RMW,preservehigh8'),hex(scalar_addresses[2]):dict(entry='0x309228',operation='storeargument0low16'),hex(scalar_addresses[3]):dict(entry='0x30923c',operation='storeargument0low16'),hex(scalar_addresses[4]):dict(entry='0x309250',operation='argument0 low8RMW thenbit15setiffargument1nonzero,preservebits8..14')}
 result=dict(status='PASS_FFC7000_ORIGINAL_TABLE_TAIL_AUDIT',date='2026-10-25',checks=checks,completed_memory_events=1684,reads=reads,writes=writes,transfer_windows=windows,new_window_cells=127,scalar_addresses=list(map(hex,scalar_addresses)),scalar_operations=scalar_operations,scalar_events=96,window_events=1588,original_parameter_table=dict(address='0x354e50',bytes_hex=table.hex(),groups={k:list(v)for k,v in parameters.items()}),literal_bindings=bindings,aux_sr_records=aux,aux_unique_pcs=12,metamorphic_equivalences=2,parameterized_helper_domains_closed=False,skipped_destination='0xffc75cc',independently_redecoded_instructions={hex(pc):i for pc,i in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=d['limits']);a.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS24scenarios/1684events,13windows/127cells+5scalars;104SR/12PCs,original tables andinputloads audited')
if __name__=='__main__':main()
