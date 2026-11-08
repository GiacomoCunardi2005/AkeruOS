#!/usr/bin/env python3
"""Walk the original unrolled writer CFG and derive input-to-MMIO bit masks independently."""
import argparse,hashlib,json,re,struct
from pathlib import Path
from s33_run_gnu_arc700 import ROOT
from s33_verify_sensor_mmio_dialog import aligned_window

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);a=ap.parse_args();src=a.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FFC7000_BUFFER_WRITER';assert all(sha(Path(k))==v for k,v in d['input_hashes'].items());assert all(sha(src/k)==v for k,v in d['files'].items());p=d['payload'];body=Path(p['path']).read_bytes();fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';assert body==fw.read_bytes()[p['firmware_offset']:p['firmware_offset']+p['size']]
 inputs={str(q):sha(q)for q in[Path(__file__),fw,src/'verified_evidence.json',ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']};instructions={}
 def decode(pc):
  if pc in instructions:return instructions[pc]
  text=aligned_window(body,p['base'],pc,pc+10);line=next(x for x in text.splitlines()if re.match(r'\s*'+f'{pc:x}'+':',x));m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line);raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert raw==body[pc-p['base']:pc-p['base']+len(raw)];i=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=p['firmware_offset']+pc-p['base']);instructions[pc]=i;return i
 def pool(pc):return struct.unpack_from('<I',body,pc-p['base'])[0]
 def band(x,y):
  if isinstance(x,int)and isinstance(y,int):return(x&y)&0xffffffff
  if isinstance(x,int):x,y=y,x
  assert isinstance(x,dict)and isinstance(y,int),(x,y)
  return{k:mask&y for k,mask in x.items()if mask&y}
 def bor(x,y):
  assert isinstance(x,dict)and isinstance(y,dict),(x,y)
  keys=set(x)|set(y);return{k:x.get(k,0)|y.get(k,0)for k in keys}
 regs={'r0':0x700000,'r1':'unresolved_initial_argument1'};input_pcs={};read_pcs={};fields=[];pools=[];walk=[];seen=set();pc=0x308a74;tail_target=None
 def operand(s):return regs[s]if s.startswith('r')else int(s,0)&0xffffffff
 while 0x308a74<=pc<0x308ed4:
  assert pc not in seen;seen.add(pc);walk.append(hex(pc));i=decode(pc);op=i['opcode'];args=i['operands'].split('\t;')[0].strip();next_pc=pc+len(bytes.fromhex(i['bytes_hex']))
  if op in['push_s','nop_s']:pass
  elif op=='bl':assert int(re.search(r';(0x[0-9a-f]+)',i['operands'])[1],0)==0x33412c
  elif op in['b_s','b']:
   target=int(re.search(r';(0x[0-9a-f]+)',i['operands'])[1],0)
   if not 0x308a74<=target<0x308ed4:assert target==0x334194;tail_target=target;break
   next_pc=target
  elif op in['mov','mov_s']:
   dest,source=args.split(',');regs[dest]=operand(source)
  elif op=='ld_s':
   match=re.fullmatch(r'(r\d+),\[pcl,(0x[0-9a-f]+|\d+)\]',args);assert match;address=int(re.search(r';(0x[0-9a-f]+)',i['operands'])[1],0);regs[match[1]]=pool(address);pools.append(dict(pc=hex(pc),pool_address=hex(address),value=hex(pool(address))))
  elif op=='ldh.di':
   match=re.fullmatch(r'(r\d+),\[(r\d+)\]',args);assert match;address=regs[match[2]];assert isinstance(address,int)and 0xffc7000<=address<0xffc8000;regs[match[1]]={('old',address):65535};read_pcs[address]=pc
  elif op in['ldw_s','ldh']:
   match=re.fullmatch(r'(r\d+),\[(r\d+),(0x[0-9a-f]+|\d+)\]',args);assert match and regs[match[2]]==0x700000;offset=int(match[3],0);assert offset%2==0 and 0<=offset<=124;regs[match[1]]={('input',offset):65535};input_pcs[offset]=pc
  elif op in['and_s','or_s']:
   dest,left,right=args.split(',');regs[dest]=band(operand(left),operand(right))if op=='and_s'else bor(operand(left),operand(right))
  elif op=='extw_s':
   dest,source=args.split(',');regs[dest]=band(operand(source),65535)
  elif op=='bmsk_s':
   dest,source,n=args.split(',');regs[dest]=band(operand(source),(1<<(int(n,0)+1))-1)
  elif op=='sth.di':
   match=re.fullmatch(r'(r\d+),\[(r\d+)\]',args);assert match;address=regs[match[2]];expression=regs[match[1]];assert isinstance(expression,dict);iv=[(key,mask)for key,mask in expression.items()if key[0]=='input'];ov=[(key,mask)for key,mask in expression.items()if key[0]=='old'];assert len(iv)==1 and len(ov)<=1;offset=iv[0][0][1];mask=iv[0][1];assert mask in[0x1ff,65535];keep=ov[0][1]if ov else 0;assert keep==(~mask&65535)and (not ov or ov[0][0][1]==address);assert len(expression)==len(iv)+len(ov);fields.append(dict(address=address,read_pc=read_pcs[address],write_pc=pc,input_offset=offset,input_load_pc=input_pcs[offset],field_width_bits=mask.bit_length(),value_mask=mask,keep_mask=keep))
  else:raise AssertionError((hex(pc),i))
  pc=next_pc
 expected_cells=set(range(0xffc7124,0xffc717c,4))|set(range(0xffc7180,0xffc71c0,4));assert tail_target==0x334194 and len(fields)==38 and{f['address']for f in fields}==expected_cells and sum(f['field_width_bits']==9 for f in fields)==32;assert len(input_pcs)==38 and len(read_pcs)==38 and 0xffc717c not in read_pcs
 assert[{k:f[k]for k in['read_pc','write_pc','input_offset','field_width_bits','address']}for f in fields]==d['slots'];used_offsets={f['input_offset']for f in fields};assert used_offsets=={38,40,*range(50,114,2),118,120,122,124}
 checks=[];outputs={};reads=0;writes=0;aux_srs=[]
 for c in d['cases']:
  if not c['observer_enabled']:continue
  path=src/(c['name']+'.trace');err=src/(c['name']+'.stderr.log');inputs[str(path)]=sha(path);inputs[str(err)]=sha(err);assert path.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes();raw=(src/c['input_file']).read_bytes();assert len(raw)==126;state={int(k,0):struct.unpack_from('<H',bytes.fromhex(v['before']),int(k,0)%8)[0]for k,v in c['fixtures'].items()};expected=[]
  for f in fields:
   address=f['address'];value=struct.unpack_from('<H',raw,f['input_offset'])[0];result=(state[address]&f['keep_mask'])|(value&f['value_mask']);expected.extend([(f['read_pc'],'read',address,state[address]),(f['write_pc'],'write',address,result)]);state[address]=result
  captured=[json.loads(line.removeprefix('S33_MEM '))for line in err.read_text().splitlines()if line.startswith('S33_MEM ')];events=c['completed_memory_events'];assert len(captured)==2*len(events)and[e for e in captured if e['stage']=='result']==events
  for begin,end in zip(captured[::2],captured[1::2]):assert begin['stage']=='begin'and end['stage']=='result'and all(begin[k]==end[k]for k in['id','pc','operation','address','width_bytes'])
  assert[(e['pc'],e['operation'],e['address'],e['value'])for e in events]==expected;pcs={e['pc']for e in events};traced=[];loaded={}
  for line in path.read_text().splitlines():
   m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
   if m and int(m[1],16)in pcs:traced.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',int(m[3],16)&65535))
   m=re.match(r'0x([0-9a-f]+)\s+(ldw(?:_s)?)\s+.*? - .*?<- (0x[0-9a-f]+)',line)
   if m and int(m[1],16)in input_pcs.values():loaded[int(m[1],16)]=int(m[3],16)&65535
   if re.match(r'0x[0-9a-f]+\s+sr\s+',line):aux_srs.append(line)
  assert traced==[(e['pc'],e['operation'],e['value'])for e in events]and all(e['width_bytes']==2 for e in events);assert len(loaded)==38
  for offset,load_pc in input_pcs.items():assert loaded[load_pc]==struct.unpack_from('<H',raw,offset)[0]
  for key,f in c['fixtures'].items():
   address=int(key,0);before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes();offset=address%8;assert len(after)==8 and struct.unpack_from('<H',after,offset)[0]==state[address]and all(before[j]==after[j]for j in range(8)if j not in[offset,offset+1])
  assert c['exit_code']==0 and c['fault']is None and c['full_original_writer_completed'];outputs[c['pattern']]=[(e['address'],e['value'])for e in events if e['operation']=='write'];reads+=sum(e['operation']=='read'for e in events);writes+=sum(e['operation']=='write'for e in events);checks.append(dict(case=c['name'],events=len(events)))
 assert len(checks)==8 and reads==304 and writes==304 and not aux_srs;assert outputs[2]==outputs[3]==outputs[4]==outputs[6]==outputs[7]and len(d['pairs'])==8 and all(x['trace_identical']for x in d['pairs']);assert all(sha(Path(k))==v for k,v in inputs.items())
 windows=[]
 for name,base,count in[('ffc7000_buffer_low',0xffc7124,22),('ffc7000_buffer_high',0xffc7180,16)]:
  selected=[dict(f,address=hex(f['address']),read_pc=hex(f['read_pc']),write_pc=hex(f['write_pc']),input_load_pc=hex(f['input_load_pc']),value_mask=hex(f['value_mask']),keep_mask=hex(f['keep_mask']))for f in fields if base<=f['address']<base+4*count];assert len(selected)==count;windows.append(dict(name=name,writer_entry='0x308a74',base=hex(base),element_count=count,stride_bytes=4,store_width_bits=16,access='read_modify_write_halfword_di',last_cell_address=hex(base+4*(count-1)),value_contract='Per-cell source_offset andkeep/value masks;includes raw16 andlow9fields',write_strategy='unrolled_fixed_literal_destinations',ordered_fields=selected,physical_kind='unknown_register_array_or_memory_aperture',concrete_control_registers_admitted_from_window_cells=0,hardware_verified=False))
 result=dict(status='PASS_FFC7000_BUFFER_CFG_DATAFLOW_AUDIT',date='2026-10-25',checks=checks,writer_entry='0x308a74',static_body_walk=walk,static_tail_target=hex(tail_target),literal_pools=pools,derived_fields=fields,transfer_windows=windows,computed_scalar_register_admissions=0,completed_memory_events=reads+writes,reads=reads,writes=writes,transfer_cell_count=38,low9_fields=32,full16_fields=6,input_used_halfword_offsets=sorted(used_offsets),input_ignored_halfword_offsets=sorted(set(range(0,126,2))-used_offsets),unwritten_between_ranges='0xffc717c',metamorphic_equivalences=4,new_aux_sr_sites=0,independently_redecoded_instructions={hex(pc):i for pc,i in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=d['limits']+['CFG walker skips the known shared save helper33412C and stops at shared return334194;runtime executes both unchanged.']);a.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS full straight-line CFG/dataflow,38cells/32low9+6full16,608events,4equivalences;no scalar admissions')
if __name__=='__main__':main()
