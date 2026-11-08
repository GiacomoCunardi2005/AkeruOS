#!/usr/bin/env python3
"""Audit formulas independently; forbid register admission from unbounded examples."""
import argparse,hashlib,json,re,struct
from pathlib import Path
from s33_run_gnu_arc700 import ROOT
from s33_verify_sensor_mmio_dialog import aligned_window

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def sx32(n):return(n^0x80000000)-0x80000000

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('--census',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args();src=args.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FE6_INDEXED_FAMILIES_SEPARATE_ADMISSION'
 assert all(sha(Path(p))==h for p,h in d['input_hashes'].items());assert all(sha(src/p)==h for p,h in d['files'].items());assert json.loads(args.census.read_text())==json.loads((src/'caller_census.json').read_text());info=d['payload'];fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';body=Path(info['path']).read_bytes();assert body==fw.read_bytes()[info['firmware_offset']:info['firmware_offset']+info['size']]
 paths=[Path(__file__),fw,src/'verified_evidence.json',args.census.resolve(),ROOT/'Python_Trace_Scripts/s33_census_fe6_indexed_callers.py',ROOT/'Python_Trace_Scripts/s33_verify_custom_aux_cfg.py',ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy'];inputs={str(p):sha(p)for p in paths};instructions={}
 def decode(pc):
  if pc in instructions:return instructions[pc]
  text=aligned_window(body,info['base'],pc,pc+8);m=next(re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',s)for s in text.splitlines()if re.match(r'\s*'+f'{pc:x}'+r':',s));raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert body[pc-info['base']:pc-info['base']+len(raw)]==raw
  i=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=info['firmware_offset']+pc-info['base']);instructions[pc]=i;return i
 for pc,op,arg in[(0x2c6b76,'cmp_s','r2,0x1'),(0x2c6b78,'mov_s','r2,0x1'),(0x2c6b7a,'sub.eq','r2,r2,r2'),(0x2c6b7e,'asl_s','r2,r2,0xf'),(0x2c6b80,'bmsk_s','r3,r3,0xb'),(0x2c6b82,'cmp_s','r0,0'),(0x2c6b8e,'add2_s','r0,r0,r1'),(0x2c6c72,'cmp_s','r2,0x1'),(0x2c6c74,'mov_s','r2,0x1'),(0x2c6c76,'sub.eq','r2,r2,r2'),(0x2c6c7a,'asl_s','r2,r2,0xf'),(0x2c6c7c,'bmsk_s','r3,r3,0xb'),(0x2c6c7e,'cmp_s','r0,0x2'),(0x2c6c86,'asl_s','r0,r0,0x8'),(0x2c6c88,'add_s','r0,r0,0xfe648d0'),(0x2c6c8e,'add2_s','r0,r0,r1'),(0x2c6c2e,'and','r0,r0,0x10')]:assert decode(pc)['opcode']==op and decode(pc)['operands']==arg
 for pool,value in[(0x2c6b94,0xfe64680),(0x2c6b98,0xfe646d0)]:assert struct.unpack_from('<I',body,pool-info['base'])[0]==value
 nominal={0xfe648c0+256*s+o for s in[0,1,2]for o in[0,4]};checks=[];counts={'nominal_control':0,'structural_family_examples':0,'signed_alias':0};seen=set();candidate_seen=set();attempts=[]
 for c in d['cases']:
  if not c['observer_enabled']:continue
  ev=c['completed_memory_events'];pcs={e['pc']for e in ev};path=src/(c['name']+'.trace');inputs[str(path)]=sha(path);rows=[]
  for line in path.read_text().splitlines():
   m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
   if m and int(m[1],16)in pcs:rows.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',int(m[3],16)&65535))
  assert len(rows)==len(ev)
  for row,e in zip(rows,ev):
   assert row==(e['pc'],e['operation'],e['value'])and e['width_bytes']==2;assert decode(e['pc'])['opcode']==('ldh.di'if e['operation']=='read'else'sth.di')
   if c['scope_kind']=='structural_family_examples':candidate_seen.add(e['address'])
   else:assert e['address']in nominal;seen.add(e['address'])
  assert path.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes()
  if c['scope_kind']=='structural_family_examples':
   calculated=[]
   for call in c['original_calls']:
    entry=int(call['entry'],0);s,i,flag,value=map(lambda x:int(x,0),call['arguments']);word=((0 if flag==1 else 1)<<15)|(value&0xfff)
    if entry==0x2c6b74:base=0xfe64680 if s==0 else 0xfe646d0;pc=0x2c6b9c
    else:
     assert entry==0x2c6c70
     if sx32(s)>2:continue
     base=0xfe648d0+256*s;pc=0x2c6c90
    calculated.append((pc,'write',(base+4*i)&0xffffffff,word))
   assert [(e['pc'],e['operation'],e['address'],e['value'])for e in ev]==calculated and len(ev)==84
  if c['scope_kind']=='incomplete_attempt':
   assert c['exit_code']==11 and not ev and not c['full_selected_paths_completed'];attempts.extend(c['attempts_without_result']);assert len(c['attempts_without_result'])==1 and c['attempts_without_result'][0]['address']==0xfe647c0
  else:assert c['exit_code']==0 and c['full_selected_paths_completed'];counts[c['scope_kind']]+=len(ev)
  checks.append(dict(case=c['name'],scope_kind=c['scope_kind'],events=len(ev),attempts_without_result=len(c['attempts_without_result'])))
 assert len(checks)==6 and counts==dict(nominal_control=114,structural_family_examples=84,signed_alias=12)and seen==nominal and len(candidate_seen)==18 and not candidate_seen&nominal
 families=[dict(entry='0x2c6b74',kind='computed_store_family_unresolved_caller_indices',address_expression='uint32((r0==0 ? 0x0FE64680 : 0x0FE646D0) + uint32(4*r1))',value_expression='uint16(((r2==1 ? 0 : 1)<<15) | (r3&0xFFF))',software_guard='none; r0==0 selects first base, any nonzero selects second',caller_index_domain='unknown; r1 has no local bound',concrete_registers_admitted=0,hardware_verified=False),dict(entry='0x2c6c70',kind='computed_store_family_unresolved_caller_indices',address_expression='uint32(0x0FE648D0 + uint32(256*r0) + uint32(4*r1))',value_expression='uint16(((r2==1 ? 0 : 1)<<15) | (r3&0xFFF))',software_guard='signed32(r0)<=2; no lower bound; signed32(r0)>2 returns without store',caller_index_domain='unknown; r1 has no local bound',concrete_registers_admitted=0,hardware_verified=False)]
 result=dict(status='PASS_FE6_INDEXED_FAMILY_FORMULA_SCOPE_AUDIT',date='2026-10-25',checks=checks,counts=counts,nominal_addresses=list(map(hex,sorted(nominal))),family_example_addresses_not_admitted=list(map(hex,sorted(candidate_seen))),incomplete_attempts_not_admitted=attempts,computed_mmio_families=families,caller_census_reproduced_exactly=True,independently_redecoded_instructions={hex(pc):i for pc,i in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=['Formula/range and sampled CPU evidence, not physical implementation or full caller reachability.','Caller census checks BL and exact pointers in16payloads; computed references and tail branches remain unresolved.','Unbounded indices can target other virtual ranges; these expressions do not define a physical register bank.'])
 assert all(sha(Path(p))==h for p,h in inputs.items());args.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS6 nominal cells,2parametric formulas,84example stores not admitted,6identical pairs')
if __name__=='__main__':main()
