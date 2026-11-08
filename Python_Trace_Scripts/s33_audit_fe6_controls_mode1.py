#!/usr/bin/env python3
"""Audit nominal FE6 addresses separately from signed-alias and incomplete accesses."""
import argparse,hashlib,json,re,struct
from pathlib import Path
from s33_run_gnu_arc700 import ROOT
from s33_verify_sensor_mmio_dialog import aligned_window

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);args=ap.parse_args();src=args.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FE6_CONTROLS_MODE1_AND_SIGNED_BOUNDARY'
 assert all(sha(Path(p))==h for p,h in d['input_hashes'].items());assert all(sha(src/p)==h for p,h in d['files'].items());info=d['payload'];fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';body=Path(info['path']).read_bytes();assert body==fw.read_bytes()[info['firmware_offset']:info['firmware_offset']+info['size']]
 inputs={str(p):sha(p)for p in[Path(__file__),fw,src/'verified_evidence.json',ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']};instructions={}
 def decode(pc):
  if pc in instructions:return instructions[pc]
  text=aligned_window(body,info['base'],pc,pc+8);m=next(re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',s)for s in text.splitlines()if re.match(r'\s*'+f'{pc:x}'+r':',s));raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert body[pc-info['base']:pc-info['base']+len(raw)]==raw
  i=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=info['firmware_offset']+pc-info['base']);instructions[pc]=i;return i
 for pc,op,arg in[(0x2c694e,'cmp_s','r0,0x2'),(0x2c6954,'asl_s','r0,r0,0x5'),(0x2c6956,'add_s','r0,r0,0xfe64600'),(0x2c6a54,'and','r0,r0,0x10'),(0x2c6b08,'bmsk_s','r0,r0,0xe'),(0x2c6cac,'cmp_s','r14,0x18'),(0x2c6cfc,'cmp_s','r14,0xc')]:assert decode(pc)['opcode']==op and decode(pc)['operands']==arg
 assert decode(0x2c6950)['opcode']=='bgt';assert decode(0x2c6cae)['opcode']=='blo_s'and decode(0x2c6cfe)['opcode']=='blo_s'
 for pool,value in[(0x2c6998,0xfe646c0),(0x2c6a4c,0xfe646c8),(0x2c6af0,0xfe646c4),(0x2c6cc0,0xfe60100),(0x2c6d10,0xfe64000)]:assert struct.unpack_from('<I',body,pool-info['base'])[0]==value
 controls={b+o for b in[0xfe64600,0xfe64620,0xfe64640,0xfe646c0]for o in[0,4,8]};arrays={0xfe60100+4*s for s in range(24)}|{0xfe64000+4*s for s in range(12)};nominal=controls|arrays;assert len(nominal)==48
 checks=[];total=0;nominal_events=0;alias_events=0;attempts=[];nominal_seen=set()
 for c in d['cases']:
  if not c['observer_enabled']:continue
  ev=c['completed_memory_events'];pcs={e['pc']for e in ev};path=src/(c['name']+'.trace');inputs[str(path)]=sha(path);rows=[]
  for line in path.read_text().splitlines():
   m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
   if m and int(m[1],16)in pcs:rows.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',int(m[3],16)&65535))
  assert len(rows)==len(ev)
  for row,e in zip(rows,ev):
   assert row==(e['pc'],e['operation'],e['value'])and e['width_bytes']==2
   assert decode(e['pc'])['opcode']==('ldh.di'if e['operation']=='read'else'sth.di')and e['address']in nominal;total+=1
   if c['scope_kind']=='out_of_domain_alias':alias_events+=1
   else:nominal_seen.add(e['address']);nominal_events+=1
  assert path.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes()
  if c['scope_kind']=='out_of_domain_fault':
   assert c['exit_code']==11 and not ev and not c['full_selected_paths_completed'];assert len(c['attempts_without_result'])==1;e=c['attempts_without_result'][0]
   assert e['stage']=='begin'and e['operation']=='read'and e['pc']==0x2c6964 and e['address']not in nominal
   selector=int(c['original_calls'][0]['arguments'][0],0);assert e['address']==(0xfe64600+((selector<<5)&0xffffffff))&0xffffffff;attempts.append(dict(case=c['name'],**e));assert decode(e['pc'])['opcode']=='ldh.di'
  else:assert c['exit_code']==0 and c['full_selected_paths_completed']
  if c['scope_kind']=='out_of_domain_alias':assert {e['address']for e in ev}=={0xfe64600,0xfe64620}and len(ev)==8
  if c['scenario']in['rejected_nonnegative','mode_gate2']:assert not ev
  checks.append(dict(case=c['name'],events=len(ev),attempts_without_result=len(c['attempts_without_result']),scope_kind=c['scope_kind'],full_selected_paths_completed=c['full_selected_paths_completed']))
 assert len(checks)==7 and total==728 and nominal_events==720 and alias_events==8 and nominal_seen==nominal
 assert {e['address']for e in attempts}=={0xfe645e0,0xfe64680}and len(attempts)==2
 assert len(d['pairs'])==7 and all(p['trace_identical']for p in d['pairs'])
 result=dict(status='PASS_FE6_CONTROLS_MODE1_BYTE_TRACE_SCOPE_AUDIT',date='2026-10-25',checks=checks,nominal_addresses=list(map(hex,sorted(nominal))),nominal_events=720,signed_alias_events=8,completed_memory_events=728,incomplete_attempts=attempts,independently_redecoded_instructions={hex(pc):i for pc,i in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=['Only nonnegative control branches0/1/2/4 and bounded arrays are admitted as nominal address evidence.','Signed-negative alias records are separate software-overflow observations; incomplete reads do not prove accessible or physical registers.','Unmapped faults are properties of the declared emulator model, not observed camera faults.'])
 assert all(sha(Path(p))==h for p,h in inputs.items());args.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS48nominal addresses,720nominal+8alias events,2incomplete attempts,7identical pairs')
if __name__=='__main__':main()
