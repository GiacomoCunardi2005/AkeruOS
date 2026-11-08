#!/usr/bin/env python3
"""Source-bind the next FF7 raw-loop candidates, keeping overlapping ranges explicit."""
import argparse,hashlib,json,re,struct
from pathlib import Path
from s33_verify_sensor_mmio_dialog import aligned_window
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--atlas',type=Path,required=True);ap.add_argument('--source',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();atlas=a.atlas.resolve();source=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
 d=json.loads((source/'verified_evidence.json').read_text());p=d['payload'];body=Path(p['path']).read_bytes();fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';assert sha(fw)==d['firmware_sha256'] and hashlib.sha256(body).hexdigest()==p['sha256'];assert fw.read_bytes()[p['firmware_offset']:p['firmware_offset']+len(body)]==body
 ledger=json.loads((atlas/'sha256.json').read_text());assert all(sha(atlas/k)==v for k,v in ledger.items());m=json.loads((atlas/'register_map.json').read_text());known={r['number']for r in m['records']if r['space']=='soc_mmio'};old_windows=m['mmio_transfer_windows'];instructions={}
 def decode(pc):
  if pc in instructions:return instructions[pc]
  s=aligned_window(body,p['base'],pc,pc+8);line=next(x for x in s.splitlines()if re.match(r'\s*'+f'{pc:x}'+':',x));match=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line);raw=b''.join(bytes.fromhex(w)[::-1]for w in match[2].split());assert body[pc-p['base']:pc-p['base']+len(raw)]==raw
  row=dict(opcode=match[3],operands=match[4].strip(),bytes_hex=raw.hex(),firmware_offset=p['firmware_offset']+pc-p['base']);instructions[pc]=row;return row
 specs=[(0x2e0f30,33,0xff741dc),(0x2e0f70,33,0xff74044),(0x2e0fb0,9,0xff74260),(0x2e0ff0,9,0xff74284),(0x2e10f0,9,0xff760d0),(0x2e1298,33,0xff76128),(0x2e12d8,17,0xff761ac)];rows=[]
 for entry,count,base in specs:
  extended=entry==0x2e10f0;delta=4 if extended else 0
  checks=[(entry,'push_s','blink'),(entry+6,'mov',f'lp_count,0x{count:x}'),(entry+0x10+delta,'sr','r12,[lp_end]'),(entry+0x16+delta,'sr','r12,[lp_start]'),(entry+0x1a+delta,'asl_s','r0,r13,0x2'),(entry+0x1c+delta,'ldw_s','r1,[r14,0]'),(entry+0x1e+delta,'add_s',f'r0,r0,0x{base:x}'),(entry+0x30+delta,'sth.di','r1,[r0]'),(entry+0x34+delta,'add_s','r14,r14,0x2'),(entry+0x36+delta,'add_s','r13,r13,0x1'),(entry+0x38+delta,'extw_s','r13,r13')]
  for pc,op,args in checks:
   actual=decode(pc);assert actual['opcode']==op and actual['operands']==args,(hex(pc),actual,op,args)
  lp_end,lp_start=struct.unpack_from('<II',body,entry+0x28+delta-p['base']);assert (lp_end,lp_start)==(entry+0x3a+delta,entry+0x1a+delta)
  if extended:
   assert struct.unpack_from('<I',body,0x2e1134-p['base'])[0]==0xff760f4 and struct.unpack_from('<I',body,0x2e1144-p['base'])[0]==0xff760f8
   for pc,operand in[(0x2e1138,'r15,[r0]'),(0x2e1148,'r0,[r1]')]:assert decode(pc)['opcode']=='sth.di' and decode(pc)['operands']==operand
  cells={base+4*i for i in range(count)};overlap=[]
  for w in old_windows:
   wc={int(w['base'],0)+int(w['stride_bytes'])*i for i in range(w['element_count'])};hit=sorted(cells&wc)
   if hit:overlap.append(dict(window=w['name'],cell_count=len(hit),addresses=list(map(hex,hit))))
  rows.append(dict(entry=hex(entry),element_count=count,base=hex(base),last_address=hex(base+4*(count-1)),store_pc=hex(entry+0x30+delta),input_element_bits=16,input_stride_bytes=2,output_stride_bytes=4,store_width_bits=16,lp_start=hex(lp_start),lp_end=hex(lp_end),existing_scalar_overlap=list(map(hex,sorted(cells&known))),existing_window_overlap=overlap,additional_tail_parameters_static=[hex(0xff760f4),hex(0xff760f8)]if extended else[],evidence_type='static_original_instruction_and_literal_bytes',runtime_verified=False,hardware_verified=False,admitted_as_independent_registers=0))
 result=dict(status='STATIC_SOURCE_BOUND_RAW_WINDOW_CANDIDATES_NOT_CPU_VERIFIED',date='2026-10-25',candidates=rows,decoded_instructions={hex(k):v for k,v in instructions.items()},firmware_sha256=sha(fw),payload=p,parent_atlas=str(atlas),parent_ledger_sha256=sha(atlas/'sha256.json'),parent_ledger_files_verified=len(ledger),input_sha256={str(Path(__file__).resolve()):sha(Path(__file__)),str(fw):sha(fw),str(Path(p['path'])):sha(Path(p['path'])),str(atlas/'register_map.json'):sha(atlas/'register_map.json')},limits=['Static loop metadata is not guest execution or physical register identification.','FF74044 raw33 writer overlaps prior packed windows and parameter FF74088: do not add all cells to register count or assume disjoint peripherals.','Loop setup and input halfword reads require CPU verification with original code and unchanged GNU before writer contracts are consolidated.','Seven candidates are a selected source range, not an exhaustive firmware/physical census.'],hardware_access=False,gnu_modified=False)
 (out/'candidates.json').write_text(json.dumps(result,indent=2)+'\n');print('PASS7static loops; FF74044 overlap preserved; no atlas count additions');print(out/'candidates.json')
if __name__=='__main__':main()
