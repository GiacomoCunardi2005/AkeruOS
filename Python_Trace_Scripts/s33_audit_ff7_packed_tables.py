#!/usr/bin/env python3
"""Independently audit original FF7 packing, raw observer streams and saved buffers."""
import argparse,hashlib,json,re,struct
from pathlib import Path
from s33_run_gnu_arc700 import ROOT
from s33_verify_sensor_mmio_dialog import aligned_window

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);args=ap.parse_args();src=args.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FF7_PACKED_TABLES'and d['capture_streams_separate']
 assert all(sha(Path(p))==h for p,h in d['input_hashes'].items());assert all(sha(src/p)==h for p,h in d['files'].items());info=d['payload'];body=Path(info['path']).read_bytes();fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';assert fw.read_bytes()[info['firmware_offset']:info['firmware_offset']+len(body)]==body
 inputs={str(p):sha(p)for p in[Path(__file__),src/'verified_evidence.json',fw,ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']};decoded={}
 def decode(pc):
  if pc in decoded:return decoded[pc]
  text=aligned_window(body,info['base'],pc,pc+8);m=next(re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)for line in text.splitlines()if re.match(r'\s*'+f'{pc:x}'+':',line));raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert raw==body[pc-info['base']:pc-info['base']+len(raw)];decoded[pc]=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=info['firmware_offset']+pc-info['base']);return decoded[pc]
 definitions=[(0x2e06f0,'masked7',0xff74044,[0xff74088]),(0x2e0774,'masked7',0xff7408c,[0xff740d0]),(0x2e0884,'strided_bytes',0xff740f0,[0xff74138,0xff74134]),(0x2e0908,'contiguous_bytes',0xff740f0,[0xff74138,0xff74134]),(0x2e098c,'strided_bytes',0xff7413c,[0xff74184,0xff74180]),(0x2e0a10,'contiguous_bytes',0xff7413c,[0xff74184,0xff74180]),(0x2e0a94,'strided_bytes',0xff74188,[0xff741d0,0xff741cc]),(0x2e0b18,'contiguous_bytes',0xff74188,[0xff741d0,0xff741cc])];defs={a:(mode,base,tails)for a,mode,base,tails in definitions};specs={s['entry']:s for s in d['specs']}
 for entry,(mode,base,tails)in defs.items():
  s=specs[entry];assert(s['mode'],s['base'],s['tails'])==(mode,base,tails);masked=mode=='masked7';store=entry+(0x5c if masked else 0x58);assert s['store_pc']==store and decode(store)['opcode']=='sth.di'
  for pc,count in[(entry+(0x10 if masked else 0xe),16),(entry+(0x32 if masked else 0x2c),17)]:assert decode(pc)['opcode']=='mov'and decode(pc)['operands']=='lp_count,'+hex(count)
  b=decode(entry+(0x4c if masked else 0x46));assert b['opcode']=='add_s'and b['operands']=='r0,r0,'+hex(base)
  last=decode(entry+(0x2c if masked else 0x26));assert last['opcode']==('ldb'if mode=='contiguous_bytes'else'ldh')
  if masked:
   for pc in[entry+0x20,entry+0x22]:assert decode(pc)['opcode']=='bmsk_s'and decode(pc)['operands'].endswith(',0x6')
  else:
   first=decode(entry+0x18);assert first['opcode']=='ldb_s'and first['operands']==('r13,[r3,0x1]'if mode=='contiguous_bytes'else'r13,[r3,0x2]')
 checks=[];windows=set();scalars=set();total=0;window_events=0;scalar_events=0
 for c in d['cases']:
  if not c['observer_enabled']:continue
  assert c['exit_code']==0 and c['fault']is None and c['full_original_calls_completed'];trace=src/(c['name']+'.trace');err=src/(c['name']+'.stderr.log');ref=src/(c['name'].replace('_observed','_reference')+'.trace');inputs[str(trace)]=sha(trace);inputs[str(err)]=sha(err);assert trace.read_bytes()==ref.read_bytes()
  raw_events=[json.loads(line.removeprefix('S33_MEM '))for line in err.read_text().splitlines()if line.startswith('S33_MEM ')];events=[e for e in raw_events if e['stage']=='result'];assert events==c['completed_memory_events']and len(raw_events)==2*len(events)
  state={int(a,0):struct.unpack_from('<H',bytes.fromhex(f['before']),int(a,0)%8)[0]for a,f in c['fixtures'].items()};expected=[]
  for call in c['original_calls']:
   entry=call['entry'];a=call['arguments']
   if entry in defs:
    mode,base,tails=defs[entry];raw=(src/c['input_buffers'][str(a[0])]['file']).read_bytes();values=[]
    for i in range(16):
     if mode=='masked7':lo=int.from_bytes(raw[i*4:i*4+2],'little')%128;hi=int.from_bytes(raw[i*4+2:i*4+4],'little')%128
     elif mode=='strided_bytes':lo,hi=raw[i*4],raw[i*4+2]
     else:lo,hi=raw[i*2],raw[i*2+1]
     values.append(lo+256*hi)
    values.append(raw[32]if mode=='contiguous_bytes'else int.from_bytes(raw[64:66],'little'));pc=entry+(0x5c if mode=='masked7'else 0x58)
    expected.extend((pc,'write',base+4*i,v)for i,v in enumerate(values));windows.update(base+4*i for i in range(17));window_events+=17
    if mode=='masked7':tail_values=[((a[1]*1024)|a[2])%65536];tail_pcs=[entry+0x78]
    else:tail_values=[a[2]%65536,a[1]%65536];tail_pcs=[entry+0x6c,entry+0x78]
    expected.extend((p,'write',t,v)for p,t,v in zip(tail_pcs,tails,tail_values));scalars.update(tails);scalar_events+=len(tails)
   elif entry in[0x2e0600,0x2e0634]:
    bit=5 if entry==0x2e0600 else 6;address=0xff74000;old=state[address];v=(old|2**bit)if a[0]==1 else(old&~(2**bit));pc=entry+(20 if a[0]==1 else 36);expected.extend([(pc,'read',address,old),(pc+8,'write',address,v)]);state[address]=v;scalars.add(address);scalar_events+=2
   elif entry==0x2e0668:
    expected.extend((pc,'write',address,v%65536)for pc,address,v in zip([0x2e067c,0x2e0688,0x2e0694,0x2e06a0],range(0xff74004,0xff74014,4),a));scalars.update(range(0xff74004,0xff74014,4));scalar_events+=4
   elif entry in[0x2e06a8,0x2e06c0,0x2e06d8]:
    address=0xff74014+4*[0x2e06a8,0x2e06c0,0x2e06d8].index(entry);expected.append((entry+16,'write',address,(a[0]|a[1]*16)%65536));scalars.add(address);scalar_events+=1
   else:
    assert entry in range(0x2e07f8,0x2e0884,20);address=0xff740d4+4*((entry-0x2e07f8)//20);expected.append((entry+12,'write',address,a[0]%65536));scalars.add(address);scalar_events+=1
  assert[(e['pc'],e['operation'],e['address'],e['value'])for e in events]==expected
  pcs={e['pc']for e in events};rows=[]
  for line in trace.read_text().splitlines():
   m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
   if m and int(m[1],16)in pcs:rows.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',int(m[3],16)&65535))
  assert rows==[(e['pc'],e['operation'],e['value'])for e in events]
  for e in events:
   assert e['width_bytes']==2 and decode(e['pc'])['opcode']==('ldh.di'if e['operation']=='read'else'sth.di')
   if e['operation']=='write':state[e['address']]=e['value']
  for address,f in c['fixtures'].items():
   address=int(address,0);before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes();assert len(after)==8 and struct.unpack_from('<H',after,address%8)[0]==state[address];assert all(before[j]==after[j]for j in range(8)if j not in[address%8,address%8+1])
  for buf in c['input_buffers'].values():assert(src/buf['file']).read_bytes()==bytes.fromhex(buf['bytes'])
  checks.append(dict(case=c['name'],events=len(events),calls=len(c['original_calls'])));total+=len(events)
 assert len(checks)==34 and total==678 and len(windows)==85 and len(scalars)==23 and window_events==544 and scalar_events==134;assert len(d['pairs'])==34 and all(p['trace_identical']for p in d['pairs'])
 regions=[]
 for base in sorted({b for _,_,b,_ in definitions}):
  writers=[dict(entry=hex(entry),mode=mode)for entry,mode,b,_ in definitions if b==base];regions.append(dict(name='ff7_packed_'+f'{base:x}',base=hex(base),element_count=17,stride_bytes=4,store_width_bits=16,last_cell_address=hex(base+64),writer_variants=writers,physical_kind='unknown_register_array_or_memory_aperture',concrete_control_registers_admitted_from_window_cells=0,hardware_verified=False))
 result=dict(status='PASS_FF7_PACKED_TABLES_AUDIT',date='2026-10-25',checks=checks,transfer_windows=regions,scalar_addresses=list(map(hex,sorted(scalars))),window_cell_addresses_count=85,completed_memory_events=total,scalar_events=scalar_events,window_write_events=window_events,instructions={hex(pc):i for pc,i in decoded.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=d['limits']);assert all(sha(Path(p))==h for p,h in inputs.items());args.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS34scenarios,678events,5windows/85cells,23scalar addresses including existing control')
if __name__=='__main__':main()
