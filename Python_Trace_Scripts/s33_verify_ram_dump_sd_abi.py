#!/usr/bin/env python3
"""Verify original V1.1 SD ABI and temporary-name routing; no hardware execution."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[(0x30017c,0x3001ce),(0x12dbfc,0x12dd24),(0x12de3c,0x12df00),
 (0x12ce8c,0x12d000),(0x12d604,0x12d6e8),(0x1f43ac,0x1f4482),
 (0x1f449a,0x1f4542),(0x1f4542,0x1f455c),(0x1f4574,0x1f46c2),
 (0x1f4258,0x1f4340),(0x2a1648,0x2a17dc),(0x2a17f4,0x2a1858),
 (0x2ac2b4,0x2ac438)]
def main():
 bs,p,bd=verified_payloads(ROOT);info={b['index']:b for b in bs};out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_ABI';out.mkdir(parents=True,exist_ok=True)
 def raw(a,n):
  for i,b in info.items():
   k=a-b['load_address_candidate']
   if 0<=k<=len(p[i])-n:return p[i][k:k+n]
  raise ValueError(hex(a))
 def word(a):return struct.unpack('<I',raw(a,4))[0]
 def string(a):return raw(a,80).split(b'\0')[0].decode()
 modes=word(0x12de34);assert raw(modes,10)==b'w\0w+\0n\0n+\0'
 tables={}
 for tb,expected in [(0x1f4482,{'a':0x1f44f4,'n':0x1f44d8,'r':0x1f44b8,'w':0x1f44d8,'x':0x1f449a}),(0x1f455c,{'a':0x1f45be,'n':0x1f45fc,'r':0x1f4586,'w':0x1f45a4,'x':0x1f4574})]:
  got={c:tb+2*struct.unpack('b',raw(tb+ord(c)-97,1))[0] for c in expected};assert got==expected;tables[hex(tb)]={c:hex(a) for c,a in got.items()}
 formats={hex(a):string(word(a)) for a in [0x2a17ec,0x2a17f0,0x1f4388,0x1f438c]}
 assert formats['0x2a17ec']==formats['0x1f4388']=='%sTMP%05.5lu.@@@'
 assert formats['0x2a17f0']==formats['0x1f438c']=='%s\\TMP%05.5lu.@@@'
 listings=[];tools=ROOT/'work/build-arc/binutils'
 with tempfile.TemporaryDirectory(prefix='s33-dump-sd-abi-') as td:
  elf=Path(td)/'p0.elf';back=Path(td)/'p0.bin';b=info[0]
  run([tools/'objcopy','-I','binary','-O','elf32-littlearc','-B','arc','--rename-section','.data=.text,alloc,load,readonly,code,contents','--change-section-vma',f'.data={b["load_address_candidate"]:#x}',bd/b['file'],elf])
  run([tools/'objcopy','--dump-section',f'.text={back}',elf]);assert back.read_bytes()==p[0]
  for a,z in WINDOWS:listings.append(run([tools/'objdump','-d','-m','arc:ARC700','-EL',f'--start-address={a:#x}',f'--stop-address={z:#x}',elf]).replace(str(elf),'verified-payload0.elf'))
 listing='\n'.join(listings)
 def line(a):
  hits=[s for s in listing.splitlines() if re.match(rf'^\s*{a:x}:',s)];assert len(hits)==1,(hex(a),hits);return hits[0]
 checks={0x300194:'mov_s\tr1,0x2',0x30019a:';12dbfc',0x3001b2:';12de3c',0x3001bc:';12d604',0x12dec6:';1fa090',0x12decc:'st_s\tr0,[r15,0]',0x12dee2:'cmp_s\tr2,r17',0x1f457c:';2a16f0',0x2a17ac:';12ce54',0x2a17c2:';2ac2b4',0x2a17d0:'0x1a00011',0x2a181a:';225618',0x2a16a2:'mov\tr6,0',0x2ac3a2:';2abcd4',0x2ac3c8:'cmp\tr19,0'}
 for a,v in checks.items():assert v in line(a),(hex(a),v,line(a))
 (out/'gnu_verified.txt').write_text(listing)
 result={'scope':'Static V1.1 original bytes only; no target/P-code execution','script_sha256':sha(Path(__file__).read_bytes()),'payload_sha256':{str(b['index']):b['sha256'] for b in bs},'window_count':len(WINDOWS),'instruction_checks':len(checks),'mode_tables':tables,'temporary_name_formats':formats,'abi':{'create_12dbfc':['r0 path','r1 1=w / 2=w+ / 3=n / other=n+','r2 pointer to file output','r0 return status (0 success)'],'write_12de3c':['r0 file','r1 buffer','r2 requested bytes','r3 selector (original dump passes0)','r4 pointer written count','r0 return status'],'dump_30017c':['r0 path','r1 buffer','r2 length','r3 pointer written count','r0 open/write status; close ignored']},'limits':['n/n+ are NOT validated exclusive; backend7 shares n and w','x auto-generates TMPnnnnn.@@@ names from a directory, not C11 exact-name exclusive mode','Atomic collision/create semantics below 2AC2B4 remain to verify','No binding ready for camera deployment; no live mounted-volume or persistence proof']}
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');print(f'PASS: 16 hashes, roundtrip payload0, {len(WINDOWS)} windows, {len(checks)} instruction checks, 2 mode tables, 4 formats')
if __name__=='__main__':main()
