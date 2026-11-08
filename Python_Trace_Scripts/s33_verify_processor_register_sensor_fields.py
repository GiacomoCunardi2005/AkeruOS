"""Verify sensor register corrections against original aligned ARC instructions."""
import sys,json,hashlib,struct,re,argparse
from datetime import datetime, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'Python_Trace_Scripts'))
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path)
args=parser.parse_args()
OUT=args.output or ROOT/'Risultati/Processor_Registers'/('sensor_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
OUT.mkdir(parents=True,exist_ok=False)
from s33_verify_sensor_mmio_dialog import aligned_window
manifest=json.loads((ROOT/'S33-sections/TBM_blocks/manifest.json').read_text()); p=ROOT/'S33-sections/TBM_blocks'/manifest[2]['file']; b=p.read_bytes(); base=manifest[2]['load_address_candidate']; assert hashlib.sha256(b).hexdigest()==manifest[2]['sha256']
spans=[(0x60edec,0x60edf8),(0x60edfc,0x60ee7c),(0x60ee7c,0x60ee84),(0x60ee88,0x60ee94),(0x60ee94,0x60ee9c),(0x60eea0,0x60eeca),(0x60eed0,0x60eee0),(0x60eee4,0x60ef30),(0x60ef34,0x60efa4),(0x6515c4,0x6515d4),(0x6515dc,0x6515e8),(0x6515ec,0x65160c),(0x651610,0x651622)]
texts=[aligned_window(b,base,lo,hi)for lo,hi in spans];joined='\n\n'.join(texts); (OUT/'sensor_aligned_audit.txt').write_text(joined+'\n')
ins={}
for line in joined.splitlines():
 m=re.match(r'\s*([a-f0-9]+):\s+(?:[a-f0-9]{4}\s+)+\t([^\t]+)\t(.*)',line)
 if m:ins[int(m.group(1),16)]=(m.group(2),m.group(3).split('\t')[0])
checks=[]
def check(pc,op,args):
 assert ins[pc]==(op,args),(hex(pc),ins.get(pc),(op,args))
 checks.append({'pc':f'0x{pc:08X}','opcode':op,'operands':args,'bytes':b[pc-base:pc-base+(2 if op.endswith('_s') else 4)].hex()})
def pool(pc,val):
 assert struct.unpack_from('<I',b,pc-base)[0]==val;checks.append({'pool':f'0x{pc:08X}','value':f'0x{val:08X}'})
for pc,val in [(0x60edf8,0xff98074),(0x60ee84,0xff98000),(0x60ee9c,0xff98018),(0x60eee0,0xff98074),(0x60ef30,0xff98000),(0x6515c0,0xfef014c),(0x6515d8,0xfef014c),(0x6515e8,0xfe800f4),(0x65160c,0xfe800f4)]:pool(pc,val)
for pc,reg,bit in [(0x60edf4,'r13',8),(0x60ee14,'r13',2),(0x60ee2e,'r13',3),(0x60ee48,'r13',6),(0x60ee62,'r13',7),(0x60eeda,'r0',8),(0x60eef0,'r0',2),(0x60eefe,'r0',3),(0x60ef0c,'r0',6),(0x60ef1a,'r0',7)]:check(pc,'mov_s',f'{reg},0x{bit:x}')
for pc in [0x60ee00,0x60ee1a,0x60ee34,0x60ee4e,0x60ee68]:check(pc,'bset','r10,r10,r13')
for pc in [0x60ee0c,0x60ee26,0x60ee40,0x60ee5a,0x60ee74]:check(pc,'bclr','r10,r10,r13')
for pc in [0x60eee8,0x60eef6,0x60ef04,0x60ef12,0x60ef20]:check(pc,'bset','r10,r10,r0')
check(0x60ee7e,'mov_s','r0,0');check(0x60ee8c,'bclr','r10,r10,r0');check(0x60ee96,'mov_s','r0,0x1');check(0x60eea4,'mov_s','r0,0x80');check(0x60eeaa,'mov','r0,256');check(0x60eeb2,'mov','r0,512');check(0x60eebc,'bset_s','r0,r0,0xb');check(0x60eec4,'bset_s','r0,r0,0xc')
for pc in [0x60eea0,0x60eea6,0x60eeae,0x60eeb6,0x60eebe,0x60eec6]:check(pc,'sth.di','r0,[r13]')
check(0x60ef2a,'mov_s','r0,0');check(0x60ef38,'bset','r10,r10,r0')
for pc,bit in [(0x60ef40,10),(0x60ef4e,12),(0x60ef5c,8),(0x60ef6a,9),(0x60ef78,11),(0x60ef86,13),(0x60ef94,14)]:check(pc,'mov_s',f'r0,0x{bit:x}')
check(0x60ef9e,'sth.di','r10,[r14]')
check(0x6515e2,'mov_s','r0,0x4');check(0x6515f0,'bclr','r10,r10,r0');check(0x651614,'mov_s','r0,0x4');check(0x65161a,'bclr','r10,r10,r0');check(0x6515fc,'and','r0,r0,-16');check(0x651600,'bmsk','r14,r20,0x3');check(0x6515c8,'and','r0,r0,-4');check(0x6515cc,'bmsk','r1,r13,0x1')
f={'date':'2026-10-24','method':'GNU static windows re-aligned after every pool; bytes from existing hash-verified payload2; no firmware execution or hardware','status':'PASS','checks':checks,'payload':str(p),'payload_sha256':hashlib.sha256(b).hexdigest(),'disassembly':str((OUT/'sensor_aligned_audit.txt').resolve()),'disassembly_sha256':hashlib.sha256(joined.encode()+b'\n').hexdigest(),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'tools_sha256':{str(ROOT/'work/build-arc/binutils'/x):hashlib.sha256((ROOT/'work/build-arc/binutils'/x).read_bytes()).hexdigest()for x in ['objcopy','objdump']}}
(OUT/'sensor_aligned_audit.json').write_text(json.dumps(f,indent=2)+'\n'); print(f'PASS {len(checks)} exact instruction/pool checks; {OUT}')
