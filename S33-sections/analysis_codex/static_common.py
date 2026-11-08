"""Read-only S33 analysis helpers. Only outputs under analysis_codex are written."""
from pathlib import Path
import sys,struct,hashlib,json,tempfile
ROOT=Path(__file__).resolve().parents[2]
OUT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'Python_Trace_Scripts'))
from s33_trace_state_dispatch import verified_payloads,run
BS,PS,BD=verified_payloads(ROOT)
INFO={b['index']:b for b in BS}
ORIGINAL=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin'
PATCHED=ROOT/'S33-sections/firmware_HIDDENMENU_RHIR_KHIR_OFFLINE_NOT_FLASH.bin'
EXPECTED='1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39'
def sha(data):return hashlib.sha256(data).hexdigest()
def locate(a,n=1):
 hits=[(b,a-b['load_address_candidate']) for b in BS if b['load_address_candidate']<=a and a+n<=b['load_address_candidate']+b['size']]
 if len(hits)!=1:raise ValueError((hex(a),n,'unmapped/overlay'))
 return hits[0]
def raw(a,n):b,o=locate(a,n);return PS[b['index']][o:o+n]
def u32(a):return struct.unpack('<I',raw(a,4))[0]
def u16(a):return struct.unpack('<H',raw(a,2))[0]
def cstring(a,maxlen=256):
 try:
  b,o=locate(a);d=PS[b['index']][o:o+maxlen];d=d.split(b'\0',1)[0]
  if not d or any(x<32 or x>126 for x in d):return None
  return d.decode('ascii')
 except ValueError:return None
def disasm(a,b):
 block,_=locate(a,b-a);tools=ROOT/'work/build-arc/binutils'
 with tempfile.TemporaryDirectory(prefix='hiddenmenu-static-') as td:
  elf,back=Path(td)/'block.elf',Path(td)/'back.bin'
  run([tools/'objcopy','-I','binary','-O','elf32-littlearc','-B','arc','--rename-section','.data=.text,alloc,load,readonly,code,contents','--change-section-vma',f'.data={block["load_address_candidate"]:#x}','--strip-all',BD/block['file'],elf])
  run([tools/'objcopy','--dump-section',f'.text={back}',elf]);assert back.read_bytes()==PS[block['index']]
  t=run([tools/'objdump','-d','-m','arc:ARC700','-EL',f'--start-address={a:#x}',f'--stop-address={b:#x}',elf])
  assert 'out of bounds' not in t.lower(),(hex(a),hex(b))
  return t.replace(str(elf),f'verified-block{block["index"]}.elf')
def save_disasm(a,b,label):
 t=disasm(a,b);(OUT/'evidence'/f'{a:08x}_{label}.txt').write_text(t);return t
