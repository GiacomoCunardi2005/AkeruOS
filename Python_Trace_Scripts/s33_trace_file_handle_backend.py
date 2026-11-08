#!/usr/bin/env python3
"""Offline logical-file handle mapping and filesystem backend selection."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0x1F35FC,0x1F3608,'BackendPredicate'),
 (0x1F3608,0x1F365C,'BackendSevenInitializer'),
 (0x1F48A4,0x1F48E8,'CloseBackendSelection'),
 (0x1F4958,0x1F49A4,'WriteBackendSelection'),
 (0x2A1344,0x2A1398,'ResolveFileAndPrivateContexts'),
 (0x2183C8,0x218410,'InitializeThirtyMappingRecords'),
 (0x218458,0x2184A4,'RegisterLogicalHandleMapping'),
 (0x2184A8,0x2184FC,'LookupLogicalHandle'),
 (0x218500,0x218550,'RemoveLogicalHandleMapping'),
 (0x21828C,0x2182F0,'RemoveMappingBeforeClose'),
 (0x336F3C,0x336F48,'FlagBitZeroHelper'),
 (0x336718,0x336762,'FlagAssignmentImplementation'),
 (0x1B904E,0x1B90DA,'DescriptorHandleOutputArgument'),
 (0x1872A0,0x1873AC,'HandleCreationWrapper'),
 (0x21AD30,0x21AE94,'NonSevenCloseBackend'),
 (0x2AC438,0x2AC494,'CloseMetadataService'),
 (0x2AC564,0x2AC584,'RemovePrivateFileRecord'),
]

def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/file_handle_backend';out.mkdir(parents=True,exist_ok=True)
 tools=ROOT/'work/build-arc/binutils'
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 assert word(0x218414)==0x4BD110
 assert word(0x218410)==0x3500A8
 assert word((0x2184B6&~3)-112*4)==0xF20010
 assert word(0x218550)==0xF20040
 assert 0x4BD110+30*12==0x4BD278
 template=struct.unpack_from('<III',ps[0],0x3500A8-info[0]['load_address_candidate'])
 listings=[]
 with tempfile.TemporaryDirectory(prefix='s33-handle-') as td:
  elf,back=Path(td)/'0.elf',Path(td)/'0.bin'
  run([tools/'objcopy','-I','binary','-O','elf32-littlearc','-B','arc',
       '--rename-section','.data=.text,alloc,load,readonly,code,contents',
       '--change-section-vma',f'.data={info[0]["load_address_candidate"]:#x}',
       '--strip-all',bd/info[0]['file'],elf])
  run([tools/'objcopy','--dump-section',f'.text={back}',elf]);assert back.read_bytes()==ps[0]
  for a,b,label in WINDOWS:
   t=run([tools/'objdump','-d','-m','arc:ARC700','-EL',f'--start-address={a:#x}',f'--stop-address={b:#x}',elf])
   assert 'out of bounds' not in t.lower(),label
   listings.append(f'WINDOW {label}\n'+t.replace(str(elf),'verified-block0.elf'))
 listing='\n'.join(listings)
 def line(a):
  hits=[l for l in listing.splitlines() if re.match(rf'^\s*{a:x}:',l)]
  assert len(hits)==1,(hex(a),hits)
  return hits[0]
 edges=[(0x1F48BC,0x1F35FC),(0x1F48C6,0x1F9258),(0x1F48D8,0x21AD30),
        (0x1F4966,0x1F35FC),(0x1F4974,0x1F94D4),(0x1F4994,0x21A4B8),
        (0x2182C0,0x2184A8),(0x2182CE,0x218500),(0x2182D4,0x12D604),
        (0x218488,0x336F3C),(0x218534,0x336F3C),(0x336F40,0x336718),
        (0x1B90B4,0x1872A0),(0x18736E,0xBFFF4),
        (0x21AE36,0x2AC438),(0x21AE80,0x2AC564)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={0x1F35FC:'r0,[r0,0x70]',0x1F35FE:'r0,0x7',0x1F3604:'sub_s.ne',
         0x1F364E:'st_s\tr0,[r15,0x70]',0x218482:'st_s\tr3,[r0,0x8]',
         0x218484:'st_s\tr13,[r0,0x4]',0x2184D0:'ld_s\tr14,[r0,0x4]',
         0x2184D8:'btst_s\tr14,0',0x2184E0:'st_s\tr0,[r1,0]',
         0x21852C:'st_s\tr1,[r0,0x4]',0x218530:'st_s\tr13,[r0,0x8]',
         0x1B90AC:'add3\tr3,r0,0x9',0x2A1364:'st_s\tr1,[r2,0]',
         0x2A136C:'ld_s\tr0,[r0,0x24]'}
 for a,needle in checks.items():assert needle in line(a),line(a)
 data=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  mapping=dict(base='0x4bd110',count=30,stride=12,end_exclusive='0x4bd278',
    fields={'0':'flags, bit 0 active','4':'logical key','8':'underlying file pointer'},template=[hex(n) for n in template],
    registration='0x218458',lookup='0x2184a8',removal='0x218500',
    close_order=['lookup','remove mapping','0x12d604 using local file pointer']),
  backend=dict(predicate='0x1f35fc',condition='private context +0x70 == 7',
    when_equal={'close':'0x1f9258','write':'0x1f94d4'},when_different={'close':'0x21ad30','write':'0x21a4b8'},
    selection_limit='Null file-private context takes another close path 0x1f46c4'),
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],
  observations=['Removal status is overwritten by 0x12d604 result; no local map rollback on close failure',
    '0x2a1344 resolves per-file state from file+4 and device-private context from (*file)+0x24',
    '0x1872a0 receives descriptor+0x48 as output, then passes it onward to 0xbfff4; creation chain below remains partial'],
  limits=['Does not establish active SD backend or runtime context value 7',
    'Logical key is used as lookup key, not established as a directly dereferenceable pointer',
    'Metadata service and private-record removal do not prove full SD synchronization',
    'No runtime firmware execution or V1.0 compatibility proof'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(data,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instruction checks; mapping template {template}')
if __name__=='__main__':main()
