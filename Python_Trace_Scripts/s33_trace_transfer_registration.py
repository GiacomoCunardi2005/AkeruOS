#!/usr/bin/env python3
"""Offline S33 V1.1 transfer handler registration and buffer address programming."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[(0x16DD36,0x16DD58,'Register2001Handler'),
 (0x16DE54,0x16DE7C,'Register0402HandlerAndEnable'),
 (0x266030,0x26605C,'DedicatedRegistrationSlots'),
 (0x16D8DA,0x16D8F0,'Select0400Group'),
 (0x16D97A,0x16D9AE,'FindIDAndStoreHandler'),
 (0x2640E6,0x264166,'MaskGatedDispatch'),
 (0x26417E,0x26418E,'DispatchNextRow'),
 (0x266FC8,0x267014,'PrepareTransferDimensions'),
 (0x26705C,0x267066,'BufferAddressLowHalf'),
 (0x26706C,0x26707A,'BufferAddressHighHalfAndMode')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/transfer_registration';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={1498488: 2525692, 1498784: 2522912, 2515164: 3584804, 2515168: 3584808, 2515172: 3584812, 1497908: 4344320, 2519128: 267257100, 2519144: 267257104}
 for a,v in literals.items():assert word(a)==v
 def raw1(a,n):
  o=a-info[1]['load_address_candidate'];assert 0<=o<=len(ps[1])-n
  return ps[1][o:o+n]
 assert raw1(0x424A00,12).hex()=='5000ef0f8000ef0f10000000'
 rows=[]
 for i in range(16):
  a=0x424A0C+8*i;d=raw1(a,8)
  ident,bit0,bit1,callback=struct.unpack('<HBBI',d)
  assert ident==0x410-i and callback==0
  rows.append(dict(index=i,record=hex(a),id=hex(ident),first_mask_bit=bit0,second_mask_bit=bit1,initial_callback=hex(callback)))
 assert rows[14]['id']=='0x402' and rows[14]['record']=='0x424a7c'
 assert rows[14]['first_mask_bit']==rows[14]['second_mask_bit']==1
 tools=ROOT/'work/build-arc/binutils';listings=[]
 with tempfile.TemporaryDirectory(prefix='s33-release-') as td:
  elf,back=Path(td)/'0.elf',Path(td)/'0.bin'
  run([tools/'objcopy','-I','binary','-O','elf32-littlearc','-B','arc',
   '--rename-section','.data=.text,alloc,load,readonly,code,contents',
   '--change-section-vma',f'.data={info[0]["load_address_candidate"]:#x}',
   '--strip-all',bd/info[0]['file'],elf])
  run([tools/'objcopy','--dump-section',f'.text={back}',elf]);assert back.read_bytes()==ps[0]
  for a,b,label in WINDOWS:
   t=run([tools/'objdump','-d','-m','arc:ARC700','-EL',f'--start-address={a:#x}',f'--stop-address={b:#x}',elf])
   assert 'out of bounds' not in t.lower(),label
   listings.append('WINDOW '+label+'\n'+t.replace(str(elf),'verified-block0.elf'))
 listing='\n'.join(listings)
 def line(a):
  hits=[l for l in listing.splitlines() if re.match(rf'^\s*{a:x}:',l)]
  assert len(hits)==1,(hex(a),hits)
  return hits[0]
 edges=[(1498426, 2514992), (1498438, 2514920), (1498710, 1497240), (1498726, 1497064), (1498736, 1498212), (1497310, 1497466), (2519026, 2630340)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={1498424: 'mov_s\tr0,0x1', 1498430: 'bset_s\tr0,r0,0xd', 1498714: 'mov\tr0,1026', 2514992: '0x2001', 2515002: 'st_s\tr1,[r0,0]', 1497498: 'add3\tr14,r13,r3', 1497502: 'ldh.di\tr2,[r14,12]', 1497510: 'st.di\tr1,[r14,16]', 2506982: '0x424a04', 2506998: '0x424a00', 2507014: '0x424a08', 2507042: 'bbit0', 2507050: 'bbit0', 2507054: 'ld.di\tr0,[r1,4]', 2507086: 'jl\t[r0]', 2507142: 'add\tr1,r1,0x8', 2518992: 'mov_s\tr13,r0', 2519054: 'extw_s\tr0,r13', 2519132: 'sth.di\tr0,[r1]', 2519138: 'lsr_s\tr13,r13,0x10', 2519148: 'sth.di\tr13,[r0]'}
 for a,n in checks.items():assert n in line(a),line(a)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  handler_table=dict(base='0x424a00',record_stride=8,first_register_ptr='0x0fef0050',second_register_ptr='0x0fef0080',rows=rows,
   selected_callback_cell='0x424a80',selected_handler='0x267f20'),
  observations=['ID 0x0402 registration resolves to table entry 14 and callback word 0x424a80',
   'Mask-gated dispatcher checks record bit indices against two halfword MMIO reads before indirect call',
   'ID 0x2001 registration stores handler 0x2689fc in dedicated word 0x36b324',
   'Transfer helper writes low/high buffer halfwords to 0x0fee050c and 0x0fee0510'],
  limits=['Actual CPU vector and dedicated 0x2001 dispatcher remain unresolved',
   'Static registration does not prove runtime installation, enabled interrupt delivery or persistence'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
