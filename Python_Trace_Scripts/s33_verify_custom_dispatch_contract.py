#!/usr/bin/env python3
"""Verify explicit software bit/callback dependencies in original Main bytes."""
import argparse,hashlib,json,re,struct
from pathlib import Path
from s33_verify_sensor_mmio_dialog import ROOT,aligned_window


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--callback-evidence',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();cp=args.callback_evidence.resolve();cpu=json.loads(cp.read_text());out=args.output.resolve()
    assert cpu['status']=='PASS_REGISTER_DUAL_CALLBACK_AND_MODEL_BOUNDARY'
    source=ROOT/'S33-sections/TBM_blocks/block_00_type1_load_000ad800.bin';b=source.read_bytes();base=0xad800
    assert sha(source)==cpu['original_main_sha256']=='06754a1f451f17b3047fe03cdb83fd08af11dac725638818254ef0de26a5ed29'
    inputs={str(p):sha(p)for p in [source,cp,Path(__file__),ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']}
    rows={};listings=[]
    for name,a,z in [('bit_getters',0x342b40,0x342bd0),('dispatch',0x342eb0,0x342f18),('handler',0x3428b8,0x34294c)]:
        listing=aligned_window(b,base,a,z);listings.append(name+'\n'+listing)
        for line in listing.splitlines():
            m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)
            if not m:continue
            pc=int(m[1],16);raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert b[pc-base:pc-base+len(raw)]==raw
            target=re.search(r';0x([0-9a-f]+)',m[4])
            rows[pc]=dict(pc=hex(pc),opcode=m[3],operands=m[4].split(';')[0].strip(),target=int(target[1],16)if target else None,bytes_hex=raw.hex(),listing=line.strip())
    def expect(pc,op,operands=None,target=None):
        d=rows[pc];assert d['opcode']==op,(hex(pc),d)
        if operands is not None:assert d['operands']==operands,(hex(pc),d)
        if target is not None:assert d['target']==target,(hex(pc),d)
        return d
    getters=[0x342b40,0x342b4c,0x342b5c,0x342b6c,0x342b7c,0x342b8c,0x342b9c,0x342bac]
    for bit,g in enumerate(getters):
        expect(g,'lr','r0,[0x10001]')
        if bit:expect(g+8,'lsr_s','r0,r0'if bit==1 else f'r0,r0,{hex(bit)}')
        expect(g+(8 if bit==0 else 10),'j_s.d','[blink]')
        expect(g+(10 if bit==0 else 12),'bmsk_s','r0,r0,0')
    dispatch=[]
    blocks=[(0,0x342eb2,0x342eba,0x342f1c,0x342ebe,0x342eb8,0x342ec0),
            (1,0x342ec0,0x342ec8,0x342f18,0x342ecc,0x342ec6,0x342ece),
            (2,0x342ece,0x342ed6,0x342f20,0x342eda,0x342ed4,0x342edc),
            (3,0x342edc,0x342ee4,0x342f20,0x342ee8,0x342ee2,0x342eea),
            (4,0x342eea,0x342ef2,0x342f20,0x342ef6,0x342ef0,0x342ef8),
            (5,0x342ef8,0x342f00,0x342f20,0x342f04,0x342efe,0x342f06),
            (6,0x342f06,0x342f0e,0x342f20,0x342f12,0x342f0c,0x342f14)]
    for bit,call,load,pool,jump,branch,nxt in blocks:
        expect(call,'bl',target=getters[bit]);expect(call+4,'cmp_s','r0,0');expect(branch,'beq_s',target=nxt)
        expect(load,'ld_s',target=pool);expect(load+2,'ld_s','r0,[r0,0]');expect(jump,'jl_s','[r0]')
        slot=struct.unpack_from('<I',b,pool-base)[0];assert slot=={0:0x360ae0,1:0x360adc}.get(bit,0x360ad8)
        dispatch.append(dict(aux='0x10001',bit=bit,getter=hex(getters[bit]),caller=hex(call),pool=hex(pool),slot=hex(slot),
                             indirect_call=hex(jump),condition='extracted_bit_nonzero',null_check=False,physical_meaning='unknown'))
    assertions=[(0x3428ba,'lr','r0,[0x10111]'),(0x3428c2,'and','r0,r0,0x8000'),(0x3428ca,'lsr.f','0,r0,0xf'),
                (0x3428d0,'lr','r0,[0x10110]'),(0x3428d8,'and','r0,r0,0x2'),(0x3428dc,'lsr.f','0,r0'),
                (0x3428e2,'lr','r0,[0x10110]'),(0x3428ea,'bset_s','r0,r0,0x1'),(0x3428ec,'sr','r0,[0x10110]'),
                (0x3428f6,'mov_s','r0,0x1'),(0x3428f8,'stb_s','r0,[r1,0x5]'),(0x3428fa,'ld_s','r1,[r1,0]'),(0x3428fc,'cmp_s','r1,0'),(0x342900,'jl_s','[r1]'),
                (0x342902,'lr','r0,[0x10111]'),(0x34290a,'and','r0,r0,0x4000'),(0x342912,'lsr.f','0,r0,0xe'),
                (0x342918,'lr','r0,[0x10110]'),(0x342920,'btst_s','r0,0'),(0x342924,'lr','r0,[0x10110]'),
                (0x34292c,'bset_s','r0,r0,0'),(0x34292e,'sr','r0,[0x10110]'),(0x342938,'mov_s','r1,0x1'),
                (0x34293a,'stb_s','r1,[r0,0x4]'),(0x34293c,'ld_s','r1,[r0,0]'),(0x34293e,'cmp_s','r1,0'),(0x342942,'jl_s.d','[r1]'),(0x342944,'mov_s','r0,0')]
    for pc,op,args_text in assertions:expect(pc,op,args_text)
    for pc,target in [(0x3428ce,0x342902),(0x3428e0,0x342902),(0x3428fe,0x342902),
                       (0x342916,0x342946),(0x342922,0x342946),(0x342940,0x342946)]:expect(pc,'beq_s',target=target)
    for pc in [0x3428f4,0x342936]:expect(pc,'ld_s',target=0x342988)
    assert struct.unpack_from('<I',b,0x342988-base)[0]==0x360ad0
    branches=[dict(gate_aux='0x10111',gate_bit=15,status_aux='0x10110',status_bit=1,ram_flag='0x360ad5',callback_argument0=1),
              dict(gate_aux='0x10111',gate_bit=14,status_aux='0x10110',status_bit=0,ram_flag='0x360ad4',callback_argument0=0)]
    result=dict(status='PASS_STATIC_CUSTOM_DISPATCH_CONTRACT',date='2026-10-25',dispatch_bits=dispatch,
                handler_entry='0x3428b8',handler_slot='0x360ae0',user_callback_slot='0x360ad0',branches=branches,
                unreferenced_bit7_accessor=dict(entry='0x342bac',expression='(AUX10001>>7)&1',classification='structural_leaf_not_dispatch_or_caller_proof'),
                instructions={hex(k):v for k,v in rows.items()},input_sha256=inputs,hardware_access=False,
                limits=['All bit/callback dependencies are static software facts; CPU evidence covers registration and prefix only.',
                        'RMW writes do not establish W1C/acknowledgment, reset or other physical side effects.',
                        'Top dispatcher lacks a NULL check; user callback in the inner handler has one. No hardware safety/reachability inferred.',
                        'Bit7 has an adjacent getter but is not dispatched by the audited routine; no reserved-bit inference.'])
    assert all(sha(Path(p))==h for p,h in inputs.items())
    out.write_text(json.dumps(result,indent=2)+'\n');out.with_suffix('.txt').write_text('\n\n'.join(listings)+'\n')
    print('PASS7dispatchbits,2handlerbranches; physical meanings unknown')


if __name__=='__main__':main()
