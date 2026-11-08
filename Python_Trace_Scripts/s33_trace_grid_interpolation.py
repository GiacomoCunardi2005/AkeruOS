#!/usr/bin/env python3
"""Offline S33 V1.1 two-channel fixed-point grid interpolation reconstruction and bounded model validation."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[(0x1FD4E4,0x1FD614,'CompleteSharedGridInterpolator'),
 (0x1FE0E6,0x1FE10E,'FallbackSharedInterpolatorCaller'),
 (0x200450,0x20047E,'PreferredSharedInterpolatorCaller')]
def u32(v):return v&0xffffffff
def s32(v):return (v&0x7fffffff)-(v&0x80000000)
def s16(v):return (v&0x7fff)-(v&0x8000)

def interpolate_pair(samples,stride,coord_y,coord_x,scale_x,scale_y,offset_x,offset_y):
 """Reconstruct one grid point. Input/output are two unsigned halfwords.

 This models the selected normal arithmetic path, not buffer admission or
 firmware execution. Coordinates are scaled into Q8 positions. Source bounds
 are checked here for the host model; the ARC body has no equivalent check.
 """
 x=u32((s32(u32(coord_x*scale_x+0x800))>>12)+offset_x)
 y=u32((s32(u32(coord_y*scale_y+0x800))>>12)+offset_y)
 ix=x>>8;iy=(y>>8)&0xffff;fx=x&255;fy=y&255
 assert ix+1<stride and ((iy+1)*stride+ix+1)*2+1<len(samples)
 def mix(a,b,w):return s32(u32((a<<8)+s16(b-a)*w+128))>>8
 out=[]
 for c in range(2):
  a,b=samples[2*(iy*stride+ix)+c],samples[2*(iy*stride+ix+1)+c]
  d,e=samples[2*((iy+1)*stride+ix)+c],samples[2*((iy+1)*stride+ix+1)+c]
  top,bottom=mix(a,b,fx),mix(d,e,fx)
  out.append((u32((top<<8)+s16(bottom-top)*fy+128)>>8)&65535)
 return tuple(out)

def execute_decoded_point(instructions,samples,stride,cy,cx,sx,sy,ox,oy):
 """Execute only the decoded straight-line body 0x1fd514..0x1fd608.

 Strict subset: unsupported instructions fail. MAC low word r57 is modeled;
 the surrounding firmware sets aux_macmode=0. No branch, IRQ or MMIO emulation.
 """
 regs={i:0 for i in range(64)};regs.update({2:stride,3:0x2000,4:0x10000,5:sx,6:sy,7:ox,9:oy})
 mem={0x10000+2*i:v for i,v in enumerate(samples)};mem.update({0x2000:cy,0x2002:cx})
 writes=[]
 def val(x):return regs[int(x[1:])] if x.startswith('r') else int(x,0)
 def put(dst,v):regs[int(dst[1:])]=u32(v)
 for pc,op,args in instructions:
  if op=='ldw_s':
   dst,br,off=re.fullmatch(r'(r\d+),\[(r\d+),(0x[0-9a-f]+|\d+)\]',args).groups()
   put(dst,mem[val(br)+int(off,0)]&65535);continue
  if op=='sth':
   src,br,off=re.fullmatch(r'(r\d+),\[(r\d+)(?:,(0x[0-9a-f]+|\d+))?\]',args).groups()
   addr=val(br)+int(off or '0',0);mem[addr]=val(src)&65535;writes.append(addr);continue
  xs=args.split(',');dst=xs[0];vs=[val(v) for v in xs[1:]]
  if op in ('muludw','muldw'):regs[57]=u32(vs[0]*vs[1]);continue
  if op in ('mov_s','mov'):v=vs[0]
  elif op in ('add','add_s'):v=vs[0]+vs[1]
  elif op=='add1':v=vs[0]+2*vs[1]
  elif op=='add3':v=vs[0]+8*vs[1]
  elif op=='sub_s':v=vs[0]-vs[1]
  elif op in ('asl_s','asl'):v=vs[0]<<((vs[1] if len(vs)>1 else 1)&31)
  elif op in ('asr_s','asr'):v=s32(vs[0])>>((vs[1] if len(vs)>1 else 1)&31)
  elif op in ('lsr_s','lsr'):v=vs[0]>>((vs[1] if len(vs)>1 else 1)&31)
  elif op in ('extw_s','extw'):v=vs[0]&65535
  elif op=='extb':v=vs[0]&255
  elif op=='sexw_s':v=s16(vs[0])
  elif op=='and':v=vs[0]&vs[1]
  else:raise AssertionError((hex(pc),op,args))
  put(dst,v)
 assert writes==[0x2000,0x2002] and regs[3]==0x2004
 return mem[0x2000],mem[0x2002]

def verify_model(listing):
 import random
 instructions=[]
 for raw in listing.splitlines():
  m=re.match(r'^\s*([0-9a-f]+):\t[^\t]+\t(\S+)\t?(.*)$',raw)
  if m and 0x1fd514<=int(m[1],16)<=0x1fd608:
   instructions.append((int(m[1],16),m[2],m[3]))
 assert instructions[0][0]==0x1fd514 and instructions[-1][0]==0x1fd608
 rng=random.Random(0x533);tested=0
 for cap in (32767,65535):
  for _ in range(2500):
   stride=8;samples=[rng.randrange(cap+1) for _ in range(8*8*2)]
   cy,cx=rng.randrange(5*256),rng.randrange(5*256)
   sx,sy=rng.choice((2048,4096)),rng.choice((2048,4096))
   ox,oy=rng.randrange(256),rng.randrange(256)
   expected=interpolate_pair(samples,stride,cy,cx,sx,sy,ox,oy)
   observed=execute_decoded_point(instructions,samples,stride,cy,cx,sx,sy,ox,oy)
   assert observed==expected,(tested,observed,expected)
   tested+=1
 # Constant fields and exact lattice points are independent invariants.
 for k in (0,1,255,32767,65535):
  samples=[k]*(8*8*2)
  assert interpolate_pair(samples,8,384,512,4096,4096,17,33)==(k,k)
 for y in range(6):
  for x in range(6):
   samples=[rng.randrange(65536) for _ in range(8*8*2)]
   assert interpolate_pair(samples,8,y*256,x*256,4096,4096,0,0)==tuple(samples[2*(y*8+x):2*(y*8+x)+2])
 # Crossing the signed16 difference boundary differs from generic bilinear.
 samples=[0]*(8*8*2);samples[2:4]=[65535,65535]
 boundary=interpolate_pair(samples,8,0,128,4096,4096,0,0)
 assert boundary==(0,0) # generic nonwrapping midpoint would round to 32768.
 return dict(decoded_body_instructions=len(instructions),comparisons=tested,
  constant_fields=5,integer_lattice_points=36,signed_difference_boundary=list(boundary),
  limitations='bounded host arithmetic model; not ARC silicon, firmware runtime, full loop or caller admission')

def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/grid_interpolation';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
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
 edges=[(0x1FE100,0x1FD4E4),(0x200478,0x1FD4E4),(0x1FD506,0x1FD60C)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={2086122: 'asr_s\tr0,r0,0x4', 2086124: 'add_s\tr0,r0,0x1', 2086126: 'extw_s\tr0,r0', 2086128: 'asr_s\tr1,r1,0x4', 2086130: 'add_s\tr1,r1,0x1', 2086132: 'extw_s\tr1,r1', 2086134: 'sr\t0,[aux_macmode]', 2086142: 'muludw\t0,r1,r0', 2086152: 'ld\tr9,[sp,12]', 2086156: 'mov\tlp_count,r57', 2086160: 'lp\t252', 2086164: 'ldw_s\tr1,[r3,0x2]', 2086168: 'ldw_s\tr3,[r3,0]', 2086174: 'add\tr8,r57,0x800', 2086194: 'asr\tr11,r11,0xc', 2086252: 'extb\tr8,r8', 2086256: 'extb\tr11,r11', 2086262: 'sexw_s\tr1,r1', 2086306: 'sexw_s\tr1,r1', 2086326: 'sth\tr3,[r10]', 2086348: 'add3\tr3,r1,0x10', 2086404: 'sth\tr3,[r10,2]', 2086408: 'add\tr3,r10,0x4', 2086418: 'j_s\t[blink]'}
 for a,n in checks.items():assert n in line(a),line(a)
 model_validation=verify_model(listing)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  model_validation=model_validation,
  argument_contract={'r0':'first extent before shift4 plus1','r1':'second extent before shift4 plus1',
   'r2':'source row stride in pairs','r3':'in-place grid of two halfword coordinates replaced by sampled pair',
   'r4':'source pairs base','r5':'x coordinate scale','r6':'y coordinate scale','r7':'x Q8 offset',
   'stack0':'y Q8 offset'},
  observations=['Decoded helper samples two interleaved halfword components from four neighboring source positions',
   'Two horizontal interpolations and one vertical interpolation use 8-bit fractions and staged rounding',
   'Differences explicitly truncate to signed16, which changes full-range halfword results versus generic bilinear',
   'Grid coordinate pairs are overwritten in place with output sample pairs; pointer advances four bytes',
   'Body has no source bound check or allocation; caller must supply valid footprint'],
  limits=['Bounded interpreter models only the actual straight-line body, low MAC result and ordinary arithmetic',
   'No emulation of hardware loop, interrupts, exceptions, full callers or silicon arithmetic validation',
   'Count and index overflow, aliasing and physical buffer lifetime remain caller-admission questions',
   'No RGB/YUV/Bayer/JPEG format attribution or camera execution proof'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
 print('PASS: model comparisons:', model_validation['comparisons'], 'decoded instructions:', model_validation['decoded_body_instructions'])
if __name__=='__main__':main()
