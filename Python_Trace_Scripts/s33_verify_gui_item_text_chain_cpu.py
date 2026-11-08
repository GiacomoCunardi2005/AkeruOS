#!/usr/bin/env python3
"""Run original GUI text lookup with original language blocks mapped as fixtures."""
from datetime import datetime,timezone
from types import SimpleNamespace
import hashlib,json,struct,sys
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha,elf_loads
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,raw,locate,u32,disasm

def main():
 navigate='--navigate' in sys.argv
 model='--model-labels' in sys.argv or navigate
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime(('menu_navigation_text_cpu_' if navigate else 'menu_model_text_chain_cpu_' if model else 'menu_text_chain_cpu_')+'%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-text-lookup-original-language-data'))
 print('Prove:',out,flush=True)
 try:
  r.prepare();dump=ROOT/'DUMPS/MainCode.dmp';d=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
  tbm=ROOT/'S33-sections/02_TBM_SK501_payload.bin';t=tbm.read_bytes();r.input_hashes[str(tbm)]=sha(tbm)
  for a,n in [(0x6337c4,0x2e),(0x1286c4,0x40),(0x3bb118,300),(0x631f44,0x632),(0x632540,26),(0x186d08,0x130),(0x186c40,0xa4),(0x186b14,0x12c)]:
   b,o=locate(a,n);assert raw(a,n)==d[b['offset']+o:b['offset']+o+n]
  assert u32(0x1286fc)==0x43e174 and u32(0x128700)==0x43e768
  (out/'gnu_windows.txt').write_text(disasm(0x6337c4,0x6337f2)+disasm(0x1286c4,0x1286fc))
  labels=[['Esposizione','Colore / Mono',None,'Impostazioni'],['Indietro','ISO','Apertura','Altro'],['Indietro','Colore','Mono RAW',None],['Indietro','Tempo','Flash',None],['Indietro','Acceso','Spento',None],['Indietro','Posizione A','Posizione B',None]]
  tests=[('model',view*4+slot,1) for view in range(6) for slot in range(4)] if model else [('full_item',x,1) for x in (26,64,88,0x2200000,0x2200008,0x2200010,0x2200020,0)]
  asm=''
  for i,(route,key,flag) in enumerate(tests):
   a=0x2001000+i*64
   key_setup=''
   if navigate:
    routes=[[],[0x580],[0x700],[0x580,0x2700],[0x580,0x2700,0x2180],[0x580,0x2180]]
    key_setup=' mov r0,0\n mov r1,0x2003018\n st r0,[r1]\n'
    for event in routes[key//4]:
     key_setup+=f' mov r0,0x2003018\n mov r1,{event:#x}\n mov r2,0x200301c\n mov r12,akeru_menu_event\n jl_s [r12]\n cmp r0,1\n bne navigation_fail\n mov r0,0x200301c\n ld r0,[r0]\n cmp r0,1\n bne navigation_fail\n'
    key_setup+=' mov r0,0x2003018\n ld r0,[r0]\n st r0,[r20,24]\n'
   key_setup+=(f' {"nop_s" if navigate else f"mov r0,{key//4}"}\n mov r1,{key%4+1}\n mov r12,akeru_menu_label\n jl_s [r12]\n st r0,[r20,44]\n' if model else f' mov r0,{key:#x}\n')
   asm+=f""" mov r20,{a:#x}
 mov r1,0x366868
 mov r0,1
 stb r0,[r1]
 st sp,[r20,4]
 {key_setup}
 mov r1,0x2003000
 st r0,[r1,12]
 mov r1,0x367f3e
 mov r0,1
 sth r0,[r1]
 mov r1,0x2005000
 mov r0,0
 st r0,[r1,28]
 mov r0,0x2006000
 mov r1,0
 mov r2,12
 mov r3,30
 mov r12,0x631f44
 jl [r12]
 mov r1,0x2005000
 ld r0,[r1,16]
 st r0,[r20,12]
 ld r0,[r1,28]
 st r0,[r20,40]
 st sp,[r20,8]
"""
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  if navigate: asm+='navigation_fail:\n mov r0,7\n mov r8,1\n trap_s 1\n'
  if model:
   source=out/'cases.s';elf=out/'cases.elf'
   source.write_text('.section .text,"ax",@progbits\n.global _start\n_start:\n'+asm+'\n.section .stack,"aw",@nobits\n.align 16\n.space 16384\n')
   commands=[('model_as',[TOOLCHAIN/'arc-elf32-as','-mcpu=arc700','-EL','-o',out/'cases.o',source]),
             ('model_compile',['arc-snps-elf-gcc','-mcpu=arc700','-mno-sdata','-mlong-calls','-O2','-ffreestanding','-fno-builtin','-c',ROOT/'AkeruOS/ui/menu_labels.c','-o',out/'labels.o']),
             ]
   if navigate: commands.append(('navigation_compile',['arc-snps-elf-gcc','-mcpu=arc700','-mno-sdata','-mlong-calls','-O2','-ffreestanding','-fno-builtin','-c',ROOT/'AkeruOS/ui/menu.c','-o',out/'menu.o']))
   commands.append(('model_link',[TOOLCHAIN/'arc-elf32-ld','-EL','-T',LEGACY/'tests/smoke.ld','-o',elf,out/'cases.o',out/'labels.o']+([out/'menu.o'] if navigate else [])))
   for name,command in commands:
    result=r.command(name,command);assert result.returncode==0,result.stdout
   r.input_hashes[str(ROOT/'AkeruOS/ui/menu_labels.c')]=sha(ROOT/'AkeruOS/ui/menu_labels.c')
   if navigate: r.input_hashes[str(ROOT/'AkeruOS/ui/menu.c')]=sha(ROOT/'AkeruOS/ui/menu.c')
   _,segments=elf_loads(elf)
  else: elf=compile_probe(r,'cases',asm)
  def mapping(p,a,n):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{n}']
  images={i:bytearray(PS[i]) for i in (0,1,2)}; maps=[];patches=[]
  def binary(name,code):
   e=compile_probe(r,name,code);p=out/(name+'.bin');result=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',e,p]);assert result.returncode==0,result.stdout
   data=p.read_bytes();p.write_bytes(data+bytes(8+(-len(data))%8));return p
  noop=' mov r0,0\n j_s [blink]\n'
  fixtures=[('metric_a',0x26e464,noop),('metric_b',0x26e418,noop),('icon',0x26e3c0,noop),('mode',0xd0a84,noop),('text_setup',0x1eb438,noop),('color',0x18ba80,noop),('text_context',0x20e320,' mov r0,0x2007000\n j_s [blink]\n'),('metric_mode',0x14c768,noop),('metric_end',0x14c6f4,noop),('byte_class',0x23ad30,noop),('glyph_width',0x23acc4,' mov r0,10\n j_s [blink]\n'),('measure_callback',0x187168,noop),('draw_recorder',0x1870dc,' mov r12,0x2005000\n st r0,[r12]\n st r1,[r12,4]\n st r2,[r12,8]\n st r3,[r12,12]\n st r0,[r12,16]\n st r5,[r12,20]\n st r6,[r12,24]\n ld r0,[r12,28]\n add r0,r0,1\n st r0,[r12,28]\n mov r0,1\n j_s [blink]\n')]

  for i,(name,addr,code) in enumerate(fixtures):
   target=0x2030000+i*0x400;p=binary(name,code);maps+=mapping(p,target,p.stat().st_size)
   entry=binary('entry_'+name,f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
   block,off=locate(addr,8);original=bytes(images[block['index']][off:off+8]);assert original==raw(addr,8)
   images[block['index']][off:off+8]=entry;patches.append({'name':name,'address':hex(addr),'original':original.hex(),'fixture':entry.hex()})
  blocks=list(maps)
  for i,img in images.items():
   p=out/f'block{i}_fixture.bin';p.write_bytes(img);blocks+=mapping(p,BS[i]['load_address_candidate'],len(img))
  for name,addr,size in [('record',0x2003000,32),('args',0x2005000,32),('control',0x2006000,128),('runtime',0x681b68,8),('text_ctx_data',0x2007000,32),('text_bounds',0x2007100,32)]:
   p=out/(name+'.bin');data=bytearray(size)
   if name=='control': struct.pack_into('<I',data,48,0x2003000);data[54]=1
   if name=='text_ctx_data': struct.pack_into('<II',data,16,1,0x2007100)
   if name=='text_bounds': struct.pack_into('<hh',data,8,1000,1000)
   p.write_bytes(data);blocks+=mapping(p,addr,size)
  expected={'english':['Change colors','Settings','Camera settings','ISO','f/','Tempo','Mono RAW'],
   'italian':['Cambia colore','Impostazioni','Impostazioni fotocamera','ISO','f/','Tempo','Mono RAW']}
  custom=bytearray(64)
  for pos,label in [(0,b'ISO'),(8,b'f/'),(16,b'Tempo'),(32,b'Mono RAW')]: custom[pos:pos+len(label)]=label
  custom_file=out/'custom_labels.bin';custom_file.write_bytes(custom)
  results=[]
  for lang,index in [('english',1),('italian',5)]:
   offset=0xc7a000+u32(0x3bb118+4+index*4);size=u32(0x3bb118+152+index*4);blob=t[offset:offset+size]
   assert blob==d[offset:offset+size] and len(blob)==size
   p=out/(lang+'_fixture.bin');p.write_bytes(blob);maps=blocks+mapping(p,0x43e170,size)+mapping(custom_file,0x2200000,len(custom))
   statefile=out/(lang+'_cases.bin');statefile.write_bytes(bytes(len(tests)*64));maps+=mapping(statefile,0x2001000,len(tests)*64)
   case,log=r.run(lang,'/result/'+elf.name,maps,trace=True);assert case['exit_code']==0 and case['fault'] is None,log
   trace=(out/(lang+'.trace')).read_text()
   nonempty=sum(1 for row in labels for label in row if label) if model else len(tests)-1
   for addr in ('0x631f44','0x63200a','0x63200c'):
    assert sum(line.startswith(addr+' ') for line in trace.splitlines())==len(tests),addr
   assert sum(line.startswith('0x632556 ') for line in trace.splitlines())==nonempty
   assert sum(line.startswith('0x186d08 ') for line in trace.splitlines())==nonempty
   assert sum(line.startswith('0x186e2e ') for line in trace.splitlines())==nonempty
   assert sum(line.startswith('0x186c40 ') for line in trace.splitlines())==2*nonempty
   assert sum(line.startswith('0x186b14 ') for line in trace.splitlines())==2*nonempty
   assert custom_file.read_bytes()==custom
   assert p.read_bytes()==blob
   values=statefile.read_bytes()
   for i,(route,key,flag) in enumerate(tests):
    sp1,sp2,drawptr=struct.unpack_from('<III',values,i*64+4)
    count=struct.unpack_from('<I',values,i*64+40)[0]
    label=labels[key//4][key%4] if model else None
    if navigate: assert struct.unpack_from('<I',values,i*64+24)[0]==key//4,(lang,key,'screen')
    ptr=struct.unpack_from('<I',values,i*64+44)[0] if model else (key if key>=381 else (0x43e768+struct.unpack_from('<I',blob,4+4*key)[0] if key else 0))
    assert sp1==sp2 and count==int(bool(ptr)),(lang,key,count)
    if ptr: assert drawptr==ptr,(lang,key,drawptr,ptr)
    text=None
    if ptr:
     if model:
      segment=next(s for s in segments if s['address']<=ptr<s['address']+s['size']);data=segment['data'];p=ptr-segment['address']
     else:
      data=custom if ptr>=0x2200000 else blob;p=ptr-(0x2200000 if ptr>=0x2200000 else 0x43e170)
     end=data.index(b'\0',p);text=data[p:end].decode('ascii');assert text==(label if model else expected[lang][i])
    if model: assert bool(ptr)==bool(label)
    results.append({'language_fixture':lang,'entry':route,'model_screen':key//4 if model else None,'model_slot':key%4+1 if model else None,'id':None if model else key,'enabled':flag,'expected_pointer':hex(ptr),'text':text,'backend_calls':count,'final_backend_text_pointer':hex(drawptr) if count else None,'stack_preserved':True})
  (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
  (out/'cases.json').write_text(json.dumps(results,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(__import__('pathlib').Path(__file__).read_bytes())
  r.results.update(status='PASS_NAVIGATION_LABEL_TEXT_CHAIN' if navigate else 'PASS_MODEL_LABEL_TEXT_CHAIN' if model else 'PASS_SYNTHETIC_FULL_MENU_ITEM_TEXT_CHAIN',scenarios=results,
   assumptions=['Original 631f44 runs from entry to return; 186c40 and 186b14 run original code; glyph width, byte classification, metric, icon, color, context getter, and callbacks are fixtures. Original lookup and language blocks in synthetic RAM.',
                'Flag at 366868 and entry inputs set explicitly; no firmware bytes altered.'],
   limits=['Original 186d08, 186c40, and 186b14 execute but glyph callbacks are recorders; no glyphs, loader, runtime locale, display or hardware execution; only seeded branches are exercised.',
           'Synthetic RAM mapping does not establish physical memory availability.',
           'Direct pointers come from test ELF model labels' if model else 'Direct pointers come from synthetic memory and are not validated by wrapper; no proof of draw routine or physical mapping.',
           'Navigation is driven by injected model events, not the original scanner.' if navigate else 'No original scanner is exercised.',
           'No proof of glyph rendering, physical mapping or production binding.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print(f'PASS: {len(results)} item and text chain cases with glyph callback recorder over English and Italian fixture blocks;',out,flush=True)
if __name__=='__main__':main()
