#!/usr/bin/env python3
"""Read-only original V1.1 proof of custom task, finite wait and tick clock routes.
No camera access, firmware patch, fake task creation, or physical RAM claim.
"""
import json, re, struct, tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads, run, sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[(0x23C990,0x23CA38,'scheduled_task_create'),(0x2C9AE0,0x2C9B90,'custom_template'),
 (0x29F3A8,0x29F4E4,'task_constructor'),(0x19A774,0x19A7FC,'finite_delay_ms'),
 (0x28171C,0x28179C,'milliseconds_to_ticks'),(0x28179C,0x281808,'queue_delay_switch'),
 (0xB2D50,0xB2DE0,'save_switch_context'),(0x2F70C4,0x2F71C0,'tick_wake_waiters'),
 (0x2FB6FC,0x2FB75C,'coherent_tick_copy'),(0x269888,0x269990,'ticks_to_seconds_ms'),
 (0x145CD0,0x145CFC,'original_delay_wrapper'),(0x23C620,0x23C65C,'busy_delay_rejected'),
 (0x17B97C,0x17B998,'busy_loop_rejected'),(0xC58C8,0xC58F4,'hook_after_resource')]
CHECKS={0x23C9B6:'mov_s\tr0,r1',0x23C9B8:';0x2c9ae0',0x23C9BC:'mov_s\tr1,r2',
 0x23C9D0:';0x29f4e4',0x2C9B26:'ld\tr16,[r13,24]',0x2C9B2A:'mov_s\tr14,0x1',
 0x29F41A:';0xad920',0x19A792:';0x28171c',0x19A796:'mov_s\tr1,r14',
 0x19A7AE:';0x26983c',0x19A7B4:';0x28179c',0x28173C:';0x335b34',
 0x281734:'mov\tr0,1000',0x2817FC:'or\tr1,r1,256',0x281800:';0xb2d50',
 0x281804:'st_s\tr1,[r0,0x8]',0xB2D50:'sub\tsp,sp,164',0xB2DA0:'st\tgp,[sp,132]',
 0x2F70F4:'ldh\tr2,[r13,84]',0x2F7144:'and\tr1,r3,0xfffffeff',
 0x2F7182:'st\tr8,[r5,8]',0x2FB722:';0xad920',0x2FB726:'mov_s\tr2,0xc',
 0x2698C8:';0x335d34',0x26990C:'mov\tr2,1000',0x269938:'st\tr17,[r14,4]',
 0x145CDE:';0x19a774',0x23C648:';0x17b97c',0x17B988:'lp\t12',
 0xC58DC:';0xc5af4',0xC58E0:';0x159128'}
def main():
 blocks,payloads,block_dir=verified_payloads(ROOT); b=next(b for b in blocks if b['index']==0)
 tools=ROOT/'work/build-arc/binutils'; listing=[]
 with tempfile.TemporaryDirectory(prefix='s33-dump-task-') as td:
  elf=Path(td)/'original.elf'; back=Path(td)/'back.bin'
  run([tools/'objcopy','-I','binary','-O','elf32-littlearc','-B','arc','--rename-section','.data=.text,alloc,load,readonly,code,contents','--change-section-vma',f'.data={b["load_address_candidate"]:#x}','--strip-all',block_dir/b['file'],elf])
  run([tools/'objcopy','--dump-section',f'.text={back}',elf]); assert back.read_bytes()==payloads[0]
  for a,z,label in WINDOWS:
   listing.append('WINDOW '+label+'\n'+run([tools/'objdump','-d','-m','arc:ARC700','-EL',f'--start-address={a:#x}',f'--stop-address={z:#x}',elf]).replace(str(elf),'original.elf'))
 combined='\n'.join(listing)
 for addr,expected in CHECKS.items():
  line=next(l for l in combined.splitlines() if re.match(rf'^\s*{addr:x}:',l)); assert expected in line,(hex(addr),line,expected)
 def raw(a,n):return payloads[0][a-b['load_address_candidate']:a-b['load_address_candidate']+n]
 out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_Task_Binding';out.mkdir(parents=True,exist_ok=True)
 (out/'gnu_verified.txt').write_text(combined)
 evidence=dict(firmware='S33 V1.1',kind='static byte-asserted paths, not on-camera execution',
  hashes={str(b['index']):b['sha256'] for b in blocks},script_sha256=sha(Path(__file__).read_bytes()),
  windows=len(WINDOWS),instruction_assertions=len(CHECKS),
  hook=dict(site='0xc58e0',original_target='0x159128',original_bytes=raw(0xC58E0,4).hex(),
   requirement='Resource must have loaded successfully; coordinator itself does not prove success; check resident launcher signature before transfer'),
  create=dict(address='0x23c990',r0=0,r1=0,r2='pointer to 32-byte custom template',returns='nonzero task ID or zero failure; not wrapper status',
   template_copy='0x29f41a copies32; only pointers remain borrowed',stack_suggestion='0x8000 task stack with local dump state; no arbitrary RAM allocation'),
  sleep=dict(address='0x19a774',r0='milliseconds >0',returns='void, r0 unspecified',switch='0x281800 ->0xb2d50',
   wake='0x2f70c4 scans K+0x4c/54, clears0x100, inserts ready state2',preconditions='task context, scheduler unlocked, tick IRQ running'),
  clock=dict(copy='0x2fb6fc(ticks12*)',convert='0x269888(ticks12*, seconds_ms8*)',returns='convert1 normal,0 saturated',
   scalar='seconds*1000+milliseconds modulo2^32',resolution='kernel ticks; no sub-tick hardware query'),
  limits=['No actual custom task creation/scheduling execution in this verifier','No RAM physical map, heap availability, or measured stack bound','Hook only candidate; Resource failure and resident lifetime need independent guard','V1.0 compatibility unproved','0x23c620 is busy loop via0x17b97c and rejected for sleep'])
 (out/'verified_evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
 print(f'PASS:16 payload hashes, original block0 roundtrip, {len(WINDOWS)} GNU windows, {len(CHECKS)} instruction assertions')
if __name__=='__main__':main()
