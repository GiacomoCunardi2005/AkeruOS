#!/usr/bin/env python3
"""Reach the registered FED38 callback through its original parent dispatcher."""
from pathlib import Path
from s33_run_gnu_arc700 import ROOT,sha
from s33_tbib_nested_context_harness_v2 import execute
from s33_verify_tbib_registered_callback import build as registered_plan

PARENT=ROOT/'Risultati/Processor_Registers/20261026T113207Z'
DEPENDENCY=Path(__file__).with_name('s33_verify_tbib_registered_callback.py')

def build(seed,pending_mode,depth):
    p=registered_plan(seed,0,depth);a=0xfef0074
    pending=((seed^(a>>2))&0x7fff)|(0x8000 if pending_mode else 0)
    p['initial'][a]=pending
    child=next(c for c in p['calls'] if c['entry']==0x1014d6c)
    parent_events=[(0x10149a6,'read',0xfef0028,p['initial'][0xfef0028]|0x8000),(0x10149b6,'read',a,pending)]
    if pending_mode:
        parent_events+=child['events']+[(0x1014a2a,'write',a,0x8000)]
    else:
        # The child is not invoked; its pending word therefore remains seeded.
        p['final'][0xfed3834]=p['initial'][0xfed3834]
    child.update(entry=0x1014998,kind='original_parent_dispatch',return0=depth,events=parent_events,
                 parent_pending_mode=pending_mode,expected_child_calls=int(bool(pending_mode)),original_indirect_pc=0x1014a06)
    p['final'][a]=0x8000 if pending_mode else pending
    return p

if __name__=='__main__':
    execute(source=Path(__file__),parent=PARENT,action='original-tbib-parent-dispatch',status='PASS_ORIGINAL_TBIB_PARENT_DISPATCH',builder=build,values=[0,1],
        extra=dict(reused_plan_dependency=dict(path=str(DEPENDENCY),sha256=sha(DEPENDENCY))),
        limits=['Parent1014998 executes fully;originalJL1014A06 reachesregistered1014D6C onlywhenpendingbit15=1. Not physical IRQ injection,vectorentry orCPUinterruptdelivery.',
                'Pairedcases change onlyFEF0074bit15;otherMMIOseeds,pointers,callbackregistration andnestedcontext areidenticalwithinpair. No universalmetamorphicclaim.',
                'Original1004A78 installs/clears1040628;temporaryRAMgate10411E4 andcontext104126C restored;allchildcallbackslots remainoriginalzero.',
                'IDENTITY4 remainsGNUmodel0,notNikonID. Parentusesmask/pending snapshots inregisters;ordinaryMMIOstorage isnotW1C/ack/IRQphysicalsemantics.',
                'Nesteddepth1/2/7,gatedata+24=1,explicitfixtures;no fullTBIBboot/hardware/install/physicalregisteruniverseproof.'])
