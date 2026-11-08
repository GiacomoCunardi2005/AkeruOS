#!/usr/bin/env python3
"""Bounded BL and exact LE/ME reference census; no claim about computed callers."""
import argparse,json,struct
from s33_run_gnu_arc700 import ROOT,sha
from s33_trace_state_dispatch import verified_payloads
from s33_verify_custom_aux_cfg import call_at
from pathlib import Path

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('output',type=Path);a=ap.parse_args();blocks,payloads,directory=verified_payloads(ROOT);targets={0x2c6b74,0x2c6c70,0x2c6ba4,0x2c6bdc,0x2c6c14,0x2c6c38};calls=[];pointers=[]
 for info in blocks:
  body=payloads[info['index']];base=info['load_address_candidate']
  for off in range(0,len(body)-7,2):
   c=call_at(body,off,base)
   if c and c['target']in targets:calls.append(dict(namespace=info['index'],**c))
  for target in targets:
   for kind,needle in[('le',struct.pack('<I',target)),('me',struct.pack('<HH',target>>16,target&65535))]:
    pos=body.find(needle)
    while pos>=0:pointers.append(dict(namespace=info['index'],pc=hex(base+pos),target=hex(target),kind=kind));pos=body.find(needle,pos+1)
 result=dict(call_candidates=calls,pointer_candidates=pointers,payload_sha256={str(directory/i['file']):sha(directory/i['file'])for i in blocks},targets=list(map(hex,sorted(targets))),limits=['Halfword BL and exact LE/ME word census only; indirect/computed dispatch and tail branches not excluded.']);a.output.write_text(json.dumps(result,indent=2)+'\n');print(len(blocks),'payloads;',len(calls),'BL candidates;',len(pointers),'word references')
if __name__=='__main__':main()
