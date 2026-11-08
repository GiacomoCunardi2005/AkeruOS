#!/usr/bin/env python3
"""Inventory bounded GUI resources in original S33 V1.1 capture menus."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,raw,u16,u32,cstring,locate


def main():
    dump_path=ROOT/'DUMPS/MainCode.dmp';dump=dump_path.read_bytes()
    def check(addr,n):
        block,offset=locate(addr,n);data=raw(addr,n)
        assert dump[block['offset']+offset:block['offset']+offset+n]==data,(hex(addr),n)
        return data
    labels={1:'CaptureLiveview',2:'CaptureMenu',0x9b:'ImageMode',0x9d:'LiveViewHotKeyMenu'}
    objects=[]
    for key,name in labels.items():
        table=0x3f5900+4*key;check(table,4);address=u32(table)
        check(address,24);assert u16(address+4)==key
        count=u16(address+6);array=u32(address+8);main=u32(address+12)
        assert cstring(u32(address+20))==name
        check(array,count*4);resources=[]
        for i in range(count):
            resource=u32(array+4*i);check(resource,24)
            resources.append(dict(address=hex(resource),kind=hex(u16(resource+4)),
                                  resource_class=hex(u16(resource+6)),
                                  rect=[u16(resource+j) for j in (12,14,16,18)]))
        objects.append(dict(id=hex(key),name=name,descriptor=hex(address),main=hex(main),
                            resource_array=hex(array),resource_count=count,resources=resources))
    lists=[]
    for address in (0x9801c0,0x980268,0x981218,0x9812c0,0x784608,0x7846b0):
        head=check(address,56);assert u16(address+6)==0x15
        count=head[46];pointer=u32(address+48)
        assert 1<=count<=4 and u16(address+52)==count
        data=check(pointer,count*28);entries=[]
        for i in range(count):
            item=data[28*i:28*(i+1)]
            entries.append(dict(index=i,address=hex(pointer+28*i),raw=item.hex(),
                                image_ids=list(struct.unpack_from('<3H',item,0)),
                                word_12=struct.unpack_from('<I',item,12)[0],
                                word_16=struct.unpack_from('<I',item,16)[0],
                                word_20=struct.unpack_from('<I',item,20)[0],
                                word_24=struct.unpack_from('<I',item,24)[0]))
        lists.append(dict(resource=hex(address),count=count,items=hex(pointer),stride=28,entries=entries))
    assert [x['resource_count'] for x in objects]==[90,3,10,3]
    assert [x['count'] for x in lists]==[3,4,3,4,4,4]
    out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('resources_%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True,exist_ok=False)
    result=dict(status='PASS_BOUNDED_CAPTURE_GUI_RESOURCE_BYTES',dump_sha256=hashlib.sha256(dump).hexdigest(),
                source_firmware='Nikon S33 V1.1; 16 TBM payloads hash-verified',objects=objects,lists=lists,
                limits=['28-byte records and numeric fields observed, full semantics not established.',
                        'Coordinates are firmware values, not a measured physical pixel mapping.',
                        'No rendering, UI activation, hardware or persistence is verified.'])
    (out/'resources.json').write_text(json.dumps(result,indent=2)+'\n')
    (out/'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
    print('PASS: 4 descriptors and 6 original list resources;',out)


if __name__=='__main__':main()
