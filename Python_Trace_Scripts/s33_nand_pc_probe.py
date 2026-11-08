#!/usr/bin/env python3
"""Read-only INQUIRY and AKRN rejection probe; no NAND read or firmware write."""
import argparse
import ctypes as C
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import time
from s33_nand_pc_read import SgIo, SG_IO, SG_DXFER_FROM_DEV, fd_identity, page_cdb


def transfer(fd, cdb, size):
    command=C.create_string_buffer(cdb,len(cdb));data=C.create_string_buffer(size);sense=C.create_string_buffer(64)
    header=SgIo(interface_id=ord('S'),dxfer_direction=SG_DXFER_FROM_DEV,cmd_len=len(cdb),mx_sb_len=64,
                dxfer_len=size,dxferp=C.addressof(data),cmdp=C.addressof(command),sbp=C.addressof(sense),timeout=20000)
    raw=bytearray(bytes(header));started=time.monotonic()
    fcntl.ioctl(fd,SG_IO,raw,True)
    h=SgIo.from_buffer(raw);actual=size-h.resid if 0<=h.resid<=size else None
    return dict(cdb=cdb.hex(),requested=size,status=h.status,host_status=h.host_status,driver_status=h.driver_status,
                info=h.info,resid=h.resid,actual=actual,sense=sense.raw[:min(h.sb_len_wr,64)].hex(),
                data=data.raw[:actual].hex() if actual is not None else None,
                elapsed_seconds=time.monotonic()-started,duration_ms=h.duration)


def classify(rows):
    inquiry=rows[0];rejection=rows[1]
    if inquiry['status'] or inquiry['host_status'] or inquiry['driver_status'] or inquiry['info']&1 or inquiry['actual']!=36:
        return 'INQUIRY_NOT_VERIFIED'
    if rejection['host_status'] or rejection['driver_status']&~8:
        return 'AKRN_REJECTION_TRANSPORT_ERROR'
    sense=bytes.fromhex(rejection['sense'])
    response=(sense[0]&0x7f) if sense else 0
    key=(sense[2]&15) if response in (0x70,0x71)and len(sense)>=3 else (sense[1]&15)if response in (0x72,0x73)and len(sense)>=2 else None
    asc=sense[12]if response in (0x70,0x71)and len(sense)>=14 else sense[2]if response in (0x72,0x73)and len(sense)>=4 else None
    if rejection['status']==2 and key==5 and asc==0x24:
        return 'OBSERVED_AKRN_INVALID_FIELD_REJECTION_COMPATIBLE'
    if not rejection['status'] and not rejection['driver_status'] and not rejection['info']&1 and rejection['actual']==0:
        return 'OBSERVED_GOOD_STATUS_WITHOUT_DATA_COMPATIBLE_WITH_ORIGINAL_FF_NOOP'
    return 'AKRN_REJECTION_REQUIRES_REVIEW'


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--device',required=True);ap.add_argument('--output-dir',required=True,type=Path);args=ap.parse_args()
    args.output_dir.mkdir(parents=False,exist_ok=False)
    result=dict(status='RUNNING',utc=datetime.now(timezone.utc).isoformat(),device_path=args.device,
                scope='INQUIRY plus FF AKRN with deliberately invalid magic; both data-IN, no NAND request')
    fd=None
    try:
        fd=os.open(args.device,os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC);result['identity']=fd_identity(fd)
        result['transfers']=[]
        result['transfers'].append(transfer(fd,bytes([0x12,0,0,0,36,0]),36))
        invalid=bytearray(page_cdb(0,0,0));invalid[1]=ord('X')
        result['transfers'].append(transfer(fd,bytes(invalid),2112))
        result['status']=classify(result['transfers'])
    except BaseException as exc:
        result.update(status='PROBE_ERROR',error_type=type(exc).__name__,error=str(exc));raise
    finally:
        if fd is not None:os.close(fd)
        (args.output_dir/'probe.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
