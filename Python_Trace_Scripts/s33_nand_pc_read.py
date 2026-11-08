#!/usr/bin/env python3
"""Read one AKRN v1 RAW page through Linux SG_IO after installing a compatible image."""
import argparse
import ctypes as C
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat

RAW_BYTES = 2112
SG_IO = 0x2285
SG_DXFER_FROM_DEV = -3


class SgIo(C.Structure):
    _fields_ = [('interface_id',C.c_int),('dxfer_direction',C.c_int),
        ('cmd_len',C.c_ubyte),('mx_sb_len',C.c_ubyte),('iovec_count',C.c_ushort),
        ('dxfer_len',C.c_uint),('dxferp',C.c_void_p),('cmdp',C.c_void_p),('sbp',C.c_void_p),
        ('timeout',C.c_uint),('flags',C.c_uint),('pack_id',C.c_int),('usr_ptr',C.c_void_p),
        ('status',C.c_ubyte),('masked_status',C.c_ubyte),('msg_status',C.c_ubyte),
        ('sb_len_wr',C.c_ubyte),('host_status',C.c_ushort),('driver_status',C.c_ushort),
        ('resid',C.c_int),('duration',C.c_uint),('info',C.c_uint)]


def page_cdb(chip, block, page):
    if not (0 <= chip <= 255 and 0 <= block < 512 and 0 <= page < 64):
        raise ValueError('Coordinate fuori dal profilo configurato: chip0..255, blocco0..511, pagina0..63')
    return b'\xffAKRN\x01'+bytes((chip,page))+block.to_bytes(2,'big')+bytes(6)


def nikon_identity(scsi_path):
    chain=[scsi_path,*scsi_path.parents]
    luns=[p.name for p in chain if re.fullmatch(r'\d+:\d+:\d+:\d+',p.name)]
    if not luns or int(luns[0].split(':')[-1]) != 0:
        raise ValueError('Il dispositivo deve essere il LUN0 della Nikon')
    interface=next((p for p in chain if (p/'bInterfaceClass').exists()),None)
    usb=next((p for p in chain if (p/'idVendor').exists()),None)
    if interface is None or usb is None:
        raise ValueError('Dispositivo USB Nikon non identificato in sysfs')
    fields={n:(usb/n).read_text().strip() for n in ['idVendor','idProduct','product']}
    codes=[int((interface/n).read_text().strip(),16) for n in ['bInterfaceClass','bInterfaceSubClass','bInterfaceProtocol']]
    if (fields['idVendor'],fields['idProduct']) != ('04b0','035d') or codes != [8,6,0x50]:
        raise ValueError('Dispositivo diverso da Nikon S33 MSDC08/06/50')
    return dict(fields,sysfs=str(usb),lun=luns[0])


def fd_identity(fd):
    s=os.fstat(fd)
    kind='block' if stat.S_ISBLK(s.st_mode) else 'char' if stat.S_ISCHR(s.st_mode) else None
    if kind is None:
        raise ValueError('Occorre un dispositivo SCSI Linux, non un file regolare')
    path=Path(f'/sys/dev/{kind}/{os.major(s.st_rdev)}:{os.minor(s.st_rdev)}/device').resolve(strict=True)
    return nikon_identity(path)


def read_page(fd, chip, block, page):
    cdb=page_cdb(chip,block,page)
    command=C.create_string_buffer(cdb,len(cdb));data=C.create_string_buffer(RAW_BYTES);sense=C.create_string_buffer(64)
    h=SgIo(interface_id=ord('S'),dxfer_direction=SG_DXFER_FROM_DEV,cmd_len=16,mx_sb_len=64,
        dxfer_len=RAW_BYTES,dxferp=C.addressof(data),cmdp=C.addressof(command),sbp=C.addressof(sense),timeout=20000)
    header=bytearray(bytes(h))
    fcntl.ioctl(fd,SG_IO,header,True)
    h=SgIo.from_buffer(header)
    if h.status or h.host_status or h.driver_status or h.info&1:
        raise OSError(f'SCSI fallito: status={h.status:02x}, host={h.host_status:04x}, driver={h.driver_status:04x}, sense={sense.raw[:min(h.sb_len_wr,64)].hex()}')
    if h.resid != 0:
        raise OSError(f'Pagina RAW incompleta: residuo={h.resid}, attesi={RAW_BYTES}byte')
    return data.raw


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device',required=True,help='/dev/sgN o disco SCSI intero della Nikon')
    ap.add_argument('--chip',type=int,default=0)
    ap.add_argument('--block',type=int,required=True)
    ap.add_argument('--page',type=int,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();page_cdb(args.chip,args.block,args.page)
    # Reserve the local result before issuing I/O; existing files are never replaced.
    with args.output.open('xb') as output:
        try:
            fd=os.open(args.device,os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
            try:
                identity=fd_identity(fd);data=read_page(fd,args.chip,args.block,args.page)
            finally:os.close(fd)
        except BaseException:
            output.close();args.output.unlink();raise
        output.write(data)
    print(json.dumps(dict(device=identity,chip=args.chip,block=args.block,page=args.page,
        bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),output=str(args.output.resolve()),
        format='Nikon RAW bytes as returned; not normalized or independently ECC-verified'),indent=2))


if __name__=='__main__':main()
