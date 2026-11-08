#!/usr/bin/env python3
"""Decode fields observed in S33 V1.1 routine 0x210c08; no device access.

This does not validate a key, identify a volume, or reconstruct a full path.
"""
import argparse
import json


def decode_key(key):
    if not isinstance(key,int) or isinstance(key,bool) or not 0<=key<=0xffffffff:
        raise ValueError('Key must be an unsigned 32-bit integer')
    extension_index=(key>>26)&3
    return dict(key=f'0x{key:08x}',file_number=key&0x3fff,
                name_variant=(key>>14)&3,directory_record_index=(key>>16)&0x3ff,
                extension_index=extension_index,extension=('JPG','AVI','WAV','MPO')[extension_index],
                namespace_selector=(key>>28)&15,
                limitation='Decoded fields only; validity, current volume, directory and filename prefix require runtime state')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('key',help='Unsigned 32-bit key in decimal or 0x-prefixed hex')
    args=parser.parse_args()
    try:result=decode_key(int(args.key,0))
    except (ValueError,TypeError) as exc:parser.error(str(exc))
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
