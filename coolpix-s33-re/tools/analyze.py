#!/usr/bin/env python3
"""Non-destructive firmware triage for Nikon COOLPIX S33; stdlib only."""
import argparse, collections, hashlib, json, math, pathlib, re, struct

SIGNATURES = {"ELF":b'\x7fELF',"gzip":b'\x1f\x8b\x08',"ZIP":b'PK\x03\x04',"JPEG":b'\xff\xd8\xff',"PNG":b'\x89PNG\r\n\x1a\n',"LZMA_alone_common":b'\x5d\x00\x00\x80\x00',"uImage":b'\x27\x05\x19\x56',"UBI":b'UBI#',"SquashFS_LE":b'hsqs',"SquashFS_BE":b'sqsh'}

def entropy(buf):
    if not buf:return 0.0
    counts=collections.Counter(buf)
    return -sum((n/len(buf))*math.log2(n/len(buf)) for n in counts.values())

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('firmware',type=pathlib.Path)
    ap.add_argument('--output',type=pathlib.Path,default=pathlib.Path('output'))
    ap.add_argument('--window',type=int,default=65536)
    ap.add_argument('--min-string',type=int,default=6)
    args=ap.parse_args()
    if not args.firmware.is_file():ap.error('File non trovato: '+str(args.firmware))
    if args.window<=0 or args.min_string<4:ap.error('Invalid window/string length')
    data=args.firmware.read_bytes()
    args.output.mkdir(parents=True,exist_ok=True)
    h={a:hashlib.new(a,data).hexdigest() for a in ('md5','sha256')}
    hits={name:[m.start() for m in re.finditer(re.escape(sig),data)][:100] for name,sig in SIGNATURES.items()}
    hits={k:v for k,v in hits.items() if v}
    chunks=[{'offset':i,'size':len(data[i:i+args.window]),'entropy':round(entropy(data[i:i+args.window]),4)} for i in range(0,len(data),args.window)]
    patterns={r'(?i)(nikon|coolpix|firmware|version|boot|rtos|arm|mips|jpeg|sensor|exif)': 'keywords'}
    strings=[]
    for m in re.finditer(rb'[\x20-\x7e]{'+str(args.min_string).encode()+rb',}',data):
        s=m.group().decode('ascii','replace')
        strings.append(f'0x{m.start():08x} {s}')
    report={'file':str(args.firmware),'size_bytes':len(data),'hashes':h,'first_256_hex':data[:256].hex(' '),'signatures':hits,'total_strings':len(strings),'entropy_windows':chunks,'notes':['Signature hits are hypotheses, not proof of file format or CPU architecture.','High entropy may indicate compression, encryption, or other packed data.','Input firmware was read only.']}
    (args.output/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    (args.output/'strings.txt').write_text('\n'.join(strings)+'\n',encoding='utf-8')
    (args.output/'entropy.csv').write_text('offset,size,entropy\n'+''.join(f"{x['offset']},{x['size']},{x['entropy']}\n" for x in chunks),encoding='utf-8')
    print(f"Size: {len(data):,} bytes | SHA256: {h['sha256']}")
    print('First 64 bytes:',data[:64].hex(' '))
    print('Signature candidates:',json.dumps({k:v[:10] for k,v in hits.items()}))
    print(f"Strings found: {len(strings)} | results: {args.output.resolve()}")
if __name__=='__main__':main()
