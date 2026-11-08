#!/usr/bin/env python3
"""Observe cached Linux USB/sysfs data only; no PTP session or device writes."""
from datetime import datetime,timezone
from pathlib import Path
import argparse,hashlib,json,subprocess,time
ROOT=Path(__file__).resolve().parents[1]
EXPECTED='af65ab0e66781c1a1036ab2349700e9d2110c6618738b02208da8b83c8813544'


def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def cached_descriptors(data):
 records=[];pos=0
 while pos<len(data):
  assert pos+2<=len(data) and data[pos]>=2 and pos+data[pos]<=len(data),(pos,len(data))
  size,kind=data[pos:pos+2];v=data[pos:pos+size];row=dict(offset=pos,length=size,type=kind,hex=v.hex())
  if kind==4:
   assert size>=9;row.update(interface_number=v[2],alternate=v[3],class_code=v[5],subclass=v[6],protocol=v[7])
  records.append(row);pos+=size
 return records


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--connection-sequence',choices=('powered-on-before-usb','usb-from-off','unknown'),default='unknown')
 parser.add_argument('--reported-installed-file',default=None,help='Filename explicitly reported by the user for this update; never inferred from the local artifact')
 parser.add_argument('--update-screen',choices=('completed','unknown'),default='unknown')
 args=parser.parse_args()
 stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out=ROOT/'Risultati/Hardware/MSDC_Default'/stamp;out.mkdir(parents=True,exist_ok=False)
 artifact=ROOT/'Risultati/Firmware_sperimentali/USB_MSDC_Default/S33_USB_MSDC_DEFAULT_OFFLINE_NON_INSTALLARE.bin';assert digest(artifact)==EXPECTED and artifact.stat().st_size==29602084
 samples=[];errors=[]
 def read(p):
  try:return p.read_text().strip()
  except OSError:return None
 for i in range(10):
  row=dict(utc=datetime.now(timezone.utc).isoformat(),nikon=[])
  for p in sorted(Path('/sys/bus/usb/devices').glob('*')):
   if read(p/'idVendor')!='04b0':continue
   dev=dict(sysfs=str(p),fields={n:read(p/n) for n in ('idVendor','idProduct','manufacturer','product','serial','busnum','devnum','speed','bConfigurationValue')},interfaces=[],block_devices=[],block_device_details=[])
   for q in sorted(p.parent.glob(p.name+':*')):
    interface=dict(name=q.name,fields={n:read(q/n) for n in ('bInterfaceClass','bInterfaceSubClass','bInterfaceProtocol','interface')})
    try:interface['driver']=(q/'driver').resolve(strict=True).name
    except OSError:interface['driver']=None
    dev['interfaces'].append(interface)
   for b in Path('/sys/class/block').glob('*'):
    try:
     if b.resolve().is_relative_to(p.resolve()):
      dev['block_devices'].append(b.name)
      sectors=read(b/'size')
      dev['block_device_details'].append(dict(name=b.name,sysfs=str(b.resolve()),size_sectors_512=int(sectors) if sectors is not None else None,
       size_bytes=int(sectors)*512 if sectors is not None else None,partition=(b/'partition').exists(),device_number=read(b/'dev')))
    except OSError:pass
   try:
    data=(p/'descriptors').read_bytes();name=f'sample_{i:02d}_{p.name}_cached_descriptors.bin';(out/name).write_bytes(data)
    dev.update(descriptors_file=name,descriptors_sha256=hashlib.sha256(data).hexdigest(),descriptors=cached_descriptors(data))
   except (OSError,AssertionError) as exc:errors.append(dict(sample=i,device=str(p),error=repr(exc)))
   row['nikon'].append(dev)
  samples.append(row)
  if i<9:time.sleep(1)
 commands=[]
 for name,cmd in [('nikon_lsusb',['lsusb','-d','04b0:']),('block_metadata',['lsblk','-J','-o','NAME,TYPE,SIZE,TRAN,VENDOR,MODEL,MOUNTPOINTS'])]:
  proc=subprocess.run(cmd,capture_output=True,text=True,timeout=10);(out/(name+'.txt')).write_text(proc.stdout+proc.stderr);commands.append(dict(command=cmd,exit_code=proc.returncode,output=name+'.txt'))
 seen=[d for s in samples for d in s['nikon']];classes=[i['fields']['bInterfaceClass'] for d in seen for i in d['interfaces']]
 stable=all(len(s['nikon'])==1 for s in samples) and len({(d['sysfs'],d['fields']['idProduct'],d['fields']['devnum']) for d in seen})==1
 def triples(d):return [tuple(i['fields'][n] for n in ('bInterfaceClass','bInterfaceSubClass','bInterfaceProtocol')) for i in d['interfaces']]
 ptp=stable and all(triples(d)==[('06','01','01')] and not d['block_devices'] for d in seen)
 msdc=stable and not errors and all(d['fields']['idProduct']=='035d' and triples(d)==[('08','06','50')] and
  d['block_devices'] and all(i['driver']=='usb-storage' for i in d['interfaces']) and 'descriptors' in d for d in seen)
 for d in seen:
  if 'descriptors' in d:
   actual=[(v['class_code'],v['subclass'],v['protocol']) for v in d['descriptors'] if v['type']==4]
   reported=[tuple(int(v['fields'][n],16) for n in ('bInterfaceClass','bInterfaceSubClass','bInterfaceProtocol')) for v in d['interfaces']]
   assert actual==reported,(actual,reported)
 (out/'collector_snapshot.py').write_bytes(Path(__file__).read_bytes())
 zero_capacity=msdc and all(all(b['size_bytes']==0 for b in d['block_device_details']) for d in seen)
 report=dict(status='OBSERVED_MSDC_ZERO_CAPACITY' if zero_capacity else 'OBSERVED_MSDC_WITH_NIKON_BLOCK_DEVICE' if msdc else 'OBSERVED_PTP_NO_MSC' if ptp else 'OBSERVATION_REQUIRES_REVIEW',utc=stamp,
  user_report=dict(installed_file=args.reported_installed_file,update_screen=args.update_screen,connection_sequence=args.connection_sequence),
  local_candidate=dict(path=str(artifact.relative_to(ROOT)),sha256=EXPECTED,bytes=artifact.stat().st_size),
  commands=commands,samples=samples,errors=errors,
  limits=['User report identifies installed filename; actual flash bytes/version not read back',
          'Only cached USB descriptors/sysfs and OS enumeration/block metadata; no PTP session, raw SD read or device write',
          'Enumeration is an observed result of this connection, not proof of RAM selector, executed patch bytes or universal boot behavior',
          'No physical recovery or hardware safety certification'])
 report['files']={str(p.relative_to(out)):digest(p) for p in sorted(out.iterdir()) if p.is_file()}
 (out/'observation.json').write_text(json.dumps(report,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps(dict(observation=str((out/'observation.json').relative_to(ROOT))),indent=2)+'\n')
 print(json.dumps(dict(status=report['status'],observation=str((out/'observation.json').relative_to(ROOT)),samples=len(samples),interfaces=classes,block_devices=sorted({n for d in seen for n in d['block_devices']}),errors=errors),indent=2),flush=True)


if __name__=='__main__':main()
