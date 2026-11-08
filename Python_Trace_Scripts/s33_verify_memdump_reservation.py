#!/usr/bin/env python3
"""Test a held exclusive reservation against Nikon's original save wrapper."""
from datetime import datetime, timezone
from pathlib import Path
import json
import hashlib
import struct
import subprocess
import tempfile
import sys
from s33_trace_state_dispatch import verified_payloads

ROOT = Path(__file__).resolve().parents[1]


def main():
    blocks, payloads, _ = verified_payloads(ROOT)
    assert sys.argv[1:] in ([], ['--held-writer'], ['--held-diagnostic'])
    held = sys.argv[1:] == ['--held-writer']
    diagnostic = sys.argv[1:] == ['--held-diagnostic']
    script = 'ProbeMemdumpHeldDiagnostic.java' if diagnostic else 'ProbeMemdumpHeldWriter.java' if held else 'ProbeMemdumpReservation.java'
    out = ROOT / 'Risultati/Runtime_Kernel' / ('MEMDUMP_Held_Diagnostic' if diagnostic else 'MEMDUMP_Held_Writer' if held else 'MEMDUMP_Reservation') / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out.mkdir(parents=True)
    scripts = ROOT / 'S33-sections/analysis_ghidra/scripts'
    (out / 'probe_snapshot.java').write_bytes((scripts / 'ProbeMemdumpReservation.java').read_bytes())
    if held or diagnostic:
        (out / 'held_probe_snapshot.java').write_bytes((scripts / script).read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-memdump-fat-') as td:
        temp = Path(td)
        for i in (0, 1):
            (temp / f'p{i}.bin').write_bytes(payloads[i])
        cmd = [str(ROOT / 'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'), str(temp), 'model', '-import', str(temp / 'p0.bin'), '-loader', 'BinaryLoader', '-loader-baseAddr', '0xad800', '-processor', 'ARCompact:LE:32:loopfix', '-noanalysis', '-scriptPath', str(scripts), '-postScript', script, str(out / 'trace.txt'), str(temp / 'p1.bin'), '-deleteProject']
        (out / 'command.json').write_text(json.dumps(cmd, indent=2) + '\n')
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
        (out / 'headless.log').write_text(p.stdout)
        assert p.returncode == 0 and 'SCRIPT ERROR' not in p.stdout, p.stdout[-5000:]
        trace = (out / 'trace.txt').read_text()
        if diagnostic:
            assert trace == 'HELD_DIAG redirects=2 rival=1a00012 first=0/256 second=1a00014/3840 message=39304e closes=1 size=4096\nCOMPLETE cases=1\n', trace
        elif held:
            assert trace == 'HELD open=0 first=0/256 competitor=1a00012 second=0/513 close=0 size=769 reread=769 sectors_preserved=110\nCOMPLETE cases=1\n', trace
        else:
            assert trace == ('RESERVE first=0 held_save=1a00012 release=0 after_save=0 '
                         'second_wrappers=1/1 second_objects=1/1 size=256 sectors_preserved=110 reread=256\n'
                         'COMPLETE cases=1\n'), trace
    image_path = out / ('diagnostic_held.img' if diagnostic else 'held.img' if held else 'reservation.img')
    image=image_path.read_bytes()
    assert len(image)==110*512 and image[100*512:100*512+11]==b'TARGET  BIN'
    size = 4096 if diagnostic else 769 if held else 256
    assert struct.unpack_from('<I',image,100*512+28)[0]==size
    cluster=struct.unpack_from('<H',image,100*512+26)[0]
    assert 2<=cluster<=5
    offset=(102+(cluster-2)*2)*512
    if diagnostic:
        data, chain = bytearray(), []
        while len(data) < size:
            assert 2 <= cluster <= 5 and cluster not in chain
            chain.append(cluster)
            offset=(102+(cluster-2)*2)*512
            data.extend(image[offset:offset+1024])
            pair=struct.unpack_from('<H',image,20*512+cluster+cluster//2)[0]
            cluster=pair>>4 if cluster&1 else pair&0xfff
        assert cluster>=0xff8 and data==bytes((i*37+(i>>8)*97+11)&255 for i in range(size))
    else:
        assert image[offset:offset+size]==bytes((i*37+(i>>8)*97+11)&255 for i in range(size))
    check=subprocess.run(['/usr/bin/fsck.fat','-n',str(image_path)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=30)
    (out/'fsck.txt').write_text(check.stdout)
    assert check.returncode==0 and image_path.read_bytes()==image,check.stdout
    if held or diagnostic:
        (out/'evidence.json').write_text(json.dumps({'status':'PASS_HELD_DIAGNOSTIC_SYNTHETIC_FAT' if diagnostic else 'PASS_HELD_WRITER_SYNTHETIC_FAT','trace':trace,'file_size':size,'image_sha256':hashlib.sha256(image).hexdigest(),'fsck_exit':check.returncode,'limits':['One prepared FAT backend, synthetic heap/controller/DMA and modeled competing open.','Diagnostic redirection is a fixture, not an implemented firmware adapter.' if diagnostic else 'Does not execute the MEMDUMP routine or prove physical exclusivity, memory or SD.']},indent=2)+'\n')
        print(trace,flush=True)
        return
    (out/'evidence.json').write_text(json.dumps({'status':'PASS_RESERVED_FILE_REOPEN_BEHAVIOR_SYNTHETIC_FAT',
        'held_save_status':'0x01a00012','release_status':0,'post_release_save_status':0,
        'sectors_unchanged_on_rejection':110,'reread_bytes':256,'image_sha256':hashlib.sha256(image).hexdigest(),
        'payload_sha256':[b['sha256'] for b in blocks],
        'limits':['One prepared FAT profile with synthetic heap, DMA, controller and scheduler.',
                  'Holding reservation prevents the original wrapper from saving; releasing creates a race.',
                  'No physical SD, concurrent scheduler, complete MEMDUMP or camera.']},indent=2)+'\n')
    print(trace, flush=True)


if __name__ == '__main__':
    main()
