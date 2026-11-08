#!/usr/bin/env python3
"""Dump read-only dell'intero LUN MSDC Nikon (memoria interna) con doppia lettura.

Apre il disco SOLO in lettura (os.open O_RDONLY), lo legge per intero due volte,
confronta le due copie e scrive immagine, hash e diario in una cartella con
timestamp sotto Risultati/Hardware/MSDC_Default/. Non scrive mai sul device.

Uso: sudo python3 Python_Trace_Scripts/s33_dump_msdc_lun.py [--device /dev/sda]
Il default e' /dev/sda. Con un file regolare come --device funziona in offline
(autotest).
"""
import argparse, hashlib, json, os, struct, sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHUNK = 1 << 20  # 1 MiB
EXPECT_SECTORS = 45056


def sha_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(CHUNK), b''):
            h.update(block)
    return h.hexdigest()


def read_pass(fd, total, out_path):
    """Una lettura completa del device in chunk da 1 MiB; hash per chunk."""
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256()
    parts = []
    done = 0
    with open(out_path, 'wb') as out:
        while done < total:
            n = min(CHUNK, total - done)
            data = os.read(fd, n)
            if not data:
                raise SystemExit(f'lettura interrotta a {done} byte di {total}')
            if len(data) != n:
                raise SystemExit(f'lettura corta: {len(data)} byte attesi {n} a {done}')
            out.write(data)
            h.update(data)
            parts.append({'offset': done, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
            done += len(data)
    return h.hexdigest(), parts


def usb_identity(dev_name):
    base = Path(f'/sys/class/block/{dev_name}')
    info = {}
    for parent in [base, *base.resolve().parents]:
        p = parent / 'idVendor'
        if p.is_file() and 'idProduct' in {q.name for q in parent.iterdir()}:
            info['usb_vendor'] = (parent / 'idVendor').read_text().strip()
            info['usb_product'] = (parent / 'idProduct').read_text().strip()
            for key in ('manufacturer', 'product', 'serial'):
                q = parent / key
                if q.is_file():
                    info[key] = q.read_text().strip()
            break
    for key in ('size', 'stat'):
        q = base / key
        if q.is_file():
            info[key] = q.read_text().strip()[:200]
    q = base / 'device' / 'model'
    if q.is_file():
        info['model'] = q.read_text().strip()
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--device', default='/dev/sda')
    args = ap.parse_args()
    dev = Path(args.device)
    if os.geteuid() != 0 and not dev.is_file():
        raise SystemExit('serve root: esegui con sudo')

    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = ROOT / 'Risultati/Hardware/MSDC_Default' / f'LUN_interno_{stamp}'
    out.mkdir(parents=True, exist_ok=False)

    fd = os.open(str(dev), os.O_RDONLY)
    if dev.name.startswith('sd') or dev.name.startswith('sg') or 'mmcblk' in dev.name:
        size_file = Path(f'/sys/class/block/{dev.name.replace("sg", "sd")}/size')
        sectors = int(size_file.read_text().strip()) if size_file.is_file() else None
        total = (sectors * 512) if sectors else (os.fstat(fd).st_size or 0)
    else:
        total = os.fstat(fd).st_size

    h1, parts1 = read_pass(fd, total, out / 'read1.img')
    h2, parts2 = read_pass(fd, total, out / 'read2.img')
    os.close(fd)

    same = h1 == h2 and all(a['sha256'] == b['sha256'] for a, b in zip(parts1, parts2))
    identity = usb_identity(dev.name) if dev.name.startswith(('sd', 'sg')) else {'offline_test_file': str(dev)}

    journal = {
        'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'device': str(dev),
        'mode': 'O_RDONLY, no write to device',
        'bytes': total,
        'sectors_512': total // 512 if total % 512 == 0 else None,
        'sectors_expected_when_nikon_msdc_22MiB': EXPECT_SECTORS,
        'identity': identity,
        'sha256_read1': h1,
        'sha256_read2': h2,
        'two_reads_identical': same,
        'chunks': len(parts1),
        'partial_sha256_read1': parts1,
    }
    (out / 'journal.json').write_text(json.dumps(journal, indent=2) + '\n')
    (out.parent / 'LUN_interno_latest.json').write_text(
        json.dumps({'evidence': str((out / 'journal.json').relative_to(ROOT))}, indent=2) + '\n')
    print('PASS' if same else 'MISMATCH')
    print(f'cartella: {out}')
    print(f'byte: {total}  sha256: {h1}')
    print('scritti read1.img read2.img journal.json; nessuna scrittura sul device')


if __name__ == '__main__':
    main()
