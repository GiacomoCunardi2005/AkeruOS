#!/usr/bin/env python3
"""Verifica indipendente del dump LUN MSDC (memoria interna) del 21 ottobre 2026.

Non riusa la logica di s33_dump_msdc_lun.py: rilegge read1.img/read2.img e
journal.json e ricalcola tutto da zero, poi ricostruisce i file dalla catena
di cluster FAT12 e controverifica l'assenza dei byte LUN dai dump NAND noti.

Controlli:
  1. dimensioni e SHA-256 integrali di read1.img/read2.img vs journal;
  2. identita' byte per byte delle due letture;
  3. hash per blocco da 1 MiB (read1 vs journal, read2 ricalcolata);
  4. MBR: firma 0xAA55, tabella partizioni, partizione attesa LBA 55/45001;
  5. BPB FAT12: geometria coerente, media 0xF8, due FAT identiche;
  6. directory root e sotto-directory; ricostruzione file da cluster chain,
     con hash e verifica frammentazione;
  7. prefissi hash dei file confrontati con quelli pubblicati nel rapporto;
  8. assenza dei byte distintivi del LUN dai dump NAND esistenti.

Uso: python3 Python_Trace_Scripts/s33_verify_msdc_lun.py [--evidence <cartella>]
Scrive verified_evidence.json nella cartella evidenze (o in una nuova
cartella LUN_verify_<stamp> quando --evidence non e' specificata).
"""
import argparse, hashlib, json, os, struct
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVID = ROOT / 'Risultati/Hardware/MSDC_Default/LUN_interno_20261021T155624Z'
CHUNK = 1 << 20

# Prefissi SHA-256 pubblicati nel rapporto S33_MSDC_LUN_Memoria_Interna_Dump_Doppio.md
REPORT_FILES = {
    ('DCIM/101NIKON/DSCN0144.JPG', 5501197): 'c1bdeff7',
    ('DCIM/101NIKON/DSCN0148.JPG', 6052103): 'bc510026',
    ('DCIM/102NIKON/DSCN0865.JPG', 5776073): '875f73b7',
    ('NCFL/NCMRKLST.LST', 825): 'fd377c13',
}

NAND_DUMPS = ['DUMPS/NANDP1.dmp', 'DUMPS/NANDReserved.dmp', 'DUMPS/MainCode.dmp', 'DUMPS/BootCode.dmp']


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(CHUNK), b''):
            h.update(block)
    return h.hexdigest()


def chunk_hashes(path):
    out = []
    with open(path, 'rb') as f:
        off = 0
        for block in iter(lambda: f.read(CHUNK), b''):
            out.append((off, len(block), hashlib.sha256(block).hexdigest()))
            off += len(block)
    return out


class Fat12:
    def __init__(self, img, part_start, part_sectors):
        self.img = img
        self.part_start = part_start
        bpb_off = part_start * 512
        self.bytes_per_sec = struct.unpack_from('<H', img, bpb_off + 11)[0]
        self.sec_per_clus = img[bpb_off + 13]
        self.rsvd = struct.unpack_from('<H', img, bpb_off + 14)[0]
        self.nfats = img[bpb_off + 16]
        self.fat_sectors = struct.unpack_from('<H', img, bpb_off + 22)[0]
        self.root_entries = struct.unpack_from('<H', img, bpb_off + 17)[0]
        self.media = img[bpb_off + 21]
        self.total16 = struct.unpack_from('<H', img, bpb_off + 19)[0]
        self.total32 = struct.unpack_from('<I', img, bpb_off + 32)[0]
        self.root_secs = (self.root_entries * 32 + self.bytes_per_sec - 1) // self.bytes_per_sec
        self.fat1 = bpb_off + self.rsvd * 512
        self.fat2 = self.fat1 + self.fat_sectors * 512
        self.root_off = self.fat1 + self.nfats * self.fat_sectors * 512
        self.data_sec = (self.root_off - bpb_off) // 512 + self.root_secs
        self.clus_count = (part_sectors - self.data_sec) // self.sec_per_clus
        self.clus_bytes = self.sec_per_clus * self.bytes_per_sec

    def fat_entry(self, n):
        off = n + n // 2
        v = struct.unpack_from('<H', self.img, self.fat1 + off)[0]
        return (v >> 4) if (n & 1) else (v & 0xFFF)

    def chain(self, first):
        out = []
        seen = set()
        c = first
        while 2 <= c < 0xFF8:
            if c in seen or c >= self.clus_count + 2:
                raise ValueError(f'catena cluster invalida: {c}')
            seen.add(c)
            out.append(c)
            c = self.fat_entry(c)
        return out

    def read_chain(self, first, size):
        data = bytearray()
        for c in self.chain(first):
            off = self.part_start * 512 + (self.data_sec + (c - 2) * self.sec_per_clus) * 512
            data += self.img[off:off + self.clus_bytes]
        if len(data) < size:
            raise ValueError(f'catena corta: {len(data)} < {size}')
        return bytes(data[:size])

    def dir_entries(self, off, count):
        ents = []
        for i in range(count):
            e = self.img[off + i * 32: off + (i + 1) * 32]
            if e[0] == 0x00:
                break
            if e[0] == 0xE5 or (e[11] & 0x08):
                continue
            name = e[0:8].decode('ascii', 'replace').strip()
            ext = e[8:11].decode('ascii', 'replace').strip()
            attr = e[11]
            first = struct.unpack_from('<H', e, 26)[0]
            size = struct.unpack_from('<I', e, 28)[0]
            ents.append({'name': f'{name}.{ext}' if ext else name, 'attr': attr,
                         'first_cluster': first, 'size': size})
        return ents

    def list_dir(self, first_cluster=None):
        if first_cluster is None:
            return self.dir_entries(self.root_off, self.root_entries)
        out = []
        for c in self.chain(first_cluster):
            off = self.part_start * 512 + (self.data_sec + (c - 2) * self.sec_per_clus) * 512
            out += self.dir_entries(off, self.clus_bytes // 32)
        return out


def search_needle(hay_path, needles):
    """Cerca piu' pagine da 4 KiB; ritorna {descrizione: offset o None}."""
    res = {}
    with open(hay_path, 'rb') as f:
        data = f.read()
    for desc, needle in needles.items():
        res[desc] = data.find(needle)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--evidence', default=str(DEFAULT_EVID))
    args = ap.parse_args()
    ev = Path(args.evidence)
    j = json.loads((ev / 'journal.json').read_text())
    checks = []
    evd = {'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
           'evidence_dir': str(ev.relative_to(ROOT)), 'checks': checks}

    def check(name, ok, detail):
        checks.append({'check': name, 'ok': bool(ok), 'detail': detail})
        assert ok, f'FALLITO: {name}: {detail}'

    r1, r2 = ev / 'read1.img', ev / 'read2.img'
    check('dimensioni_letture', r1.stat().st_size == r2.stat().st_size == j['bytes'],
          f"{r1.stat().st_size}/{r2.stat().st_size} attesi {j['bytes']}")
    h1, h2 = sha256_file(r1), sha256_file(r2)
    check('sha256_read1_journal', h1 == j['sha256_read1'], h1)
    check('sha256_read2_journal', h2 == j['sha256_read2'], h2)
    check('due_letture_identiche', h1 == h2 and j['two_reads_identical'], h1)

    c1 = chunk_hashes(r1)
    c2 = chunk_hashes(r2)
    check('num_chunk', len(c1) == len(c2) == j['chunks'], f'{len(c1)}/{len(c2)} attesi {j["chunks"]}')
    jp = j['partial_sha256_read1']
    ok = all(a[0] == p['offset'] and a[1] == p['size'] and a[2] == p['sha256']
             for a, p in zip(c1, jp))
    check('hash_per_MiB_read1_journal', ok, f'{len(c1)} chunk confrontati col journal')
    ok = all(a[2] == b[2] for a, b in zip(c1, c2))
    check('hash_per_MiB_read2_ricalcolato', ok, 'read2 identica per chunk, ricalcolata')

    img = r1.read_bytes()
    check('mbr_firma', img[510:512] == b'\x55\xaa', 'firma 0xAA55')
    parts = []
    for i in range(4):
        e = img[446 + i * 16: 446 + (i + 1) * 16]
        if e[4] != 0:
            start = struct.unpack_from('<I', e, 8)[0]
            nsec = struct.unpack_from('<I', e, 12)[0]
            parts.append({'type': e[4], 'lba': start, 'sectors': nsec})
    check('una_partizione', len(parts) == 1 and parts[0]['lba'] == 55 and parts[0]['sectors'] == 45001,
          json.dumps(parts))

    fat = Fat12(img, parts[0]['lba'], parts[0]['sectors'])
    geo = {'bytes_per_sec': fat.bytes_per_sec, 'sec_per_clus': fat.sec_per_clus,
           'reserved': fat.rsvd, 'nfats': fat.nfats, 'fat_sectors': fat.fat_sectors,
           'root_entries': fat.root_entries, 'media': hex(fat.media),
           'root_secs': fat.root_secs, 'clusters': fat.clus_count}
    check('geometria_fat12', (fat.bytes_per_sec == 512 and fat.sec_per_clus == 32 and fat.nfats == 2
                              and fat.fat_sectors == 12 and fat.root_entries == 256 and fat.media == 0xF8),
          json.dumps(geo))
    fat_match = img[fat.fat1:fat.fat1 + fat.fat_sectors * 512] == img[fat.fat2:fat.fat2 + fat.fat_sectors * 512]
    check('fat_copie_identiche', fat_match, 'FAT1==FAT2')

    root = fat.list_dir()
    names = sorted(e['name'] for e in root)
    dirs_root = {e['name'] for e in root if e['attr'] & 0x10}
    check('root_attese', {'DCIM', 'MISC', 'NCFL'} <= dirs_root,
          json.dumps(sorted(names)))
    evd['root_entries'] = root

    files = {}
    for e in root:
        if e['attr'] & 0x10:
            files[e['name']] = fat.list_dir(e['first_cluster'])
    for d, ents in list(files.items()):
        for e in ents:
            if e['attr'] & 0x10:
                files[f'{d}/{e["name"]}'] = fat.list_dir(e['first_cluster'])

    rebuilt = {}
    for path, size in REPORT_FILES:
        d, fn = path.rsplit('/', 1)
        ents = files.get(d, [])
        ent = next((e for e in ents if e['name'] == fn), None)
        check(f'voce_dir:{path}', ent is not None and ent['size'] == size,
              f'entrata {ent}')
        data = fat.read_chain(ent['first_cluster'], ent['size'])
        h = hashlib.sha256(data).hexdigest()
        rebuilt[path] = {'size': ent['size'], 'sha256': h,
                         'clusters': len(fat.chain(ent['first_cluster'])),
                         'contiguous': all(b == a + 1 for a, b in
                                           zip(fat.chain(ent['first_cluster']),
                                               fat.chain(ent['first_cluster'])[1:]))}
        check(f'hash_prefisso:{path}', h.startswith(REPORT_FILES[(path, size)]),
              f'{h[:8]} atteso prefisso {REPORT_FILES[(path, size)]}')
    check('dscn0148_frammentato', not rebuilt['DCIM/101NIKON/DSCN0148.JPG']['contiguous'],
          json.dumps(rebuilt['DCIM/101NIKON/DSCN0148.JPG']))
    check('dscn0144_contiguo', rebuilt['DCIM/101NIKON/DSCN0144.JPG']['contiguous'],
          json.dumps(rebuilt['DCIM/101NIKON/DSCN0144.JPG']))
    evd['files'] = rebuilt

    needles = {'VBR_LBA55': img[55 * 512: 55 * 512 + 512]}
    blk = rebuilt['DCIM/101NIKON/DSCN0144.JPG']
    body = fat.read_chain(
        next(e for e in files['DCIM/101NIKON'] if e['name'] == 'DSCN0144.JPG')['first_cluster'],
        blk['size'])
    needles['bloccointerno_DSCN0144_1MiB'] = body[1 << 20: (1 << 20) + 4096]
    absence = {}
    for d in NAND_DUMPS:
        p = ROOT / d
        if not p.is_file():
            continue
        found = search_needle(p, needles)
        absence[d] = {k: (None if v < 0 else v) for k, v in found.items()}
        check(f'assenza_da:{d}', all(v is None for v in absence[d].values()),
              json.dumps(absence[d]))
    evd['nand_absence'] = absence

    out_dir = ev.parent / f'LUN_verify_{datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")}'
    out_dir.mkdir(parents=True, exist_ok=False)
    evd['result'] = 'PASS'
    (out_dir / 'verified_evidence.json').write_text(json.dumps(evd, indent=2) + '\n')
    (ev.parent / 'LUN_verify_latest.json').write_text(
        json.dumps({'evidence': str((out_dir / 'verified_evidence.json').relative_to(ROOT)),
                    'source_dump': str(ev.relative_to(ROOT))}, indent=2) + '\n')
    print('PASS', len(checks), 'controlli')
    print('cartella:', out_dir)
    for path, info in rebuilt.items():
        print(f'{path}: {info["size"]}B sha256={info["sha256"][:16]}... cluster={info["clusters"]}')


if __name__ == '__main__':
    main()
