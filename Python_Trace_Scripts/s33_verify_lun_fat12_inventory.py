#!/usr/bin/env python3
"""Independent FAT12 inventory of the MSDC internal-memory LUN from the double dump.

Parses the MBR/FAT12 structures of read1.img directly (no mount, no OS cache),
enumerates every file and directory, rebuilds each cluster chain, detects
fragmentation, recomputes per-file SHA-256, and cross-checks the mounted-read
hashes reported in the LUN checkpoint. Read-only on all inputs.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import struct

from s33_run_gnu_arc700 import ROOT, sha
from s33_verify_nand_pc_dump_journal import verify_lun_images, LUN_DIR

SECTOR = 512
EVIDENCE = ROOT/'Risultati/Hardware/MSDC_Default'
EXPECTED = {  # from the LUN report (mounted reads): name -> (size, sha256 prefix)
    'DSCN0144.JPG': (5501197, 'c1bdeff7'),
    'DSCN0148.JPG': (6052103, 'bc510026'),
    'DSCN0865.JPG': (5776073, '875f73b7'),
    'NCMRKLST.LST': (825, 'fd377c13'),
}


def fat12_entry(fat, n):
    off = n//2*3
    if n % 2 == 0:
        return fat[off] | ((fat[off+1] & 0xF) << 8)
    return (fat[off+1] >> 4) | (fat[off+2] << 4)


def parse(image):
    # MBR: single partition entry expected at LBA55 for 45001 sectors.
    assert image[510:512] == b'\x55\xaa', 'firma MBR assente'
    entries = []
    for i in range(4):
        entry = image[446+16*i:446+16*i+16]
        if entry[4] == 0:
            continue
        start, size = struct.unpack_from('<II', entry, 8)
        entries.append((entry[4], start, size))
    assert len(entries) == 1 and entries[0][0] == 0x01, entries  # FAT12 type, single
    part_start, part_sectors = entries[0][1], entries[0][2]
    assert (part_start, part_sectors) == (55, 45001), (part_start, part_sectors)
    bpb = part_start*SECTOR
    assert image[bpb+510:bpb+512] == b'\x55\xaa', 'firma VBR assente'
    bytes_sector, sec_cluster, reserved, nfats, root_entries = struct.unpack_from('<HBHBH', image, bpb+11)
    media = image[bpb+21]
    fats_sectors = struct.unpack_from('<H', image, bpb+22)[0]
    total_sectors = struct.unpack_from('<H', image, bpb+19)[0]
    hidden = struct.unpack_from('<I', image, bpb+28)[0]
    if total_sectors == 0:
        total_sectors = struct.unpack_from('<I', image, bpb+32)[0]
    assert (bytes_sector, sec_cluster, reserved, nfats, root_entries) == (512, 32, 1, 2, 256)
    assert media == 0xF8 and (fats_sectors, total_sectors) == (12, part_sectors)
    assert hidden == part_start, (hidden, part_start)
    root_sectors = root_entries*32//bytes_sector
    fat_offset = (part_start+reserved)*SECTOR
    fat_bytes = fats_sectors*bytes_sector
    fat1 = image[fat_offset:fat_offset+fat_bytes]
    fat2 = image[fat_offset+fat_bytes:fat_offset+2*fat_bytes]
    assert fat1 == fat2, 'le due FAT differiscono'
    data_start_sector = part_start+reserved+nfats*fats_sectors+root_sectors
    clusters = (part_sectors-(data_start_sector-part_start))//sec_cluster
    geometry = dict(partition_start_lba=part_start, partition_sectors=part_sectors,
                    bytes_per_sector=bytes_sector, sectors_per_cluster=sec_cluster,
                    reserved_sectors=reserved, fats=nfats, fat_sectors=fats_sectors,
                    root_entries=root_entries, media=hex(media), data_start_lba=data_start_sector,
                    total_clusters=clusters, fats_identical=True)
    return fat1, data_start_sector, clusters, geometry


def chain(fat, start, limit):
    clusters = []
    current = start
    seen = set()
    while 2 <= current < limit:
        assert current not in seen, 'anello nella catena cluster'
        seen.add(current)
        clusters.append(current)
        current = fat12_entry(fat, current)
        if current >= 0xFF8:
            break
    return clusters


def read_dir(image, fat, data_start_sector, clusters, dir_clusters, path):
    entries = []
    blob = b''.join(cluster_bytes(image, data_start_sector, clusters, c) for c in dir_clusters)
    i = 0
    while i+32 <= len(blob):
        raw = blob[i:i+32]
        first = raw[0]
        if first == 0x00:
            break
        attrib = raw[11]
        if attrib & 0x3F == 0x0F or first == 0xE5 or first == 0x2E:  # LFN, deleted, '.'/'..': skip
            i += 32
            continue
        name = raw[0:8].decode('ascii', 'replace').rstrip()+('.'+raw[8:11].decode('ascii', 'replace').rstrip() if raw[8:11].strip() else '')
        first_cluster = struct.unpack_from('<H', raw, 26)[0]
        size = struct.unpack_from('<I', raw, 28)[0]
        child_path = path+name
        if attrib & 0x10:  # directory
            if first_cluster in (0, 1):
                entries.append(dict(path=child_path, kind='directory', size=0, clusters=0, fragmented=False))
            else:
                dc = chain(fat, first_cluster, clusters+2)
                entries.append(dict(path=child_path, kind='directory', size=len(dc)*32,
                                    first_cluster=first_cluster,
                                    clusters=len(dc), fragmented=len(dc) > 1))
                entries += read_dir(image, fat, data_start_sector, clusters, dc, child_path+'/')
        else:
            fc = chain(fat, first_cluster, clusters+2)
            data = b''.join(cluster_bytes(image, data_start_sector, clusters, c) for c in fc)[:size]
            digest = hashlib.sha256(data).hexdigest()
            entry = dict(path=child_path, kind='file', size=size, first_cluster=first_cluster,
                         clusters=len(fc), fragmented=len(fc) > 1 and len(fc) > 1,
                         contiguous=fc == list(range(fc[0], fc[0]+len(fc))) if fc else True,
                         sha256=digest, lba_extent=[data_start_sector+(fc[0]-2)*32,
                                                    data_start_sector+(fc[-1]-2)*32+31] if fc else None)
            entries.append(entry)
        i += 32
    return entries


def cluster_bytes(image, data_start_sector, total, n):
    offset = (data_start_sector+(n-2)*32)*SECTOR
    return image[offset:offset+32*SECTOR]


def main():
    out = EVIDENCE/('LUN_FAT12_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    out.mkdir(parents=True, exist_ok=False)
    try:
        lun = verify_lun_images()  # independent double-read/absence re-check reused
        image = (LUN_DIR/'read1.img').read_bytes()
        fat, data_start, nclusters, geometry = parse(image)
        root_dir_offset = (55+1+2*12)*SECTOR  # root directory is a fixed reserved area
        entries = []
        i = 0
        while i+32 <= 256*32:
            raw = image[root_dir_offset+i:root_dir_offset+i+32]
            if raw[0] == 0x00:
                break
            attrib = raw[11]
            if not (attrib & 0x3F == 0x0F) and raw[0] != 0xE5:
                name = raw[0:8].decode('ascii', 'replace').rstrip()+('.'+raw[8:11].decode('ascii', 'replace').rstrip() if raw[8:11].strip() else '')
                first = struct.unpack_from('<H', raw, 26)[0]
                size = struct.unpack_from('<I', raw, 28)[0]
                if attrib & 0x10:
                    dc = chain(fat, first, nclusters+2)
                    entries.append(dict(path=name, kind='directory', size=len(dc)*32, first_cluster=first,
                                        clusters=len(dc), fragmented=len(dc) > 1))
                    entries += read_dir(image, fat, data_start, nclusters, dc, name+'/')
                else:
                    entries += _file_entry(image, fat, data_start, nclusters, name, size, first)
            i += 32
        files = [e for e in entries if e['kind'] == 'file']
        dirs = [e for e in entries if e['kind'] == 'directory']
        # Cross-check with the mounted-read hashes from the LUN checkpoint.
        checks = []
        for name, (size, prefix) in EXPECTED.items():
            match = [e for e in files if e['path'].endswith('/'+name) or e['path'] == name]
            assert len(match) == 1, (name, match)
            e = match[0]
            assert e['size'] == size and e['sha256'].startswith(prefix), (name, e)
            checks.append(dict(name=name, size=size, hash_prefix=prefix, matched=True,
                              fragmented=e['fragmented'], clusters=e['clusters'],
                              lba_extent=e['lba_extent']))
        # FAT consistency: no cluster referenced by two chains (simple full-walk audit).
        referenced = set()
        for e in files+dirs:
            if e['clusters'] and e.get('first_cluster'):
                for c in chain(fat, e['first_cluster'], nclusters+2):
                    assert c not in referenced, f'cluster {c} condiviso'
                    referenced.add(c)
        used_data_clusters = len(referenced)
        free = sum(1 for n in range(2, nclusters+2) if fat12_entry(fat, n) == 0)
        assert used_data_clusters+free == nclusters, (used_data_clusters, free, nclusters)
        result = dict(status='PASS_LUN_FAT12_INDEPENDENT_INVENTORY',
                      geometry=geometry,
                      files=[dict(path=e['path'], size=e['size'], clusters=e['clusters'],
                                  fragmented=e['fragmented'], contiguous=e.get('contiguous'),
                                  sha256=e['sha256'], lba_extent=e['lba_extent']) for e in files],
                      directories=[dict(path=e['path'], clusters=e['clusters'], fragmented=e['fragmented']) for e in dirs],
                      mounted_hash_cross_checks=checks,
                      used_data_clusters=used_data_clusters, free_clusters=free,
                      total_data_clusters=nclusters,
                      lun_recheck=lun,
                      limits=['Static parse of one dump; the FAT and files are as the camera firmware wrote them',
                              'LBA extents are logical within the 22MiB LUN: physical NAND mapping remains unknown',
                              'No write, no mount, no new acquisition; the region is still absent from all known dumps'],
                      sources={str(p): sha(p) for p in [LUN_DIR/'read1.img', LUN_DIR/'read2.img', LUN_DIR/'journal.json']})
        (out/'verified_evidence.json').write_text(json.dumps(result, indent=2, ensure_ascii=False)+'\n')
        (EVIDENCE/'LUN_FAT12_latest.json').write_text(json.dumps(
            dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))), indent=2)+'\n')
        print('PASS', out)
        for e in files:
            print(f"  {e['path']:28s} {e['size']:9d}B clusters={e['clusters']} frag={e['fragmented']} lba={e['lba_extent']}")
        print('  dirs:', [d['path'] for d in dirs])
        print('  used clusters:', used_data_clusters, 'free:', free, 'of', nclusters)
    except BaseException as exc:
        (out/'failure.json').write_text(json.dumps(dict(status='FAIL', error=repr(exc)), indent=2)+'\n')
        raise


def _file_entry(image, fat, data_start, nclusters, name, size, first):
    fc = chain(fat, first, nclusters+2)
    data = b''.join(cluster_bytes(image, data_start, nclusters, c) for c in fc)[:size]
    return [dict(path=name, kind='file', size=size, first_cluster=first, clusters=len(fc),
                 fragmented=(fc != list(range(fc[0], fc[0]+len(fc)))) if len(fc) > 1 else False,
                 contiguous=fc == list(range(fc[0], fc[0]+len(fc))) if fc else True,
                 sha256=hashlib.sha256(data).hexdigest(),
                 lba_extent=[data_start+(fc[0]-2)*32, data_start+(fc[-1]-2)*32+31] if fc else None)]


if __name__ == '__main__':
    main()
