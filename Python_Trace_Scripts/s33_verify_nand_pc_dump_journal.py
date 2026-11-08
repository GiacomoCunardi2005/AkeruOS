#!/usr/bin/env python3
"""Independent validation of AKRN dump artifacts (manifest/journal/raw) and known-dump comparison.

Unlike s33_verify_nand_pc_dump.py, which drives the client during acquisition,
this verifier only reads the files a run leaves on disk and recomputes every
claim from the bytes themselves. It also locates each page in the known camera
dumps (page-aligned records of NANDP1 plus substring search in the other
exports) and independently re-checks the MSDC internal-memory LUN images.

No device, no firmware, no writes to any input: read-only on evidence and dumps.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil

from s33_run_gnu_arc700 import ROOT, sha

RAW_BYTES = 2112          # driver profile constant, independently restated here
PAGES_PER_BLOCK = 64      # driver profile constant, independently restated here
EVIDENCE = ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'
KNOWN_DUMPS = ROOT/'DUMPS'
PAGE_DUMPS = ['NANDP1.dmp']             # integral RAW_BYTES stride, page-aligned records
SUBSTRING_DUMPS = ['MainCode.dmp', 'NANDReserved.dmp', 'BootCode.dmp']
LUN_DIR = ROOT/'Risultati/Hardware/MSDC_Default/LUN_interno_20261021T155624Z'
SUBSTRING_SAMPLE = 16                     # pages per directory searched as substrings


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def next_coordinate(chip, first_block, blocks, index):
    """Expected linear coordinate of journal row `index`, or None past the end."""
    if not 0 <= index < blocks*PAGES_PER_BLOCK:
        return None
    return dict(chip=chip, block=first_block+index//PAGES_PER_BLOCK, page=index % PAGES_PER_BLOCK)


def verify_directory(directory):
    """Recompute every artifact claim from the files alone. Raises AssertionError.

    Uses no client code: the only inputs are the configured driver profile
    constants restated at module level. Returns what was checked.
    """
    directory = Path(directory)
    manifest = json.loads((directory/'manifest.json').read_text())
    status = manifest['status']
    journal_path = directory/'pages.jsonl'
    rows = [json.loads(line) for line in journal_path.read_text().splitlines()] if journal_path.exists() else []
    if status == 'FAILED_BEFORE_ACQUISITION':
        assert manifest['pages_written'] == 0 and not rows
        assert manifest.get('error') and manifest.get('error_type')
        assert not (directory/'dump.raw').exists() and not (directory/'dump.raw.partial').exists()
        return dict(directory=str(directory), status=status, verdict='OK_INCOMPLETE_BEFORE_ACQUISITION',
                    pages=0, checks=['pages_written==0', 'no journal', 'no raw files', 'error recorded'])
    chip, first_block, blocks = manifest['chip'], manifest['first_block'], manifest['blocks']
    assert 0 <= chip <= 255 and 0 <= first_block and first_block+blocks <= 512, 'range fuori dal profilo'
    assert manifest['raw_bytes_per_page'] == RAW_BYTES and manifest['pages_per_block'] == PAGES_PER_BLOCK
    assert manifest['pages_expected'] == blocks*PAGES_PER_BLOCK
    assert manifest['pages_written'] == len(rows), (manifest['pages_written'], len(rows))
    assert manifest['bytes_written'] == len(rows)*RAW_BYTES
    assert manifest['pages_expected'] >= len(rows) >= 0
    # Coordinates must cover the requested range exactly, in order, no gaps.
    for i, row in enumerate(rows):
        expected = next_coordinate(chip, first_block, blocks, i)
        assert dict(chip=row['chip'], block=row['block'], page=row['page']) == expected, (i, row, expected)
        assert row['offset'] == i*RAW_BYTES and row['bytes'] == RAW_BYTES, (i, row)
    if rows and 'last_compared_page' in manifest:
        assert manifest['last_compared_page'] == dict(chip=rows[-1]['chip'], block=rows[-1]['block'], page=rows[-1]['page'])
    final = directory/'dump.raw'
    partial = directory/'dump.raw.partial'
    if status == 'COMPLETE_DOUBLE_READ_LOCAL_FILE_VERIFIED':
        assert final.exists() and not partial.exists(), (final, partial)
        raw = final
    elif status == 'FAILED':
        assert partial.exists() and not final.exists(), (final, partial)
        raw = partial
    elif status == 'RUNNING':
        # A RUNNING manifest is explicitly incomplete; exactly one raw file may exist.
        present = [p for p in (final, partial) if p.exists()]
        assert len(present) == 1, f'RUNNING senza file raw univoco: {present}'
        raw = present[0]
    else:
        raise AssertionError(f'Stato manifest non riconosciuto: {status}')
    size = raw.stat().st_size
    assert size == manifest['bytes_written'], (size, manifest['bytes_written'])
    with raw.open('rb') as stream:
        for i, row in enumerate(rows):
            page = stream.read(RAW_BYTES)
            assert len(page) == RAW_BYTES and _sha(page) == row['sha256'], (i, 'contento/hash non corrispondenti')
        assert stream.read(1) == b'', 'file raw piu lungo del diario'
    if status == 'COMPLETE_DOUBLE_READ_LOCAL_FILE_VERIFIED':
        assert manifest['pages_written'] == manifest['pages_expected'], 'completato con pagine mancanti'
        assert manifest['sha256'] == _sha(raw.read_bytes()), 'sha256 del manifest non corrisponde'
        assert manifest.get('completed_utc') and manifest['output'] == 'dump.raw'
        verdict = 'OK_COMPLETE'
    elif status == 'FAILED':
        failure = manifest['failed_coordinate']
        last = next_coordinate(chip, first_block, blocks, len(rows)-1) if rows else None
        following = next_coordinate(chip, first_block, blocks, len(rows))
        assert failure in (last, following), (failure, last, following)
        assert manifest.get('error') and manifest.get('error_type') and manifest.get('failed_utc')
        verdict = 'OK_FAILED_PRESERVED_PARTIAL'
    else:
        verdict = 'INCOMPLETE_RUNNING'
    return dict(directory=str(directory), status=status, verdict=verdict, pages=len(rows),
                checks=['coordinate esatte e ordinate', 'offset contigui', 'hash pagine ricomputati',
                        'dimensione raw uguale a bytes_written', 'invarianti di stato'])


def known_page_index(dumps_dir=KNOWN_DUMPS):
    """Index page-aligned records of the integral-stride dumps by sha256."""
    index = {}
    for name in PAGE_DUMPS:
        data = (Path(dumps_dir)/name).read_bytes()
        assert len(data) % RAW_BYTES == 0, name
        for i in range(0, len(data), RAW_BYTES):
            index.setdefault(_sha(data[i:i+RAW_BYTES]), []).append(dict(dump=name, record=i//RAW_BYTES, offset=i))
    return index


_SUB_CACHE = {}


def substring_search(page, dumps_dir=KNOWN_DUMPS):
    """Search a page as a substring in the non-page-aligned known exports."""
    hits = []
    for name in SUBSTRING_DUMPS:
        if name not in _SUB_CACHE or _SUB_CACHE[name][0] != dumps_dir:
            _SUB_CACHE[name] = (dumps_dir, (Path(dumps_dir)/name).read_bytes())
        data = _SUB_CACHE[name][1]
        start = 0
        while True:
            found = data.find(page, start)
            if found < 0:
                break
            hits.append(dict(dump=name, offset=found)); start = found+1
    return hits


def compare_directory_with_known(directory, index=None, dumps_dir=KNOWN_DUMPS):
    """Compare journal pages of a dump directory against the known camera dumps.

    Aligned records are checked for every page; substring search covers a
    sample (SUBSTRING_SAMPLE) because the aligned index is exhaustive for the
    only page-aligned export. Byte identity only: no physical mapping implied.
    """
    index = known_page_index(dumps_dir) if index is None else index
    directory = Path(directory)
    manifest = json.loads((directory/'manifest.json').read_text())
    raw = directory/('dump.raw' if manifest['status'] == 'COMPLETE_DOUBLE_READ_LOCAL_FILE_VERIFIED' else 'dump.raw.partial')
    rows = [json.loads(line) for line in (directory/'pages.jsonl').read_text().splitlines()]
    results = []
    with raw.open('rb') as stream:
        for i, row in enumerate(rows):
            page = stream.read(RAW_BYTES)
            aligned = index.get(_sha(page), [])
            substr = substring_search(page, dumps_dir) if i % max(1, len(rows)//SUBSTRING_SAMPLE or 1) == 0 else None
            results.append(dict(**{k: row[k] for k in ('chip', 'block', 'page', 'offset')},
                                aligned_records=len(aligned),
                                substring_hits=len(substr) if substr is not None else None,
                                known=bool(aligned) or bool(substr),
                                first_aligned_match=aligned[0] if aligned else None))
    return results


def verify_lun_images(lun_dir=LUN_DIR, dumps_dir=KNOWN_DUMPS):
    """Independent re-check of the MSDC LUN double dump: hashes, chunks, absence from known dumps."""
    lun_dir = Path(lun_dir)
    journal = json.loads((lun_dir/'journal.json').read_text())
    first = (lun_dir/'read1.img').read_bytes()
    second = (lun_dir/'read2.img').read_bytes()
    checks = dict(bytes=len(first), two_reads_identical=first == second,
                  sha256_read1=_sha(first), sha256_read2=_sha(second),
                  hashes_match_journal=_sha(first) == journal['sha256_read1'] == journal['sha256_read2'],
                  identical_claim=journal['two_reads_identical'],
                  sectors=len(first)//512 == journal['sectors_512'] == 45056,
                  size_multiple_of_sector=len(first) % 512 == 0)
    assert checks['two_reads_identical'] and checks['hashes_match_journal'] and checks['identical_claim'] and checks['sectors']
    chunks = [_sha(first[i:i+1024*1024]) for i in range(0, len(first), 1024*1024)]
    assert chunks == [c['sha256'] for c in journal['partial_sha256_read1']] and len(chunks) == journal['chunks'] == 22
    # Distinctive bytes (FAT12 VBR at LBA55, a JPEG data slice): must not appear
    # in any known dump. Independent repetition of the LUN report claim.
    distinctive = [('vbr_lba55', first[55*512:55*512+512]),
                   ('dscn_slice', first[4*1024*1024:4*1024*1024+RAW_BYTES])]
    absent = {}
    for label, blob in distinctive:
        locations = []
        for name in PAGE_DUMPS:
            data = (Path(dumps_dir)/name).read_bytes()
            start = 0
            while True:
                found = data.find(blob, start)
                if found < 0:
                    break
                locations.append(dict(dump=name, offset=found)); start = found+1
        locations += substring_search(blob, dumps_dir)
        absent[label] = locations
    assert not any(absent.values()), absent
    return dict(checks=checks, chunk_hashes=len(chunks), distinctive_bytes_absent_from_known_dumps=absent,
                lun_sha256=checks['sha256_read1'])


def main():
    out = EVIDENCE/('pc_dump_journal_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    out.mkdir(parents=True, exist_ok=False)
    try:
        scenario_root = EVIDENCE/'pc_dump_20261021T143223Z'
        # 1. Positive: independently revalidate every artifact of the offline scenarios.
        def pattern(chip, block, page):
            return bytes((chip, block >> 8, block & 255, page))*528
        positives = []
        expected_status = dict(two_blocks='COMPLETE_DOUBLE_READ_LOCAL_FILE_VERIFIED', last_block='COMPLETE_DOUBLE_READ_LOCAL_FILE_VERIFIED',
                               mismatch_second_read='FAILED', short_second_read='FAILED', scsi_error='FAILED', ioctl_error='FAILED',
                               interrupted='FAILED', progress_manifest_failure='FAILED', final_manifest_failure='FAILED',
                               identity_failure='FAILED_BEFORE_ACQUISITION')
        for name, want in expected_status.items():
            verdict = verify_directory(scenario_root/name)
            assert verdict['status'] == want, (name, verdict)
            manifest = json.loads((scenario_root/name/'manifest.json').read_text())
            if verdict['pages']:
                raw = scenario_root/name/('dump.raw' if want == 'COMPLETE_DOUBLE_READ_LOCAL_FILE_VERIFIED' else 'dump.raw.partial')
                data = raw.read_bytes()
                chip, fb, blocks = manifest['chip'], manifest['first_block'], manifest['blocks']
                expected = b''.join(pattern(chip, b, p) for b in range(fb, fb+blocks) for p in range(PAGES_PER_BLOCK))
                assert data == expected[:len(data)], name
            positives.append(dict(name=name, verdict=verdict['verdict'], pages=verdict['pages']))
        # 2. Negative: tampered copies must all be rejected; originals are never touched.
        tampered = []
        base = out/'tampered_source'
        shutil.copytree(scenario_root/'two_blocks', base)
        def expect_reject(name, source, fn):
            target = out/name
            shutil.copytree(source, target)
            fn(target)
            try:
                verify_directory(target)
            except AssertionError as exc:
                tampered.append(dict(name=name, rejected=True, reason=str(exc)[:160]))
            else:
                raise AssertionError(f'manomissione non rifiutata: {name}')
        def flip_raw(t):
            p = t/'dump.raw'; data = bytearray(p.read_bytes()); data[RAW_BYTES*10+5] ^= 0xff; p.write_bytes(bytes(data))
        def forge_hash(t):
            p = t/'pages.jsonl'; rows = [json.loads(l) for l in p.read_text().splitlines()]
            rows[3]['sha256'] = '00'*32; p.write_text(''.join(json.dumps(r)+'\n' for r in rows))
        def drop_row(t):
            p = t/'pages.jsonl'; lines = p.read_text().splitlines(); lines.pop(7); p.write_text('\n'.join(lines)+'\n')
        def swap_pages(t):
            p = t/'pages.jsonl'; rows = [json.loads(l) for l in p.read_text().splitlines()]
            rows[20]['page'] = 0; p.write_text(''.join(json.dumps(r)+'\n' for r in rows))
        def inflate_pages(t):
            m = json.loads((t/'manifest.json').read_text()); m['pages_written'] = 130
            (t/'manifest.json').write_text(json.dumps(m))
        def truncate_partial(t):
            p = t/'dump.raw.partial'; p.write_bytes(p.read_bytes()[:-100])
        def fake_complete(t):
            m = json.loads((t/'manifest.json').read_text()); m['status'] = 'COMPLETE_DOUBLE_READ_LOCAL_FILE_VERIFIED'
            (t/'manifest.json').write_text(json.dumps(m))
        def running_left(t):
            m = json.loads((t/'manifest.json').read_text()); m['status'] = 'RUNNING'
            (t/'manifest.json').write_text(json.dumps(m))
        expect_reject('flip_raw_byte', base, flip_raw)
        expect_reject('forged_journal_hash', base, forge_hash)
        expect_reject('dropped_journal_row', base, drop_row)
        expect_reject('swap_pages_order', base, swap_pages)
        expect_reject('inflated_pages_written', base, inflate_pages)
        expect_reject('truncate_partial', scenario_root/'interrupted', truncate_partial)
        expect_reject('fake_complete_on_partial', scenario_root/'interrupted', fake_complete)
        assert verify_directory(base)['verdict'] == 'OK_COMPLETE', 'la copia degli originali resta valida'
        running = out/'running_copy'; shutil.copytree(base, running); running_left(running)
        assert verify_directory(running)['verdict'] == 'INCOMPLETE_RUNNING'
        # 3. Known-dump comparison on real bytes: page-aligned fixture from NANDP1.
        nandp1 = (KNOWN_DUMPS/'NANDP1.dmp').read_bytes()
        records = len(nandp1)//RAW_BYTES
        hashes = [_sha(nandp1[i*RAW_BYTES:(i+1)*RAW_BYTES]) for i in range(records)]
        counts = {}
        for h in hashes:
            counts[h] = counts.get(h, 0)+1
        unique_window = None
        for start in range(1, records-128):
            if all(counts[hashes[i]] == 1 for i in range(start, start+128)):
                unique_window = start; break
        assert unique_window is not None, 'nessuna finestra di record unici trovata'
        fixture = out/'known_fixture'
        fixture.mkdir()
        pages = [nandp1[i*RAW_BYTES:(i+1)*RAW_BYTES] for i in range(unique_window, unique_window+128)]
        (fixture/'dump.raw').write_bytes(b''.join(pages))
        rows = [dict(chip=0, block=unique_window//PAGES_PER_BLOCK+b, page=p, offset=(b*PAGES_PER_BLOCK+p)*RAW_BYTES,
                     bytes=RAW_BYTES, sha256=_sha(pages[b*PAGES_PER_BLOCK+p])) for b in range(2) for p in range(PAGES_PER_BLOCK)]
        (fixture/'pages.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
        (fixture/'manifest.json').write_text(json.dumps(dict(
            status='COMPLETE_DOUBLE_READ_LOCAL_FILE_VERIFIED', started_utc=datetime.now(timezone.utc).isoformat(),
            device=dict(fixture=True), chip=0, first_block=unique_window//PAGES_PER_BLOCK, blocks=2,
            pages_per_block=PAGES_PER_BLOCK, raw_bytes_per_page=RAW_BYTES, pages_expected=128, pages_written=128,
            bytes_written=128*RAW_BYTES, reads_per_page=2, completed_utc=datetime.now(timezone.utc).isoformat(),
            output='dump.raw', sha256=_sha(b''.join(pages)),
            origin=f'fixture offline da NANDP1.dmp record {unique_window}..{unique_window+127}; non una acquisizione hardware'), indent=2)+'\n')
        assert verify_directory(fixture)['verdict'] == 'OK_COMPLETE'
        comparison = compare_directory_with_known(fixture)
        assert all(r['aligned_records'] == 1 and r['known'] for r in comparison)
        assert comparison[0]['first_aligned_match'] == dict(dump='NANDP1.dmp', record=unique_window, offset=unique_window*RAW_BYTES)
        assert comparison[-1]['first_aligned_match']['record'] == unique_window+127
        # Random bytes must be reported unknown, never silently matched.
        assert known_page_index().get(_sha(os.urandom(RAW_BYTES)), []) == []
        assert substring_search(os.urandom(RAW_BYTES)) == []
        # 4. Independent re-check of the real MSDC LUN double dump.
        lun = verify_lun_images()
        index = known_page_index()
        result = dict(status='PASS_JOURNAL_INDEPENDENT_VERIFICATION',
                      positives=positives, tampering_detected=tampered, tampering_expected=len(tampered),
                      running_reported_incomplete=True,
                      known_fixture=dict(source='NANDP1.dmp', records=[unique_window, unique_window+127],
                                         unique_pages=128, all_found_aligned=True,
                                         first_match=comparison[0]['first_aligned_match']),
                      lun_recheck=lun, nandp1_records_indexed=sum(len(v) for v in index.values()),
                      sources={str(p): sha(p) for p in [Path(__file__), KNOWN_DUMPS/'NANDP1.dmp', KNOWN_DUMPS/'MainCode.dmp',
                                                        KNOWN_DUMPS/'NANDReserved.dmp', KNOWN_DUMPS/'BootCode.dmp']},
                      limits=['Artifacts validated, not acquisition proven: transport and device remain untested here',
                              'Known-dump match proves byte identity only, not physical NAND location',
                              'NANDP1 is the only known dump with integral 2112-byte stride; the others are substring-searched on a sample',
                              'No candidate installation, no hardware read, no new dump: candidate NON_INSTALLARE stands'])
        (out/'verified_evidence.json').write_text(json.dumps(result, indent=2, ensure_ascii=False)+'\n')
        (EVIDENCE/'pc_dump_journal_latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))), indent=2)+'\n')
        print('PASS', out)
    except BaseException as exc:
        (out/'failure.json').write_text(json.dumps(dict(status='FAIL', error=repr(exc)), indent=2)+'\n')
        raise


def cli(argv):
    ap = argparse.ArgumentParser(description='Verifica indipendente di una cartella di dump AKRN')
    ap.add_argument('directory', type=Path, help='Cartella con manifest.json, pages.jsonl e dump.raw o dump.raw.partial')
    ap.add_argument('--compare-known', action='store_true', help='Cerca le pagine nei dump noti della fotocamera')
    args = ap.parse_args(argv)
    verdict = verify_directory(args.directory)
    print(json.dumps(verdict, indent=2, ensure_ascii=False))
    if args.compare_known:
        matches = compare_directory_with_known(args.directory)
        known = sum(1 for m in matches if m['known'])
        print(json.dumps(dict(pages=len(matches), found_in_known_dumps=known, unknown_pages=len(matches)-known), indent=2))
    return 0


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        cli(sys.argv[1:])
    else:
        main()
