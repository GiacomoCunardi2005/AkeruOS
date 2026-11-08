#!/usr/bin/env python3
"""Acquire explicit RAW block ranges through AKRN v1, comparing two reads per page.

Requires a compatible image already running. Uses the existing read-only SG_IO
client; never opens a device for writing or installs a firmware image.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

from s33_nand_pc_read import RAW_BYTES, fd_identity, page_cdb, read_page

PAGES_PER_BLOCK = 64


def utc():
    return datetime.now(timezone.utc).isoformat()


def validate_range(chip, first_block, blocks):
    if blocks <= 0:
        raise ValueError('Il numero di blocchi deve essere positivo')
    page_cdb(chip, first_block, 0)
    page_cdb(chip, first_block+blocks-1, PAGES_PER_BLOCK-1)


def write_json(path, value):
    # Directory is reserved exclusively by this run; atomic replacement is local.
    temp = path.with_suffix(path.suffix+'.tmp')
    with temp.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(path)


def acquire(fd, chip, first_block, blocks, directory, identity, reader=read_page):
    """Write into a newly reserved directory; no retries or device reopening.

    The caller creates the directory exclusively. A failed run retains .partial
    and records FAILED in manifest.json. Only compared pages enter the RAW file.
    """
    validate_range(chip, first_block, blocks)
    directory = Path(directory)
    partial = directory/'dump.raw.partial'
    final = directory/'dump.raw'
    journal = directory/'pages.jsonl'
    manifest = directory/'manifest.json'
    # Do not overwrite a previous run, including one interrupted before manifest.
    if any(directory.iterdir()):
        raise FileExistsError('La cartella di acquisizione deve essere nuova e vuota')
    result = dict(status='RUNNING', started_utc=utc(), device=identity, chip=chip,
                  first_block=first_block, blocks=blocks, pages_per_block=PAGES_PER_BLOCK,
                  raw_bytes_per_page=RAW_BYTES, pages_expected=blocks*PAGES_PER_BLOCK,
                  pages_written=0, bytes_written=0, reads_per_page=2,
                  geometry='Configured driver profile only; not independently measured capacity',
                  format='Nikon RAW as returned, not normalized or ECC-verified',
                  limits=['Two equal reads do not certify hardware ECC, physical coverage or recovery'])
    write_json(manifest, result)
    digest = hashlib.sha256()
    current = None
    try:
        with partial.open('xb') as raw, journal.open('x', encoding='utf-8') as log:
            for block in range(first_block, first_block+blocks):
                for page in range(PAGES_PER_BLOCK):
                    current = dict(chip=chip, block=block, page=page)
                    first = reader(fd, chip, block, page)
                    if len(first) != RAW_BYTES:
                        raise OSError(f'Prima lettura corta a blocco{block}/pagina{page}: {len(first)}byte')
                    second = reader(fd, chip, block, page)
                    if len(second) != RAW_BYTES:
                        raise OSError(f'Seconda lettura corta a blocco{block}/pagina{page}: {len(second)}byte')
                    if first != second:
                        raise OSError(f'Letture discordanti a blocco{block}/pagina{page}')
                    offset = result['bytes_written']
                    raw.write(first)
                    log.write(json.dumps(dict(**current, offset=offset, bytes=RAW_BYTES,
                                              sha256=hashlib.sha256(first).hexdigest()))+'\n')
                    digest.update(first)
                    result['pages_written'] += 1
                    result['bytes_written'] += RAW_BYTES
                # Persist both files and progress at a block boundary.
                raw.flush(); os.fsync(raw.fileno())
                log.flush(); os.fsync(log.fileno())
                result['last_compared_page'] = current
                write_json(manifest, result)
            raw.flush(); os.fsync(raw.fileno())
            log.flush(); os.fsync(log.fileno())
        # Independent host-file reread catches a short/truncated local result.
        stored = hashlib.sha256()
        with partial.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024*1024), b''):
                stored.update(chunk)
        if partial.stat().st_size != result['bytes_written'] or stored.hexdigest() != digest.hexdigest():
            raise OSError('Verifica del file locale fallita')
        partial.rename(final)
        result.update(status='COMPLETE_DOUBLE_READ_LOCAL_FILE_VERIFIED', completed_utc=utc(),
                      output=final.name, sha256=stored.hexdigest())
        write_json(manifest, result)
        return result
    except BaseException as exc:
        if final.exists() and not partial.exists():
            try:
                final.rename(partial)
            except OSError:
                pass
        # Never silently delete useful compared data or label a partial run complete.
        result.update(status='FAILED', failed_utc=utc(), failed_coordinate=current,
                      error_type=type(exc).__name__, error=str(exc), output=partial.name if partial.exists() else final.name if final.exists() else None)
        try:
            write_json(manifest, result)
        except OSError:
            # The last persisted RUNNING manifest remains explicitly incomplete.
            pass
        raise


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device', required=True, help='/dev/sgN o disco SCSI intero Nikon')
    ap.add_argument('--chip', type=int, default=0)
    ap.add_argument('--first-block', type=int, required=True)
    ap.add_argument('--blocks', type=int, required=True)
    ap.add_argument('--output-dir', type=Path, required=True, help='Nuova cartella locale, non deve esistere')
    args = ap.parse_args()
    validate_range(args.chip, args.first_block, args.blocks)
    args.output_dir.mkdir(parents=False, exist_ok=False)
    fd = None
    try:
        fd = os.open(args.device, os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
        identity = fd_identity(fd)
        result = acquire(fd, args.chip, args.first_block, args.blocks, args.output_dir, identity)
    except BaseException as exc:
        # Identity/open failures happen before acquire has its own manifest.
        if not (args.output_dir/'manifest.json').exists():
            write_json(args.output_dir/'manifest.json', dict(status='FAILED_BEFORE_ACQUISITION',
                       failed_utc=utc(), error_type=type(exc).__name__, error=str(exc), pages_written=0))
        raise
    finally:
        if fd is not None:
            os.close(fd)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
