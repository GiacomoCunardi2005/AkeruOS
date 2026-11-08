#!/usr/bin/env python3
"""GNU differential and rejection tests for the host-only ARC ELF prototype."""
import json
from pathlib import Path
import struct
import subprocess
import sys

from s33_arc_elf_offline import load
from s33_check_arc_relocations import ROOT, digest, read_elf, run, symbols

OUT = ROOT / 'Ghidra_Results/ghidra_reports/arc_elf_offline'


def check_gnu(obj, base, external, log):
    raw = obj.read_bytes()
    simulated = load(raw, base, external)
    sections = read_elf(obj)
    script = OUT / f'{obj.stem}_{base:08x}.ld'
    lines = [f'SECTIONS {{ . = {base:#x};']
    for s in sections:
        if s['flags'] & 2:
            lines.extend((f'. = ALIGN({s["align"] or 1});',
                          f'{s["name"]} : {{ *("{s["name"]}") }}'))
    lines.append('}')
    script.write_text('\n'.join(lines) + '\n')
    exe = script.with_suffix('.elf')
    defs = [arg for name, value in external.items() for arg in ('--defsym', f'{name}={value:#x}')]
    run('arc-snps-elf-ld', '-T', script, '-o', exe, *defs, obj)
    linked = read_elf(exe)
    placed = {s['name']: s for s in linked}
    comparisons = []
    for s in simulated['sections']:
        if not s['size']:
            continue
        expected = placed[s['name']]
        assert (s['address'], s['size'], s['type']) == (expected['addr'], expected['size'], expected['type'])
        data = bytes.fromhex(s['bytes'])
        assert data == (bytes(expected['size']) if expected['type'] == 8 else expected['data'])
        comparisons.append(dict(name=s['name'], bytes=s['size'], match=True))
    table = next(s for s in linked if s['type'] == 2)
    oracle = {name: value for name, value, index in symbols(linked, table) if name}
    for sym in simulated['symbols']:
        if sym['name'] and sym['value'] is not None:
            assert sym['value'] == oracle[sym['name']], sym
    log.extend((exe.name, run('arc-snps-elf-readelf', '-h', '-S', '-s', '-r', obj),
                run('arc-snps-elf-readelf', '-h', '-S', '-s', exe),
                run('arc-snps-elf-objdump', '-d', '-s', '-m', 'arc:ARC700', '-EL', exe)))
    return dict(object=obj.name, object_sha256=digest(obj), elf=exe.name, elf_sha256=digest(exe),
                matches=comparisons, simulation=simulated, differences=[])


def rejection_checks(obj):
    raw = obj.read_bytes()
    sections = read_elf(obj)
    shoff = struct.unpack_from('<I', raw, 32)[0]
    rel_index = next(i for i, s in enumerate(sections) if s['type'] == 4)
    rel = sections[rel_index]
    table = sections[rel['link']]
    symoff = table['offset'] + (struct.unpack_from('<I', raw, rel['offset']+4)[0] >> 8)*16
    records = []

    def reject(name, mutated, message, base=0x100000, external=None):
        try:
            load(mutated, base, external)
        except ValueError as error:
            assert message in str(error), (name, str(error))
            records.append(dict(test=name, status='PASS', error=str(error)))
        else:
            raise AssertionError(f'accepted invalid input: {name}')

    def patch(name, offset, fmt, value, message):
        mutated = bytearray(raw)
        struct.pack_into(fmt, mutated, offset, value)
        reject(name, bytes(mutated), message)

    reject('truncated header', raw[:20], 'input size')
    reject('truncated sections', raw[:-1], 'out of bounds')
    for name, offset, fmt, value, message in (
        ('ELF64', 4, '<B', 2, 'ELF32'), ('big endian', 5, '<B', 2, 'little-endian'),
        ('ARM machine', 18, '<H', 40, 'ARC ET_REL'), ('executable', 16, '<H', 2, 'ET_REL'),
        ('wrong ABI', 36, '<I', 0x402, 'ABI'), ('section names outside file', 50, '<H', 0xffff, 'section header'),
        ('PROGBITS outside file', shoff+40+16, '<I', len(raw), 'file range'),
        ('bad alignment', shoff+40+32, '<I', 3, 'power of two'),
        ('unsupported TLS', shoff+40+8, '<I', 0x406, 'allocated section'),
        ('SHT_REL', shoff+40*rel_index+4, '<I', 9, 'SHT_REL'),
        ('bad RELA size', shoff+40*rel_index+36, '<I', 8, 'RELA size'),
        ('bad RELA target', shoff+40*rel_index+28, '<I', 0xffff, 'RELA symbol'),
        ('bad RELA symtab', shoff+40*rel_index+24, '<I', 0, 'RELA symbol'),
        ('unknown relocation', rel['offset']+4, '<I', (struct.unpack_from('<I', raw, rel['offset']+4)[0] & ~255) | 50, 'unsupported ARC'),
        ('symbol index', rel['offset']+4, '<I', 0xffff001b, 'symbol index'),
        ('write outside section', rel['offset'], '<I', sections[rel['info']]['size']-3, 'write out'),
        ('overlap', rel['offset']+12, '<I', struct.unpack_from('<I', raw, rel['offset'])[0], 'overlapping'),
        ('unresolved symbol', symoff+14, '<H', 0, 'unresolved'),
        ('common symbol', symoff+14, '<H', 0xfff2, 'symbol section'),
        ('symbol extent', symoff+4, '<I', 0xffffffff, 'symbol extent'),
        ('symbol name outside table', symoff, '<I', 0xffffffff, 'string offset'),
        ('host memory limit', shoff+40*4+20, '<I', 0x2000000, 'host limit'),
    ):
        patch(name, offset, fmt, value, message)
    reject('address overflow', raw, 'address space', base=0xfffffffc)
    reject('invalid base', raw, 'synthetic base', base=-1)
    reject('invalid external address', raw, 'external symbol', external={'bad': 2**32})
    broken = OUT / 'rejected_abi.o'
    mutated = bytearray(raw)
    struct.pack_into('<I', mutated, 36, 0)
    broken.write_bytes(mutated)
    result = subprocess.run([sys.executable, '-O', str(Path(__file__).with_name('s33_arc_elf_offline.py')),
                             str(broken), '--base', '0x100000'], capture_output=True, text=True)
    assert result.returncode == 1 and not result.stdout and 'ABI' in result.stderr
    records.append(dict(test='CLI rejects with python -O', status='PASS', error=result.stderr.strip()))
    return records


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    flags = ('-mcpu=arc700', '-mno-sdata', '-O2', '-ffreestanding', '-fno-builtin', '-Wall', '-Wextra')
    main_obj = OUT / 'main.o'
    run('arc-snps-elf-gcc', *flags, '-c', ROOT / 'AkeruOS/main.c', '-o', main_obj)
    asm = OUT / 'multiple.s'
    lines = ['.text', '.short 0']
    for section, kinds in (('.text', ('R_ARC_32_ME',)), ('.data', ('R_ARC_32', 'R_ARC_32_PCREL'))):
        lines.extend((section, '.balign 16' if section == '.data' else '.balign 2'))
        for kind in kinds:
            for addend in (0, -4, 4):
                lines.extend((f'.reloc ., {kind}, target{addend:+d}', '.long 0'))
    lines.extend(('.long local_value+4', '.long scratch+4',
                  '.reloc ., R_ARC_32, abs_value', '.long 0', '.set abs_value, 0x4321',
                  '.local local_value', 'local_value:', '.long 0x11223344',
                  '.bss', '.balign 32', '.global scratch', 'scratch:', '.space 12'))
    asm.write_text('\n'.join(lines) + '\n')
    multiple = OUT / 'multiple.o'
    run('arc-snps-elf-as', '-mcpu=arc700', '-EL', asm, '-o', multiple)
    (OUT / 'caller.c').write_text('extern int helper(int); extern volatile unsigned state;\nint entry(int n) { return helper(n) + state; }\n')
    (OUT / 'helper.c').write_text('volatile unsigned state = 7;\nint helper(int n) { return n + 3; }\n')
    for name in ('caller', 'helper'):
        run('arc-snps-elf-gcc', *flags, '-mlong-calls', '-ffunction-sections', '-fdata-sections',
            '-c', OUT / f'{name}.c', '-o', OUT / f'{name}.o')
    calls = OUT / 'calls.o'
    run('arc-snps-elf-ld', '-r', OUT / 'caller.o', OUT / 'helper.o', '-o', calls)
    log, results = [], []
    for base in (0x100003, 0x200000):
        for obj in (main_obj, multiple, calls):
            external = {'target': 0x12345678 if base == 0x100003 else 0x1000} if obj == multiple else {}
            results.append(check_gnu(obj, base, external, log))
    rejects = rejection_checks(main_obj)
    for external in ({}, {'target_extra': 0x12345678}):
        try:
            load(multiple.read_bytes(), 0x100000, external)
        except ValueError as error:
            assert str(error) == 'unresolved symbol: target'
            rejects.append(dict(test='missing external' if not external else 'exact symbol name',
                                status='PASS', error=str(error)))
        else:
            raise AssertionError('unresolved external accepted')
    short = OUT / 'caller_short.o'
    run('arc-snps-elf-gcc', *flags, '-ffunction-sections', '-fdata-sections',
        '-c', OUT / 'caller.c', '-o', short)
    short_calls = OUT / 'calls_short.o'
    run('arc-snps-elf-ld', '-r', short, OUT / 'helper.o', '-o', short_calls)
    listing = run('arc-snps-elf-readelf', '-r', short_calls)
    assert 'R_ARC_S25W_PCREL' in listing
    log.extend((short_calls.name, listing))
    try:
        load(short_calls.read_bytes(), 0x100000)
    except ValueError as error:
        assert str(error) == 'unsupported ARC relocation 17'
        rejects.append(dict(test='real C call without -mlong-calls', status='PASS', error=str(error)))
    else:
        raise AssertionError('unsupported branch relocation accepted')
    cli = run(sys.executable, Path(__file__).with_name('s33_arc_elf_offline.py'),
              main_obj, '--base', '0x100003')
    assert json.loads(cli) == load(main_obj.read_bytes(), 0x100003)
    (OUT / 'cli_main.json').write_text(cli)
    (OUT / 'gnu_verified.txt').write_text('\n'.join(log))
    evidence = dict(checker_sha256=digest(Path(__file__)),
                    prototype_sha256=digest(Path(__file__).with_name('s33_arc_elf_offline.py')),
                    relocation_helper_sha256=digest(Path(__file__).with_name('s33_check_arc_relocations.py')),
                    compiler=run('arc-snps-elf-gcc', '--version').splitlines()[0],
                    linker=run('arc-snps-elf-ld', '--version').splitlines()[0],
                    comparisons=results, rejections=rejects, cli_json_matches_api=True,
                    limits='Single ET_REL object; host simulation; no Nikon calls or firmware output.')
    (OUT / 'verified_evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(f'PASS: {len(results)} GNU comparisons, {len(rejects)} rejection cases; sections, symbols, BSS and RELA')


if __name__ == '__main__':
    main()
