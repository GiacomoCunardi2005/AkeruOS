#!/usr/bin/env python3
"""Count reached PCs and challenge zero-filled RAM; no instruction semantics are inferred from execution."""
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
import hashlib
import json
import re
import shutil
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha, TRACE
from s33_verify_gnu_dsp_lab import compile_probe
from s33_disassemble_firmware11 import OUTPUT

SOURCE = ROOT/'outputs/gnu_arc700/20261020T115305Z_b0bb8232'


def records(path):
    with path.open() as stream:
        for line in stream:
            match = TRACE.match(line)
            if match and match[2] != '-':
                yield int(match[1], 16), match[2], line.rstrip()


def audit(path, fault):
    counts = Counter(); pcs = set(); selectors = []; recent = []
    for pc, mnemonic, line in records(path):
        counts[mnemonic] += 1; pcs.add(pc)
        if pc in (0x12ca28, 0x1009e54):
            wrapper = 0x231420 if pc == 0x12ca28 else 0x10139d0
            assert recent[-2][0] == wrapper and recent[-1][0] == wrapper+4
            assert 'mov_s r0,0x0' in recent[-1][2] and 'cr16 <- 0x0' in recent[-1][2]
            selectors.append([item[2] for item in recent[-6:]] + [line])
        recent.append((pc, mnemonic, line)); recent = recent[-6:]
    completed = pcs - ({int(fault['pc'], 16)} if fault else set())
    # shortcut: a final fault is excluded conservatively; the trace is not a retirement oracle.
    return dict(instruction_records=sum(counts.values()), reached_unique_pc=len(pcs),
                successful_prefix_unique_pc=len(completed), trace_mnemonic_labels=len(counts),
                mnemonics=dict(counts), selector_calls=selectors), completed


def main():
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=None, action='execution-coverage-zero-challenge'))
    print('Evidence:', r.out, flush=True)
    try:
        r.prepare(); shutil.copyfile(__file__, r.out/'audit_snapshot.py')
        source = json.loads((SOURCE/'verified_evidence.json').read_text())
        assert source['status'] == 'PASS_LIMITED_EMPTY_SOFTWARE_SOURCE'
        for name, expected in source['files'].items():
            assert sha(SOURCE/name) == expected, name
        for name, expected in source['input_hashes'].items():
            assert sha(Path(name)) == expected, name
        r.input_hashes[str(SOURCE/'verified_evidence.json')] = sha(SOURCE/'verified_evidence.json')
        shutil.copyfile(SOURCE/'main.elf', r.out/'main.elf')
        r.experimental_engine = ROOT/'work/gnu_arc700_dsp_lab_v7'
        simulator = r.experimental_engine/'install/bin/arc-elf32-run'
        assert sha(simulator) == source['actual_engine_sha256']
        r.input_hashes[str(simulator)] = sha(simulator)
        listing_manifest = ROOT/'Ghidra_Results/ghidra_reports/firmware11_full/verified_evidence.json'
        listing = json.loads(listing_manifest.read_text())
        r.input_hashes[str(listing_manifest)] = sha(listing_manifest)
        regions = {x['name']: x for x in listing['regions']}
        summaries = {}; sets = {}; traces = {}
        r.baseline(trace=True)
        tbib_case = r.results['cases'][-1]
        tbib_summary, tbib_pcs = audit(r.out/'tbib_baseline.trace', tbib_case['fault'])
        assert tbib_summary['reached_unique_pc'] == 1111 and len(tbib_pcs) == 1110
        assert len(tbib_summary['selector_calls']) == 1
        for fill in (0, 0xa5, 0x5a):
            options = ['--memory-fill', '0']
            for address in ('0xfe800f8', '0xfe80064', '0xfe80108', '0xfe80100'):
                options += ['--memory-region', address+',2']
            options += ['--memory-fill', str(fill), '--memory-region', '0,0x08000000']
            probe_name = f'fill_check_{fill:02x}'
            expected = fill*0x01010101
            elf = compile_probe(r, probe_name,
                f' mov r2,0x07000000\n ld r1,[r2]\n mov r3,{expected:#x}\n cmp r1,r3\n bne fail\n'
                ' mov r0,0\n b finish\nfail:\n mov r0,7\nfinish:\n mov r8,1\n trap_s 1\n')
            probe, _ = r.run(probe_name, f'/result/{elf.name}', options, trace=True)
            assert probe['exit_code'] == 0 and probe['fault'] is None, 'RAM fill was not applied'
            name = f'main_fill_{fill:02x}'
            case, log = r.run(name, '/result/main.elf', options, trace=True)
            assert 'runtime error:' not in log
            summary, pcs = audit(r.out/(name+'.trace'), case['fault'])
            summary.update(case, initial_ram_fill=fill)
            dsp = re.findall(r'S33_DSP_LAB pc=([0-9a-f]+)', log)
            summary.update(provisional_dsp_records=len(dsp), provisional_dsp_pc=sorted(set(dsp)))
            assert len(dsp) == 5 and len(set(dsp)) == 3
            summaries[name] = summary; sets[name] = pcs; traces[name] = r.out/(name+'.trace')
            if fill == 0:
                assert case['instructions'] == 583306 and case['fault'] == source['cases'][0]['fault']
                assert sha(traces[name]) == source['files']['main_boot.trace']
            print('PASS', name, 'unique prefix PCs', len(pcs), 'fault', case['fault'], flush=True)
        baseline = sets['main_fill_00']
        main_pcs = {pc for pc in baseline if 0xad800 <= pc < 0x35bc00}
        ram_pcs = baseline - main_pcs
        assert ram_pcs == {0x818}, 'Unexpected execution outside preloaded MainCode: review provenance'
        main_region = regions['TBM_00']; matched = {}; listing_hash = hashlib.sha256()
        row = re.compile(r'^F([0-9A-F]{8}) V([0-9A-F]{8}|--------) \| ([0-9a-f ]+) \| (.*)$')
        with OUTPUT.open('rb') as stream:
            for raw in stream:
                listing_hash.update(raw)
                line = raw.decode(); m = row.match(line)
                if not m or m[2] == '--------': continue
                pc = int(m[2], 16); file_offset = int(m[1], 16)
                if pc in main_pcs and main_region['start'] <= file_offset < main_region['end']:
                    matched[pc] = line.rstrip()
        assert listing_hash.hexdigest() == listing['output']['sha256']
        missing = sorted(main_pcs - matched.keys())
        (r.out/'unique_pc.txt').write_text(''.join(f'{pc:08x}\n' for pc in sorted(baseline)))
        (r.out/'matched_listing.txt').write_text('\n'.join(matched[pc] for pc in sorted(matched))+'\n')
        differences = {}
        for name in ('main_fill_a5', 'main_fill_5a'):
            first = None
            for index, (left, right) in enumerate(zip(records(traces['main_fill_00']), records(traces[name]))):
                if left != right:
                    first = dict(instruction_record_index=index, baseline=left[2], challenge=right[2]); break
            differences[name] = dict(first_different_instruction_record=first,
                                     same_trace=sha(traces[name]) == sha(traces['main_fill_00']))
        gnu = []
        for index, (start, end) in enumerate(((0x231420,0x231426),(0x29f65c,0x29f680),(0x12ca28,0x12ca52))):
            p = r.command(f'gnu_selector_{index}', [TOOLCHAIN/'arc-elf32-objdump','-d','-m','arc:ARC700','-EL',
                f'--start-address={start}',f'--stop-address={end}',r.out/'main.elf'])
            assert p.returncode == 0 and 'out of bounds' not in p.stdout
            gnu.append(p.stdout)
        (r.out/'gnu_verified.txt').write_text('\n'.join(gnu))
        p = r.command('gnu_tbib_selector', [TOOLCHAIN/'arc-elf32-objdump','-d','-m','arc:ARC700','-EL',
            '--start-address=0x10139d0','--stop-address=0x10139d6',r.out/'tbib.elf'])
        assert p.returncode == 0 and 'mov_s\tr0,0' in p.stdout
        reanchored = {}
        for pc in missing:
            p = r.command(f'gnu_reanchor_{pc:08x}', [TOOLCHAIN/'arc-elf32-objdump','-d','-m','arc:ARC700','-EL',
                f'--start-address={pc}',f'--stop-address={pc+8}',r.out/'main.elf'])
            assert p.returncode == 0
            instructions = re.findall(r'^\s*([0-9a-f]+):\s*\t([^\t]+)\t(.+)$', p.stdout, re.M)
            assert instructions and int(instructions[0][0], 16) == pc
            assert not instructions[0][2].startswith('.')
            reanchored[hex(pc)] = instructions[0][2].strip()
        r.results.update(status='PASS_MEASUREMENT_ONLY', profiles=summaries, ram_challenges=differences,
            tbib_baseline_coverage=tbib_summary, tbib_main_state_chained=False,
            successful_prefix_unique_pc=len(baseline), linear_listing_pc_matches=len(matched),
            maincode_unique_pc=len(main_pcs), runtime_ram_pc=[hex(pc) for pc in sorted(ram_pcs)],
            reanchored_missing_instructions=reanchored, ram_fill_sentinel_cases=3,
            linear_listing_missing_pc=[hex(pc) for pc in missing],
            fraction_of_main_candidate_rows_percent=len(matched)/main_region['candidate_rows']*100,
            fraction_of_all_listing_rows_percent=len(matched)/listing['output']['rows']*100,
            denominator_main_candidate_rows=main_region['candidate_rows'], denominator_all_rows=listing['output']['rows'],
            semantically_certified_instruction_percentage=None,
            limits=['Reached/executed prefix is not independently verified instruction semantics',
                    'Linear listing includes data and may miss true instruction boundaries',
                    'No retired-instruction oracle; final fault PC excluded conservatively',
                    'Different RAM fills can expose dependencies but cannot prove absence of unknown reads',
                    'ELF payloads and NOBITS, registers, AUX and MMIO profiles remain initialized by the laboratory',
                    'DSP provisional, no chained TBIB/Main boot, no physical RAM or recovery proof'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc)); raise
    finally:
        r.save()
    print(r.results['status'], r.out/'verified_evidence.json', flush=True)


if __name__ == '__main__':
    main()
