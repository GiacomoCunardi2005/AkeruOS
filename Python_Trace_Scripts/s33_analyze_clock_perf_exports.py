#!/usr/bin/env python3
"""Read-only correlation of camera CSV/performance exports with verified V1.1 code."""
from pathlib import Path
from datetime import datetime,timezone
import argparse,csv,io,re,json,hashlib,struct,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,ORIGINAL,EXPECTED,disasm,raw,u32,locate

FIELDS=[28,36,44,52,60,68,76,84,92,100,116,124,132,140,148]
WINDOWS=[(0xc6760,0xc6840),(0xc6900,0xc6974),(0x14cbdc,0x14cc00),
         (0x1f1000,0x1f10b8),(0x1f10c8,0x1f1134),(0x1f1138,0x1f11cc),
         (0xbcff0,0xbcff8),(0xbcffc,0xbd020),(0x12ca94,0x12ca9c),
         (0x12cc40,0x12ccb0),(0x12ccb0,0x12cdac),(0x12cba4,0x12cc40),(0x335c4c,0x335c74)]
POOLS={0xc6840:0x344078,0xc6844:0x36563d,0xc6848:0x377cb4,0xc684c:0x365640,
       0xc6974:0x377d34,0x14cbd8:0x443ff0,0x1f10c0:0x34fb40,0x1f1134:0x3bd1c4,
       0x1f11cc:0x3bd1ef,0x1f11d0:0x900,0x1f11d4:0x3bd21c,
       0xbd020:0x370a74,0xbcff8:0x370950,0x12ce18:0x3668b4,0x12ce34:0x38ee24,0x12ce2c:1000000}


def sha(b):return hashlib.sha256(b).hexdigest()


def cstr(addr):return raw(addr,256).split(b'\0')[0].decode('ascii')


def parse_clock(data):
    terminal=data.endswith(b'\0')
    text=(data[:-1] if terminal else data).decode('ascii')
    assert '\0' not in text,'Unexpected embedded NUL; preserve and inspect instead of dropping it'
    rows=list(csv.reader(io.StringIO(text),skipinitialspace=True))
    assert len(rows)==13 and len(rows[0])==16
    header=[v.strip() for v in rows[0]]
    assert header[0]=='State ID' and len(set(header))==16
    result=[]
    for state,row in enumerate(rows[1:]):
        assert len(row)==16 and row[0]==f'OpState[{state}]'
        vals=[int(v.strip(),10) for v in row[1:]]
        assert all(-2147483648<=v<=2147483647 for v in vals)
        result.append(dict(state=state,values=vals))
    return header,result,terminal


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--clock',type=Path,default=Path('/home/jack/Documenti/ClockSettings.csv'))
    ap.add_argument('--perf',type=Path,default=Path('/home/jack/Documenti/PerfLog.txt'))
    args=ap.parse_args()
    out=ROOT/'Risultati/Dump_fotocamera/Clock_Perf'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True,exist_ok=False);sources=out/'fonti';sources.mkdir()
    inputs={p:p.read_bytes() for p in (args.clock,args.perf)}
    assert sha(ORIGINAL.read_bytes())==EXPECTED
    tools={ROOT/'work/build-arc/binutils'/name:sha((ROOT/'work/build-arc/binutils'/name).read_bytes()) for name in ('objcopy','objdump')}
    latest=json.loads((ROOT/'Risultati/Dump_fotocamera/latest.json').read_text())
    classification=ROOT/latest['evidence'];catalog=json.loads(classification.read_text())
    dump_hashes={}
    for row in catalog['files']:
        p=ROOT/'DUMPS'/row['file'];assert sha(p.read_bytes())==row['sha256']
        dump_hashes[str(p.relative_to(ROOT))]=row['sha256']
    installed=(ROOT/'DUMPS/MainCode.dmp').read_bytes();blocks={b['index']:b for b in BS}
    checked=[]
    def supplied_span(a,n):
        b,off=locate(a,n);part=installed[b['offset']+off:b['offset']+off+n]
        assert part==raw(a,n),(hex(a),n)
        checked.append(dict(address=hex(a),bytes=n,sha256=sha(part)))
    listings=[]
    for a,b in WINDOWS:
        supplied_span(a,b-a);listings.append(disasm(a,b))
    for a,value in POOLS.items():assert u32(a)==value;supplied_span(a,4)
    (out/'gnu_verified.txt').write_text('\n'.join(listings))
    # Schema controls include a trailing C terminator and reject embedded corruption.
    head,states,terminal=parse_clock(inputs[args.clock])
    assert cstr(0x344078)=='\\ClockSettings.csv'
    assert cstr(0x377cb4).rstrip('\n')==', '.join(head)
    assert cstr(0x377d34).count('%d')==16
    stride=((1+4)*8-1)*4;assert stride==156
    base=u32(0x14cbd8)
    cells=[dict(state=row['state'],field=head[col+1],offset=off,
                candidate_cpu_address=hex(base+row['state']*stride+off),value=row['values'][col])
           for row in states for col,off in enumerate(FIELDS)]
    assert len(cells)==180 and len({c['candidate_cpu_address'] for c in cells})==180
    assert terminal and inputs[args.clock].count(b'\0')==1
    (out/'clock_fields.json').write_text(json.dumps(dict(base=hex(base),row_stride=stride,cells=cells,
          scope='Only these exported software fields; not a full RAM image or physical clock measurement'),indent=2)+'\n')
    perf=inputs[args.perf];assert b'\0' not in perf
    pattern=re.compile(r'^(.*?)\s*\[0x([0-9A-Fa-f]+)\]\s*, Timestamp =\s*(-?\d+)\s*,\s*(-?\d+)\s*$')
    events=[];warnings=[];domain='boot';unparsed=[]
    for line_no,line in enumerate(perf.decode('ascii').splitlines(),1):
        m=pattern.match(line)
        if m:
            ident=int(m[2],16);label=m[1].strip();hi=int(m[3]);lo=int(m[4])
            assert -2147483648<=hi<=2147483647 and -2147483648<=lo<=2147483647
            if ident<6:table=0x370a74;idx=ident;assert domain=='boot'
            elif 0xb00000<=ident<0xb0000e:table=0x38ee24;idx=ident-0xb00000;assert domain=='main'
            elif 0xb80000<=ident<0xb80049:table=0x370950;idx=ident-0xb80000;assert domain=='main'
            else:raise AssertionError(('Unknown event ID',hex(ident)))
            label_ptr=u32(table+4*idx);assert label_ptr and cstr(label_ptr)==label
            supplied_span(table+4*idx,4);supplied_span(label_ptr,len(label)+1)
            events.append(dict(line=line_no,domain=domain,label=label,id=hex(ident),table_address=hex(table+4*idx),
                string_address=hex(label_ptr),timestamp_high_field=hi,timestamp_low_field=lo,
                timestamp_word_pair=((hi&0xffffffff)<<32)|(lo&0xffffffff)))
        elif line==cstr(0x3bd247).rstrip('\r\n'):domain='main'
        elif line==cstr(0x3bd1ef).rstrip('\r\n'):warnings.append(dict(line=line_no,text=line))
        else:unparsed.append(dict(line=line_no,text=line))
    assert not unparsed and len(events)==37 and len(warnings)==2
    boot_ptrs=[u32(0x370a74+4*i) for i in range(6)]
    assert boot_ptrs[:4]==[0x371030,0x37103d,0x371051,0x371063] and boot_ptrs[4:]==[0,0]
    assert len([x for x in events if x['domain']=='boot'])==4
    assert len([x for x in events if x['domain']=='main'])==33
    for domain in ('boot','main'):
        times=[e['timestamp_word_pair'] for e in events if e['domain']==domain]
        assert times==sorted(times)
    # Keep durations in printed units; resolving the actual conversion mode/rate
    # must precede assigning physical seconds to this particular capture.
    phase_pairs=[('MAINCODE_LOAD_START','MAINCODE_LOAD_END'),('Load Calibration Start','Load Calibration End'),
      ('Turn On Senor Start','Turn On Senor End'),('Set Display Path Start','Set Display Path End'),
      ('Lens start','Lens end'),('Load C2 Start','Load C2 End'),('Load C3 Start','Load C3 End'),
      ('Load Resource Start','Load Resource End'),('Mount start','Mount end'),('Sort start','Sort end'),
      ('Load C4 Start','Load C4 End'),('Recorder_DisableLVW1ISR Start','Recorder_DisableLVW1ISR End')]
    phases=[]
    for start,end in phase_pairs:
        starts=[e for e in events if e['label']==start];ends=[e for e in events if e['label']==end]
        assert len(starts)==len(ends)
        for a,b in zip(starts,ends):
            assert a['domain']==b['domain'] and a['line']<b['line']
            phases.append(dict(start_label=start,end_label=end,start_line=a['line'],end_line=b['line'],domain=a['domain'],
              start=a['timestamp_word_pair'],end=b['timestamp_word_pair'],delta_printed_units=b['timestamp_word_pair']-a['timestamp_word_pair']))
    assert len(phases)==13
    def event(name):
        items=[e for e in events if e['label']==name];assert len(items)==1;return items[0]
    assert event('Load Calibration Start')['timestamp_word_pair']<event('Turn On Senor Start')['timestamp_word_pair']<event('Load Calibration End')['timestamp_word_pair']<event('Turn On Senor End')['timestamp_word_pair']
    assert event('Enter Liveview')['timestamp_word_pair']<event('Mount start')['timestamp_word_pair']<event('Mount end')['timestamp_word_pair']
    (out/'perf_events.json').write_text(json.dumps(events,indent=2)+'\n')
    (out/'perf_phases.json').write_text(json.dumps(phases,indent=2)+'\n')
    for p,b in inputs.items():(sources/p.name).write_bytes(b)
    (out/'analyzer.py.snapshot').write_bytes(Path(__file__).read_bytes())
    assert all(p.read_bytes()==b for p,b in inputs.items())
    assert all(sha((ROOT/p).read_bytes())==h for p,h in dump_hashes.items())
    assert sha(ORIGINAL.read_bytes())==EXPECTED
    assert all(sha(p.read_bytes())==h for p,h in tools.items())
    result=dict(status='PASS_EXPORT_STRUCTURE_AND_FIRMWARE_CORRELATION',
      gnu_tools_hashes_before_after={str(p.relative_to(ROOT)):h for p,h in tools.items()},
      user_provenance=dict(same_boot_as_DUMPS=True,evidence='Human reply in this chat: Sì, stesso avvio'),
      inputs={str(p):dict(bytes=len(b),sha256=sha(b),preserved_copy=str((sources/p.name).relative_to(ROOT))) for p,b in inputs.items()},
      original_firmware_sha256=EXPECTED,unchanged_camera_dumps=dump_hashes,previous_classification=str(classification.relative_to(ROOT)),
      gnu_windows=len(WINDOWS),verified_pools={hex(k):hex(v) for k,v in POOLS.items()},installed_main_windows=checked,
      clock=dict(states=len(states),numeric_fields=len(cells),all_zero=all(c['value']==0 for c in cells),
                 trailing_nul_bytes=1,software_table_base=hex(base),row_stride=stride,physical_frequencies_measured=False,
                 field_offsets=FIELDS,table_extent_candidate=[hex(base),hex(base+12*stride)]),
      perf=dict(events=len(events),boot_events=4,main_events=33,all_event_labels_match_firmware=True,
                warning_count=len(warnings),warning_explanation='BOOT label slots4/5 are null, exporter iterates six slots',
                generic_record_timestamp_offsets=[4,8],generic_printf_order='high32, low32',
                boot_high_printf_field_forced_zero=True,physical_time_unit_of_this_capture_verified=False,
                scale_constant=1000000,alternate_conversion_shift=15,distinct_boot_and_main_time_domains=True,
                phases=len(phases),liveview_before_mount_in_this_capture=True),
      limits=['Clock rows are software table fields, not live hardware frequency reads',
              'Printed time conversion uses runtime mode/frequency; no automatic physical seconds assigned',
              'Logged phase ordering and overlap do not prove dependency, core parallelism or SD persistence',
              'No raw RAM snapshot, complete NAND recovery, BFN DDR capacity or C2/C3/C4 payload mapping proven',
              'All firmware windows match supplied MainCode bytes; no camera command or GNU-tree mutation'])
    result['files']={str(p.relative_to(out)):sha(p.read_bytes()) for p in sorted(out.rglob('*')) if p.is_file()}
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    (out.parent/'latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT)),
       events=str((out/'perf_events.json').relative_to(ROOT)),phases=str((out/'perf_phases.json').relative_to(ROOT))),indent=2)+'\n')
    print('PASS:',len(states),'clock states;',len(events),'events matched;',len(phases),'paired intervals;',len(WINDOWS),'GNU windows; inputs unchanged, GNU tools read only;',out)


if __name__=='__main__':main()
