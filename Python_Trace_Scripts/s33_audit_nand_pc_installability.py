#!/usr/bin/env python3
"""Audit evidence scope and export the current BIN without promoting offline PASS to installability."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json
ROOT=Path(__file__).resolve().parents[1]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    base=ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out=base/('installability_'+stamp);out.mkdir(exist_ok=False)
    read=lambda p:json.loads(p.read_text())
    manifest=ROOT/read(base/'container_latest.json')['evidence'];m=read(manifest);artifact=ROOT/m['artifact']
    expected='0bb25fd6603488e30d41ac6ad96f4fe4e8fe5e838deda7cfc7e9c6ab7cb324e9'
    assert sha(artifact)==m['sha256']==expected and m['original_payload_offsets_preserved'] and m['rhir_record_count']==18
    previous=base/'container_20261021T092600Z/S33_NAND_PC_RAW_OFFLINE_NON_INSTALLARE.bin'
    assert artifact.read_bytes()==previous.read_bytes()
    sources={'container':manifest}
    for label,pointer in [('sector_loader','loader_cpu_latest.json'),('file_loader','file_loader_cpu_latest.json'),('namespace','tbib_namespace_latest.json'),('updater','updater_cpu_latest.json'),('main_update','main_update_cpu_latest.json'),('dispatch','package_cpu_latest.json'),('routing','tbib_fallback_latest.json')]:
        path=base/pointer
        if not path.exists():continue
        sources[label]=ROOT/read(path)['evidence']
    index=read(base/'latest.json')
    # Preserve certification boundaries; hash-match evidence does not prove a complete boot.
    for row in index['evidence']:
        assert sha(ROOT/row['path'])==row['sha256'],row['path']
    summaries={}
    for label,path in sources.items():
        d=read(path);assert d['status'].startswith('PASS'),(label,d['status'])
        bound=d.get('candidate_sha256',d.get('sha256')if label=='container'else None)
        if bound is not None:assert bound==expected,(label,bound)
        summaries[label]=dict(path=str(path.relative_to(ROOT)),sha256=sha(path),status=d['status'],scope_limits=d.get('limits',[]))
    # Earlier sector-loader proofs may carry the superseded hash; only the corrected latest is accepted.
    gates=[
        dict(requirement='Create complete modified BIN',state='PROVEN',evidence=['container'],basis='Fresh repack and byte equality with corrected18record candidate'),
        dict(requirement='Container/offset/checksum integrity',state='PROVEN_OFFLINE',evidence=['container'],basis='Original16payload offsets preserved, added record17, original TBIB/P1RES and exact inverse transform'),
        dict(requirement='Loader and update local behavior',state='PROVEN_WITH_FIXTURES',evidence=['sector_loader','file_loader','updater','main_update','dispatch'],basis='Original CPU control flow with declared I/O/resource boundaries, not physical writes'),
        dict(requirement='Runtime RAM ownership and lifetime',state='UNPROVEN',basis='Declared ranges and bounded clear/deferred transfers exclude some writers only; computed stores, DMA, cache and concurrency remain open'),
        dict(requirement='Resident updater and persistent result',state='UNPROVEN',basis='No current flash/runtime readback and no physical write/readback validation of this candidate'),
        dict(requirement='Recovery after failed or interrupted update',state='UNPROVEN',evidence=['namespace','routing','file_loader','dispatch','main_update'],basis='Static SD binding and local selection exist; SD readiness, physical trigger, complete boot and persistent restore not established'),
        dict(requirement='USB RAW path and NAND integrity on camera',state='UNPROVEN',basis='Offline BOT/core/wrapper evidence only; no command or extended physical read of modified firmware'),
    ]
    export=ROOT/'Risultati/Firmware_sperimentali/USB_NAND_PC'/stamp;export.mkdir(parents=True,exist_ok=False)
    dest=export/'S33_NAND_PC_RAW_NON_INSTALLARE.bin';dest.write_bytes(artifact.read_bytes());assert sha(dest)==expected
    (export/'SHA256SUMS').write_text(expected+'  '+dest.name+'\n')
    result=dict(status='NO_GO_INSTALLATION',goal_achieved=False,installable=False,utc=datetime.now(timezone.utc).isoformat(),artifact=str(dest.relative_to(ROOT)),sha256=expected,bytes=dest.stat().st_size,source_artifact=str(artifact.relative_to(ROOT)),reproducible_identical_to=str(previous.relative_to(ROOT)),evidence=summaries,gates=gates,no_hardware_action=True)
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes());(export/'provenance.json').write_text(json.dumps(result,indent=2)+'\n')
    (base/'installability_latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
    print(json.dumps(dict(status=result['status'],artifact=str(dest),bytes=result['bytes'],sha256=expected,audit=str(out/'verified_evidence.json')),indent=2))
if __name__=='__main__':main()
