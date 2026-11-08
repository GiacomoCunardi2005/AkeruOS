#!/usr/bin/env python3
"""S33: triage statico del dispatch CaptureImage e dei rami verso CapMgr.

Modalità offline: usa soltanto un JSON di evidenza già raccolto.
Modalità locale: con --project-root verifica tutti i 16 blocchi TBM e disassembla
il blocco 02 ARC700, senza eseguire o modificare alcun firmware.

Questo script NON determina da solo l'origine fisica di S2, NON fa CFG recovery
né identifica una modalità fotografica. I candidati grezzi non sono xref provati.
"""
from __future__ import annotations

import argparse
import bisect
import collections
import hashlib
import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path

CAPMGR = 0x1B9EA8
RECORDER = 0x12CAD4
HANDLER = 0x65ED6C
SERVICE_TABLE = 0x783D9C
STATE_BASE = 0x681FF0
STATE_BYTE = STATE_BASE + 0x1D
SITES = (0x65F262, 0x65F378, 0x65FC48, 0x65FC7E, 0x65FCD6, 0x65FD92)
MARKER_WORDS = {0xB80022: "Recorder Capture Image Start", 0xB80023: "Recorder Capture Image End"}
EXPECTED_BLOCKS = 16
# GNU objdump ARC disassembly is partly heuristic and may interpret data as code.
CALL_PATTERN = re.compile(r"^\s*([0-9a-f]+):.*?\t(bl(?:\.d|_s)?)\s+.*?;0x([0-9a-f]+)\s*$", re.M)
LINE_PATTERN = re.compile(r"^\s*([0-9a-f]+):\s+")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hx(n: int) -> str:
    return f"0x{n:x}"


def load_evidence(path: Path) -> dict:
    source = json.loads(path.read_text())
    assert source["verified_blocks"] == EXPECTED_BLOCKS, "Unexpected block count in evidence"
    assert source["capture_image_registration"]["entry"].lower() == hx(HANDLER)
    assert source["capture_image_registration"]["adjacent_words_at"].lower() == hx(SERVICE_TABLE)
    return source


def find_pattern(data: bytes, needle: bytes, base: int, *, aligned: bool = False) -> list[str]:
    result = []
    off = 0
    while True:
        off = data.find(needle, off)
        if off < 0:
            break
        if not aligned or (base + off) % len(needle) == 0:
            result.append(hx(base + off))
        off += 1
    return result


def run(args: list[str | Path], timeout: int = 120) -> str:
    process = subprocess.run([str(arg) for arg in args], capture_output=True,
                             text=True, check=True, timeout=timeout)
    return process.stdout


def verified_blocks(project: Path, evidence: dict) -> tuple[list[dict], dict[int, bytes]]:
    root = project / "S33-sections" / "TBM_blocks"
    manifest = json.loads((root / "manifest.json").read_text())
    blocks = [b for b in manifest if b["within_file"]]
    assert len(blocks) == EXPECTED_BLOCKS, "Expected 16 valid TBM blocks"
    assert len({b["index"] for b in blocks}) == EXPECTED_BLOCKS
    payloads = {}
    for b in blocks:
        # Avoid untrusted absolute/parent manifest paths.
        path = (root / b["file"]).resolve()
        if not path.is_relative_to(root.resolve()):
            raise ValueError("Unsafe manifest file path")
        data = path.read_bytes()
        assert len(data) == b["size"], f"Bad length: block {b['index']}"
        assert sha(data) == b["sha256"], f"Bad hash: block {b['index']}"
        payloads[b["index"]] = data
    b2 = next(b for b in blocks if b["index"] == 2)
    b3 = next(b for b in blocks if b["index"] == 3)
    assert b2["load_address_candidate"] == 0x5FE800
    assert b3["load_address_candidate"] == 0x669800
    for i, b in [(2, b2), (3, b3)]:
        assert sha(payloads[i]) == evidence["checked_block_sha256"][str(i)]

    def word(block: dict, addr: int) -> int:
        off = addr - block["load_address_candidate"]
        assert 0 <= off <= block["size"] - 4
        return struct.unpack_from("<I", payloads[block["index"]], off)[0]

    assert word(b2, 0x65F0EC) == STATE_BASE
    assert word(b2, 0x65F474) == 0xB80022
    assert word(b2, 0x65F480) == 0xB80023
    assert word(b2, 0x65FDEC) == 0xB80022
    assert word(b2, 0x65FDF0) == 0xB80023
    assert [word(b3, SERVICE_TABLE+i*4) for i in range(3)] == [0x4405, HANDLER, 0x4406]
    return blocks, payloads


def disassemble_block2(project: Path, blocks: list[dict], payloads: dict[int, bytes]) -> str:
    b = next(x for x in blocks if x["index"] == 2)
    objcopy = project / "work" / "build-arc" / "binutils" / "objcopy"
    objdump = project / "work" / "build-arc" / "binutils" / "objdump"
    if not objcopy.is_file() or not objdump.is_file():
        raise FileNotFoundError(f"Expected ARC binutils at {objcopy} and {objdump}")
    with tempfile.TemporaryDirectory(prefix="s33-capture-") as tmp:
        elf = Path(tmp) / "block02.elf"
        restored = Path(tmp) / "roundtrip.bin"
        source = project / "S33-sections" / "TBM_blocks" / b["file"]
        run([objcopy, "-I", "binary", "-O", "elf32-littlearc", "-B", "arc",
             "--rename-section", ".data=.text,alloc,load,readonly,code,contents",
             "--change-section-vma", f".data={b['load_address_candidate']:#x}",
             "--strip-all", source, elf])
        run([objcopy, "--dump-section", f".text={restored}", elf])
        if restored.read_bytes() != payloads[2]:
            raise ValueError("ELF round-trip changed the payload")
        listing = run([objdump, "-d", "-m", "arc:ARC700", "-EL", elf])
        if "out of bounds" in listing:
            raise ValueError("objdump reported out-of-bounds")
        return listing


def windows_of_listing(listing: str, sites: list[int], before: int = 96, after: int = 128) -> dict[str, str]:
    lines = []
    addresses = []
    for ln in listing.splitlines():
        m = LINE_PATTERN.match(ln)
        if m:
            addresses.append(int(m.group(1), 16))
            lines.append(ln)
    output = {}
    for s in sites:
        a = bisect.bisect_left(addresses, s-before)
        b = bisect.bisect_left(addresses, s+after)
        output[hx(s)] = "\n".join(lines[a:b])
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True,
                        help="s33_captureimage_dispatch.json prodotto dal tracer precedente")
    parser.add_argument("--project-root", type=Path,
                        help="Root progetto contenente S33-sections/TBM_blocks e work/build-arc/binutils")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    evidence = load_evidence(args.evidence)
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    capmgr_sites = sorted(int(x["site"], 16) for x in evidence["direct_calls_from_linear_disassembly"]["capture_manager"])
    if capmgr_sites != list(SITES):
        raise ValueError("Unexpected CapMgr callsites: do not silently reuse the prior analysis")
    markers = [int(x["site"], 16) for x in evidence["direct_calls_from_linear_disassembly"]["recorder_marker"] if x["block"] == 2]
    marker_rows = []
    for site in capmgr_sites:
        nearby = sorted(markers, key=lambda m: (abs(m-site), m))[:5]
        marker_rows.append({"capmgr_site": hx(site), "nearest_recorder_calls": [
            {"site": hx(m), "delta_bytes": m-site} for m in nearby]})

    result = {
        "analysis": "S33 CaptureImage upstream candidate triage; NOT verified S2 chain",
        "input_evidence_sha256": sha(args.evidence.read_bytes()),
        "mode": "offline evidence reanalysis" if args.project_root is None else "fresh local binary verification",
        "expected_v1_1_block_count": EXPECTED_BLOCKS,
        "capmgr_calls": marker_rows,
        "captureimage_entry": hx(HANDLER),
        "captureimage_entry_direct_calls": evidence["direct_calls_from_linear_disassembly"]["capture_image_handler"],
        "registration_pointer_raw": evidence["raw_word_occurrences"]["capture_image_handler_pointer"],
        "known_verified_start_end_sequence": {
            "start_call": "0x65f230", "capmgr_call": "0x65f262", "end_call": "0x65f268",
            "start_literal": "0x65f474", "end_literal": "0x65f480"
        },
        "second_start_end_literals": {"start": "0x65fdec", "end": "0x65fdf0"},
        "s2_marker_raw_absent_in_existing_evidence": not any(
            evidence["raw_word_occurrences"]["s2_marker_word"][endian] for endian in ("little_endian", "big_endian")),
        "caveat": "Proximity to recorder calls alone does not identify a marker's argument or prove execution order. No physical S2 pathway has been reconstructed.",
    }
    windows = {}
    if args.project_root is not None:
        project = args.project_root.expanduser().resolve()
        blocks, payloads = verified_blocks(project, evidence)
        result["blocks_freshly_sha256_verified"] = len(blocks)
        # Full-block scan but *aligned* words: unaligned byte patterns are not pointers.
        for name, value in [
            ("CaptureImage_entry", HANDLER),
            ("service_id_0x4405", 0x4405),
            ("service_id_0x4406", 0x4406),
            ("context_base_0x681ff0", STATE_BASE),
            ("context_byte_address_0x68200d", STATE_BYTE),
            ("service_table_address", SERVICE_TABLE),
        ]:
            hits = []
            for b in blocks:
                base = b["load_address_candidate"]
                data = payloads[b["index"]]
                for a in find_pattern(data, struct.pack("<I", value), base, aligned=True):
                    hits.append({"block": b["index"], "address": a})
            result.setdefault("aligned_raw_little_endian_occurrences", {})[name] = hits

        listing = disassemble_block2(project, blocks, payloads)
        found_call_sites = sorted({int(m.group(1), 16) for m in CALL_PATTERN.finditer(listing)
                                  if int(m.group(3), 16) == CAPMGR})
        if found_call_sites != capmgr_sites:
            raise AssertionError("Fresh objdump CapMgr sites differ from the original evidence")
        result["verified_capmgr_direct_calls_in_block2"] = [hx(i) for i in found_call_sites]
        # Discover which ARC PC-relative loads mention the four marker literal cells.
        refs = {}
        for addr in (0x65F474, 0x65F480, 0x65FDEC, 0x65FDF0):
            refs[hx(addr)] = []
            for line in listing.splitlines():
                match = LINE_PATTERN.match(line)
                if match and re.search(r";0x" + f"{addr:x}" + r"\s*$", line):
                    refs[hx(addr)].append({"site": hx(int(match.group(1), 16)), "instruction": line.strip()})
        result["pc_relative_literal_refs_in_linear_disassembly"] = refs

        targets = sorted(set(capmgr_sites + [0x65F230, 0x65F268, 0x65FC50, 0x65FC84,
                                             0x65F200, 0x65F204, 0x65FD92]))
        windows = windows_of_listing(listing, targets, 96, 128)

    report = [
        "# S33 — CaptureImage: analisi del dispatch e dei percorsi a CapMgr",
        "",
        f"Modalità: **{result['mode']}**. Firmware di riferimento: V1.1; fotocamera fisica registrata V1.0.",
        "",
        "## Risultati derivati dalle evidenze disponibili",
        "",
        "La scansione lineare registrata mostra 6 chiamate candidate dirette a `0x1B9EA8` nel blocco 02. "
        "La presenza del puntatore `0x65ED6C` nella tabella è confermata dal rapporto precedente; "
        "non risultano chiamate dirette `bl` a quell'handler nei dati forniti. "
        "Questo è compatibile con dispatch indiretto, ma non lo prova.",
        "",
        "| Chiamata CapMgr | Invocazioni vicine di `0x12CAD4` (offset in byte) |",
        "|---|---|",
    ]
    for row in marker_rows:
        nearby = ", ".join(f"`{r['site']}` ({r['delta_bytes']:+d})" for r in row["nearest_recorder_calls"][:3])
        report.append(f"| `{row['capmgr_site']}` | {nearby} |")
    report += [
        "",
        "**Attenzione:** una chiamata vicina a `0x12CAD4` non è automaticamente un marcatore Start/End. "
        "I suoi argomenti, il flusso di controllo e gli eventuali delay slot vanno verificati separatamente.",
        "",
        "Sono presenti le parole `0xB80022` e `0xB80023` anche a `0x65FDEC` e `0x65FDF0`; "
        "senza il binario non è possibile associare questi letterali a una chiamata specifica.",
        "",
        "## Prossimo punto da verificare",
        "",
        "1. Classificare i rami contenenti `0x65F378`, `0x65FC48`, `0x65FC7E`, `0x65FCD6`, `0x65FD92`.",
        "2. Recuperare le istruzioni che caricano i letterali in `0x65FDEC` e `0x65FDF0`, con i loro delay slot.",
        "3. Rintracciare il dispatcher che usa l'ID candidato `0x4405` e seleziona la entry `0x65ED6C`.",
        "4. Localizzare i produttori del byte `0x681FF0+0x1D` e ricostruirne il significato.",
        "5. Solo dopo, risalire a evento/input S2 e verificare le differenze fra firmware V1.0/V1.1.",
        "",
    ]
    if args.project_root is not None:
        report += [
            f"Verificati di nuovo **{result['blocks_freshly_sha256_verified']} blocchi** tramite dimensioni/hash SHA-256 del manifest.",
            "", "### Occorrenze raw LE a parola allineata (solo candidati dati)", "",
            "| Costante | Occorrenze | Primi indirizzi |", "|---|---:|---|"
        ]
        for k, hits in result["aligned_raw_little_endian_occurrences"].items():
            report.append(f"| `{k}` | {len(hits)} | " + ", ".join(f"`{h['address']}` (blocco {h['block']})" for h in hits[:8]) + " |")
        report += ["", "### Xref testuali ai letterali nel disassemblaggio lineare", ""]
        for k, refs in result["pc_relative_literal_refs_in_linear_disassembly"].items():
            report.append(f"`{k}`: " + (", ".join(f"`{r['site']}`" for r in refs) if refs else "nessun riferimento PC-relativo rilevato"))
        report += ["", "Le finestre complete sono nel file `.txt` allegato al rapporto.", ""]
    else:
        report += ["Per estendere l'analisi con nuove verifiche dei binari, eseguire con `--project-root` sul computer che contiene i TBM.", ""]
    report += [
        "## Limiti", "",
        "L'analisi offline rielabora l'evidenza caricata, non verifica autonomamente i 16 binari. "
        "La modalità locale verifica hash e ottiene nuove finestre `objdump`, ma il disassemblaggio ARC "
        "lineare può scambiare dati per istruzioni: serve revisione manuale dei blocchi base/CFG.",
        "", "Nessun collegamento fisico S2 dimostrato. Nessun firmware eseguito, modificato o flashato. "
        "Avanzamento funzionale complessivo invariato: **circa 10%**.", "",
    ]
    stem = "s33_capture_upstream"
    (out / f"{stem}.json").write_text(json.dumps(result, indent=2) + "\n")
    report_root = args.project_root.expanduser().resolve() if args.project_root else Path(__file__).resolve().parents[1]
    report_root = report_root / 'MDs'
    report_root.mkdir(parents=True, exist_ok=True)
    (report_root / f"{stem}.md").write_text("\n".join(report) + "\n")
    if windows:
        (out / f"{stem}_disassembly.txt").write_text("\n\n".join(
            f"====== {s} ======\n{v}" for s, v in windows.items()) + "\n")
    print(f"Saved {(report_root / f'{stem}.md')}")
    print(f"Saved {(out / f'{stem}.json')}")
    print("Original binary verification:", "YES" if args.project_root else "NO (offline)")


if __name__ == "__main__":
    main()
