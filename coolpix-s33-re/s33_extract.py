#!/usr/bin/env python3
"""Read-only parser and optional payload extractor for COOLPIX S33 v1.1.

Reverse-engineered, experimental layout. No flashing / firmware modifications.
All offsets are derived from descriptors where possible; recognition is specific
for the observed 2016 Nikon firmware.bin, not a general Nikon format parser.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from functools import reduce
import hashlib
import json
from pathlib import Path
from operator import xor
import struct
import sys

KNOWN_SHA256 = "1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39"


class FormatError(ValueError):
    pass


def u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise FormatError(f"u32 outside input at 0x{offset:X}")
    return struct.unpack_from("<I", data, offset)[0]


def require(cond: bool, message: str):
    if not cond:
        raise FormatError(message)


@dataclass(frozen=True)
class Section:
    name: str
    marker_offset: int
    descriptor_offset: int
    data_start: int
    data_length: int
    data_end: int
    end_field_offset: int | None


def parse_firmware(data: bytes) -> tuple[list[Section], dict]:
    require(len(data) >= 0x100, "File too small")
    require(data[4:8] == b"V2.0", "Unexpected header version; this parser expects V2.0")

    # 'TBIB_SK501.BIN' is at 0x20; the triplet is at marker+0x40.
    first_marker = 0x20
    require(data[first_marker:].startswith(b"TBIB_SK501.BIN"), "First TBIB marker missing")
    d1 = first_marker + 0x40
    s1, n1, e1 = (u32(data, d1 + i) for i in (0, 4, 8))
    require(s1 == d1 + 12 and s1 + n1 == e1 and e1 <= len(data),
            "Inconsistent TBIB descriptor")
    one = Section("TBIB_SK501", first_marker, d1, s1, n1, e1, d1 + 8)

    # Second marker is exactly at the end reported by the first descriptor.
    second_marker = e1
    require(data[second_marker:].startswith(b"TBM_SK501.BIN"),
            f"TBM marker not found at 0x{second_marker:X}")
    d2 = second_marker + 0x40
    s2, n2, e2 = (u32(data, d2 + i) for i in (0, 4, 8))
    require(s2 == d2 + 12 and s2 + n2 == e2 and e2 <= len(data),
            "Inconsistent TBM descriptor")
    two = Section("TBM_SK501", second_marker, d2, s2, n2, e2, d2 + 8)

    # P1RES immediately follows TBM; its descriptor is at marker+0x40.
    third_marker = e2
    require(data[third_marker:].startswith(b"P1RES\x00"),
            f"P1RES marker not found at 0x{third_marker:X}")
    padding = data[e2:third_marker]
    d3 = third_marker + 0x40
    s3, n3 = (u32(data, d3 + i) for i in (0, 4))
    require(s3 == d3 + 12 and n3 >= 0x14 and s3 + n3 <= len(data),
            "Inconsistent P1RES descriptor")
    e3 = s3 + n3
    three = Section("P1RES", third_marker, d3, s3, n3, e3, None)

    # The following are *not* understood as a checksum or version yet.
    # P1RES contains a word at +0x10 that, in the observed firmware,
    # points exactly at the JPEG found by Binwalk (relative to data start).
    first_resource_rel = u32(data, s3 + 0x10)
    first_resource_abs = s3 + first_resource_rel
    first_resource_in_payload = s3 <= first_resource_abs < e3
    first_resource_starts_jpeg = (
        data[first_resource_abs:first_resource_abs + 3] == b"\xff\xd8\xff"
        if first_resource_in_payload else None
    )
    # 12B060..12B084 compares this XOR with the first word; it is not a fixed magic.
    require(len(data) % 4 == 0, "Package XOR requires whole words")
    checksum = reduce(xor, (word[0] for word in struct.iter_unpack('<I', data[4:])), 0)
    require(checksum == u32(data, 0), "Package XOR mismatch")
    info = {
        "container_magic": data[:4].hex(),
        "container_version": data[4:8].decode("ascii"),
        "gap_before_P1RES": {
            "start": e2,
            "end": third_marker,
            "size": len(padding),
            "all_zero": all(b == 0 for b in padding),
        },
        "P1RES_unknown_u32_after_length": [u32(data, d3 + 8)],
        "trailer": {
            "start": e3,
            "size": len(data) - e3,
            "hex": data[e3:].hex(),
        },
        "P1RES_first_64_bytes_hex": data[s3:min(s3 + 64, e3)].hex(" "),
        "P1RES_word_at_plus_0x0C": u32(data, s3 + 0x0C),
        "P1RES_first_resource_relative_candidate": first_resource_rel,
        "P1RES_first_resource_absolute_candidate": first_resource_abs,
        "P1RES_first_resource_in_payload": first_resource_in_payload,
        "P1RES_first_resource_starts_jpeg": first_resource_starts_jpeg,
    }
    return [one, two, three], info


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path, help="Original Nikon firmware.bin")
    parser.add_argument("--extract", action="store_true", help="Write payload copies to --out")
    parser.add_argument("--out", type=Path, default=Path("s33_sections"), help="Output directory")
    args = parser.parse_args()

    try:
        data = args.firmware.read_bytes()
        sections, info = parse_firmware(data)
        sha = hashlib.sha256(data).hexdigest()
        matching = sha == KNOWN_SHA256
        manifest = {
            "source_name": args.firmware.name,
            "source_size": len(data),
            "source_sha256": sha,
            "matches_observed_v1_1_sha256": matching,
            "structure_status": "experimental, observed on Nikon COOLPIX S33 v1.1",
            "sections": [asdict(s) for s in sections],
            "metadata": info,
        }

        print(f"Input: {args.firmware} ({len(data):,} bytes)")
        print(f"SHA-256: {sha}")
        print(f"Matches observed image: {matching}")
        print("\nPayload regions:")
        for s in sections:
            print(f"  {s.name:12} header=0x{s.marker_offset:08X} "
                  f"data=0x{s.data_start:08X} size={s.data_length:,} "
                  f"end=0x{s.data_end:08X}")
        print(f"\nP1RES gap: {info['gap_before_P1RES']['size']} bytes "
              f"(zero={info['gap_before_P1RES']['all_zero']})")
        print(f"After P1RES: {info['trailer']['size']} bytes: {info['trailer']['hex']}")
        print(f"P1RES header extra words: {info['P1RES_unknown_u32_after_length']}")
        print(f"P1RES word at +0x0C: {info['P1RES_word_at_plus_0x0C']}")
        print(f"P1RES resource-offset candidate: +0x{info['P1RES_first_resource_relative_candidate']:X} "
              f"= 0x{info['P1RES_first_resource_absolute_candidate']:X} "
              f"(JPEG={info['P1RES_first_resource_starts_jpeg']})")

        if args.extract:
            args.out.mkdir(parents=True, exist_ok=True)
            # Fail rather than overwrite any existing output file.
            for i, section in enumerate(sections, start=1):
                path = args.out / f"{i:02d}_{section.name}_payload.bin"
                if path.exists():
                    raise FileExistsError(f"Output already exists: {path}")
            manifest_path = args.out / "manifest.json"
            if manifest_path.exists():
                raise FileExistsError(f"Output already exists: {manifest_path}")
            for i, section in enumerate(sections, start=1):
                path = args.out / f"{i:02d}_{section.name}_payload.bin"
                payload = data[section.data_start:section.data_end]
                with path.open("xb") as fp:
                    fp.write(payload)
                manifest["sections"][i - 1]["payload_sha256"] = hashlib.sha256(payload).hexdigest()
                manifest["sections"][i - 1]["saved_as"] = path.name
                print(f"Wrote: {path} ({len(payload):,} bytes)")
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            print(f"Wrote: {manifest_path}")
        else:
            print("\nNo files extracted. Add --extract to save payload copies.")
        return 0
    except (FormatError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
