#!/usr/bin/env python3
"""Import the saved MD corpus into PMB without the standard importer's truncation."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def chunks(text, limit=1800):
    parts = []
    while text:
        end = min(limit, len(text))
        if end < len(text):
            boundary = max(text.rfind("\n", limit // 2, end),
                           text.rfind(" ", limit // 2, end))
            if boundary >= 0:
                end = boundary + 1
        parts.append(text[:end])
        text = text[end:]
    return parts


def self_check():
    for text in ("", "αβγ\n" * 2500, "0x1F21F8" * 1000,
                 "Titolo\n\n" + "dato " * 7000):
        parts = chunks(text)
        assert "".join(parts) == text
        assert all(0 < len(p) <= 1800 for p in parts)


def main():
    self_check()
    if "--check" in sys.argv:
        print("PASS: chunk reconstruction, Unicode, long lines, empty input")
        return
    from pmb.core.engine import Engine

    out = Path((ROOT / ".pmb/migration-location.txt").read_text().strip())
    manifest = json.loads((out / "migration.json").read_text())
    assert not (out / "imported.json").exists(), "Corpus already imported"
    engine = Engine(cwd=ROOT)
    assert engine.workspace.id == manifest["workspace_id"]
    items, rows = [], []
    seen = {}
    for name, info in manifest["original_documents"].items():
        data = (ROOT / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == info["sha256"], name
        if info["sha256"] in seen:
            rows.append(dict(path=name, alias_of=seen[info["sha256"]]))
            continue
        seen[info["sha256"]] = name
        text = data.decode("utf-8")
        parts = chunks(text)
        assert "".join(parts) == text
        offset = 0
        row = dict(path=name, sha256=info["sha256"], chunks=[])
        for index, part in enumerate(parts):
            content = (f"AkeruOS Nikon COOLPIX S33 | {name} | "
                       f"parte {index + 1}/{len(parts)} | archivio documentale\n" + part)
            assert len(content) < 4000
            item = dict(type="fact", content=content, importance=0.55,
                        metadata=dict(source="akeruos-markdown-import", project="AkeruOS",
                                      file=name, original_sha256=info["sha256"],
                                      chunk=index, start_char=offset,
                                      historical_document=True))
            row["chunks"].append(dict(item=len(items), start=offset,
                                      end=offset + len(part), body_sha256=
                                      hashlib.sha256(part.encode()).hexdigest()))
            items.append(item)
            offset += len(part)
        rows.append(row)
    print(json.dumps(dict(documents=len(rows), unique_documents=len(seen),
                         chunks=len(items))), flush=True)
    engine.warmup(with_first_query=False)
    results = []
    for start in range(0, len(items), 128):
        batch = items[start:start + 128]
        result = engine.record_batch_bulk(batch)
        assert result["n_ok"] == len(batch) and not result["n_failed"], result
        results.extend(result["results"])
        (out / "import-progress.json").write_text(json.dumps(
            dict(completed=len(results), total=len(items))) + "\n")
        print(f"Imported {len(results)}/{len(items)}", flush=True)
    for row in rows:
        for chunk in row.get("chunks", []):
            ulid = results[chunk["item"]]["ulid"]
            event = engine.events.get_by_ulid(ulid)
            assert event.content == items[chunk["item"]]["content"], ulid
            chunk["ulid"] = ulid
    graph = engine.regraph()
    engine.close()
    (out / "imported.json").write_text(json.dumps(
        dict(documents=rows, n_chunks=len(items), n_unique_documents=len(seen),
             graph=graph, exact_content_roundtrip=True), ensure_ascii=False,
        indent=2) + "\n")
    print("PASS: every imported chunk read back exactly from PMB SQLite", flush=True)


if __name__ == "__main__":
    main()
