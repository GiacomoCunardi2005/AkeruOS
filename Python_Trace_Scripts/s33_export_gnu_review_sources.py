#!/usr/bin/env python3
"""Publish GNU modifications for review without writing inside source/build/install trees."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    out=ROOT/'Risultati/GNU/sorgenti'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True,exist_ok=False)
    env=dict(os.environ,GIT_OPTIONAL_LOCKS='0')
    rows=[]
    for lab in sorted((ROOT/'work').glob('gnu_arc700_*')):
        source=lab/'source/gnu-arc700-sim-src'
        assert (source/'.git').exists(),source
        def git(*args):
            return subprocess.check_output(['git','-C',str(source),*args],env=env)
        tracked=git('diff','--name-only','-z','HEAD','--').split(b'\0')
        untracked=git('ls-files','--others','--exclude-standard','-z').split(b'\0')
        paths=sorted({os.fsdecode(p) for p in tracked+untracked if p})
        dest=out/lab.name;dest.mkdir()
        patch=git('diff','--no-ext-diff','--no-textconv','--binary','HEAD','--')
        (dest/'changes.patch').write_bytes(patch)
        files=[]
        for rel in paths:
            assert not Path(rel).is_absolute() and '..' not in Path(rel).parts
            original=source/rel;target=dest/'source'/rel
            target.parent.mkdir(parents=True,exist_ok=True)
            expected=sha(original);shutil.copy2(original,target)
            assert sha(target)==expected and sha(original)==expected
            files.append(dict(path=rel,sha256=expected,bytes=original.stat().st_size,untracked=rel.encode() in untracked))
        engine=lab/'install/bin/arc-elf32-run'
        row=dict(variant=lab.name,source=str(source.relative_to(ROOT)),commit=git('rev-parse','HEAD').decode().strip(),
            export=str(dest.relative_to(ROOT)),files=files,patch_sha256=sha(dest/'changes.patch'),
            engine=str(engine.relative_to(ROOT)) if engine.exists() else None,engine_sha256=sha(engine) if engine.exists() else None,
            status='REVIEW_SNAPSHOT_ONLY; not a new semantic or boot test')
        (dest/'manifest.json').write_text(json.dumps(row,indent=2)+'\n');rows.append(row)
    manifest=out/'manifest.json'
    manifest.write_text(json.dumps(dict(variants=rows,work_trees_modified=False,original_builds_retained=True,
        scope='All tracked modifications and non-ignored untracked source files; base source identified by Git commit; binaries remain in work'),indent=2)+'\n')
    (out.parent/'latest.json').write_text(json.dumps({'manifest':str(manifest.relative_to(ROOT))},indent=2)+'\n')
    print('PASS review exports:',len(rows),'variants;',sum(len(r['files']) for r in rows),'source snapshots;',manifest)


if __name__=='__main__':main()
