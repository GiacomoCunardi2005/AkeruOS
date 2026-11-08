#!/usr/bin/env python3
"""Corroborate the candidate GUI lookup-table producer against REA and GNU."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, disasm, locate, raw, u32


def main():
    target = ROOT / 'Risultati/Analisi_storiche/block00-analysis.elf'
    target_hash = hashlib.sha256(target.read_bytes()).hexdigest()
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
    for address, size in ((0x17ac14, 0x18), (0x17ac40, 0xac), (0x17acf0, 4), (0x17b164, 4)):
        block, offset = locate(address, size)
        assert raw(address, size) == dump[block['offset'] + offset:block['offset'] + offset + size]
    assert u32(0x17acf0) == u32(0x17b164) == 0x47a448
    needle = (0x47a448).to_bytes(4, 'little')
    hits = []
    for block in BS:
        data = PS[block['index']]
        for offset in range(len(data) - 3):
            if data[offset:offset + 4] == needle:
                hits.append((block['index'], block['load_address_candidate'] + offset))
    assert hits == [(0, 0x17acf0), (0, 0x17b164)], hits
    listing = disasm(0x17ac14, 0x17ac2c) + disasm(0x17ac40, 0x17acec)
    for expected in ('mov_s\tr14,r0', 'mov\tr0,256', '0x17acf0', 'stb\tr16,[r2]',
                     'stb_s\tr15,[r2,0x1]', 'stb\tr17,[r2,2]', 'stb_s\tr0,[r2,0x3]'):
        assert expected in listing, expected

    config = tomllib.loads(Path('/home/jack/.codex-homes/profiles/codex-main/config.toml').read_text())['mcp_servers']['rea-arc']
    process = subprocess.Popen([config['command'], *config['args']], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, env={**os.environ, **config['env']})

    def request(number, method, params):
        process.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': number, 'method': method, 'params': params}) + '\n')
        process.stdin.flush()
        for line in process.stdout:
            response = json.loads(line)
            if response.get('id') == number:
                if 'error' in response:
                    raise RuntimeError(response['error'])
                return response['result']
        raise RuntimeError('REA terminated unexpectedly: ' + process.stderr.read())

    def call(number, name, arguments):
        result = request(number, 'tools/call', {'name': name, 'arguments': arguments})
        value = result.get('structuredContent') or json.loads(result['content'][0]['text'])
        if result.get('isError') or 'error' in value:
            raise RuntimeError(value)
        return value

    try:
        request(1, 'initialize', {'protocolVersion': '2025-03-26', 'capabilities': {},
                                  'clientInfo': {'name': 's33-lookup-init', 'version': '1'}})
        process.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        process.stdin.flush()
        opened = call(2, 'open_binary', {'path': str(target), 'provider_id': 'ghidra'})
        assert opened['result']['architecture'] == 'arcompact'
        segments = call(3, 'list_segments', {})
        text = next(segment for segment in segments['normalized_result'] if segment['name'] == '.text')
        assert text['start'] == '0xad800' and text['image_base'] == '0x0'
        reads = []
        for number, (address, size) in enumerate(((0x17ac14, 0x18), (0x17ac40, 0xac), (0x17acf0, 4), (0x17b164, 4)), 4):
            value = call(number, 'read_bytes', {'address': hex(address), 'length': size})
            assert value['normalized_result']['bytes_hex'] == raw(address, size).hex()
            reads.append(value)
        call(8, 'close_binary', {})
        assert hashlib.sha256(target.read_bytes()).hexdigest() == target_hash
        out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('lookup_init_%Y%m%dT%H%M%SZ')
        out.mkdir(parents=True, exist_ok=False)
        (out / 'gnu_disassembly.txt').write_text(listing)
        (out / 'evidence.json').write_text(json.dumps({'target_sha256': target_hash, 'segments': segments,
            'reads': reads, 'literal_hits': [[i, hex(a)] for i, a in hits],
            'limitations': ['Static candidate addresses; the scan only covers literal little-endian words in verified payloads.',
                            'No runtime palette, call path or physical display is established.']}, indent=2) + '\n')
        print('PASS:', out, flush=True)
    finally:
        process.terminate()
        process.wait(timeout=10)


if __name__ == '__main__':
    main()
