#!/usr/bin/env python3
"""Verify REA ARC GUI import against the original V1.1 payload."""
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
from static_common import raw


def main():
    config = tomllib.loads(Path('/home/jack/.codex-homes/profiles/codex-main/config.toml').read_text())['mcp_servers']['rea-arc']
    target = ROOT / 'Risultati/Analisi_storiche/tbm-02-analysis.elf'
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    process = subprocess.Popen([config['command'], *config['args']], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True, env={**os.environ, **config['env']})

    def request(number, method, params):
        process.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': number, 'method': method, 'params': params}) + '\n')
        process.stdin.flush()
        for line in process.stdout:
            response = json.loads(line)
            if response.get('id') == number:
                if 'error' in response:
                    raise RuntimeError(response['error'])
                return response['result']
        raise RuntimeError('REA terminated unexpectedly')

    def call(number, name, arguments):
        result = request(number, 'tools/call', {'name': name, 'arguments': arguments})
        value = result.get('structuredContent') or json.loads(result['content'][0]['text'])
        if result.get('isError') or 'error' in value:
            raise RuntimeError(value)
        return value

    try:
        request(1, 'initialize', {'protocolVersion': '2025-03-26', 'capabilities': {},
                                  'clientInfo': {'name': 's33-gui', 'version': '1'}})
        process.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        process.stdin.flush()
        opened = call(2, 'open_binary', {'path': str(target), 'provider_id': 'ghidra'})
        assert opened['result']['architecture'] == 'arcompact'
        segments = call(3, 'list_segments', {})
        text = next(segment for segment in segments['normalized_result'] if segment['name'] == '.text')
        assert text['start'] == '0x5fe800' and text['image_base'] == '0x0'
        profile = segments['analysis_profile']['parameters']
        assert profile['loader'] == 'ElfLoader' and profile['elf_image_base'] == '0x0'
        results = []
        for i, address in enumerate((0x6316bc, 0x631f44, 0x631878)):
            observed = call(4 + i * 2, 'read_bytes', {'address': hex(address), 'length': 64})
            assert observed['normalized_result']['bytes_hex'] == raw(address, 64).hex()
            assembly = call(5 + i * 2, 'procedure_assembly', {'procedure': hex(address)})
            assert hex(address) in assembly['normalized_result']
            results.append({'address': hex(address), 'bytes': observed, 'assembly': assembly})
        call(10, 'close_binary', {})
        assert hashlib.sha256(target.read_bytes()).hexdigest() == digest
        out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('rea_gui_verified_%Y%m%dT%H%M%SZ')
        out.mkdir(parents=True, exist_ok=False)
        (out / 'evidence.json').write_text(json.dumps({'target_sha256': digest, 'segments': segments, 'results': results,
            'limits': ['Function entries seeded explicitly; Ghidra instruction decoding and bodies require independent checks.',
                       'Static analysis only; no camera runtime or display observed.']}, indent=2) + '\n')
        print('PASS:', out)
    finally:
        process.terminate()
        process.wait(timeout=10)


if __name__ == '__main__':
    main()
