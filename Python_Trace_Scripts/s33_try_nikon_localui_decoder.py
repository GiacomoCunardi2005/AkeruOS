#!/usr/bin/env python3
"""Run the unchanged upstream LocalUI Package decoder on an isolated S33 copy."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT / 'Research/Repositories/External_AkeruOS/nikon'
COMMIT = 'de8019ee30db7fe7bc61e520da289078ae82dcaa'
EXPECTED = '1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39'

RUNNER = r'''using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Buffers.Binary;
using Nikon_Patch;

class Probe {
    static void Check(bool ok) { if (!ok) throw new Exception("Self-check failed"); }
    static void Put(byte[] b, int p, uint v) => BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(p,4),v);
    static void Main(string[] args) {
        // Positive control: a minimal archive in the upstream format, not Nikon firmware.
        var plain = new byte[128];
        Put(plain,0x20,1); Put(plain,0x24,0x50);
        System.Text.Encoding.ASCII.GetBytes("test.bin").CopyTo(plain,0x30);
        Put(plain,0x40,0x50); Put(plain,0x44,4);
        new byte[]{1,2,3,4}.CopyTo(plain,0x50);
        var encoder = new Package(); Check(encoder.LoadData(plain));
        var control = new Package(); Check(control.LoadData(encoder.raw));
        Check(control.TryOpen() && control.header.Count==1 && control.blocks.Count==1);
        Check(control.blocks[0].SequenceEqual(new byte[]{1,2,3,4}));
        var invalid = (byte[])plain.Clone(); Put(invalid,0x24,129);
        var invalidEncoder = new Package(); Check(invalidEncoder.LoadData(invalid));
        var negative = new Package(); Check(negative.LoadData(invalidEncoder.raw));
        Check(!negative.TryOpen());

        var input = File.ReadAllBytes(args[0]);
        // Same header selection as Form1.DecodeAndExtractFirm; UI/file writes are replaced.
        bool v1Header = input.Take(0x20).All(b=>b==0x20);
        bool v2Header = !v1Header && input.Skip(0x20).Take(0x20).All(b=>b==0x20);
        int readOff = v2Header ? 0x20 : 0;
        Check(input.Length-readOff <= 48*1024*1024);
        var data = input.Skip(readOff).ToArray();
        var package = new Package();
        bool loaded = package.LoadData(data);
        if (loaded) File.WriteAllBytes(Path.Combine(args[1],"decoded_NON_INSTALLARE.out.bin"),package.raw);
        bool? opened=null; string error=null;
        try { opened=package.TryOpen(); } catch(Exception e) { error=e.ToString(); }
        if (opened==true) {
            for(int i=0;i<package.blocks.Count;i++)
                File.WriteAllBytes(Path.Combine(args[1],$"block_{i:00}_NON_INSTALLARE.bin"),package.blocks[i]);
        }
        var result = new {
            positive_control=true, negative_control=true, v1Header, v2Header, readOff,
            load_data=loaded, try_open=opened, error,
            raw_length=package.raw.Length, raw_first64=Convert.ToHexString(package.raw.Take(64).ToArray()),
            count=Sys.ReadUint32(package.raw,0x20), headerlen=Sys.ReadUint32(package.raw,0x24),
            extracted_blocks=package.blocks.Count
        };
        Console.WriteLine(JsonSerializer.Serialize(result));
        Check(input.SequenceEqual(File.ReadAllBytes(args[0])));
    }
}
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    source = ROOT / 'OriginalSoftware_NikonS33_V1.1/firmware.bin'
    data = source.read_bytes()
    assert len(data) == 29602084 and sha(data) == EXPECTED
    parent = ROOT / 'Risultati/Nikon_Firmware_Tools'
    out = parent / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=False)
    snapshots = out / 'fonti'
    snapshots.mkdir()
    provenance = []
    for name in ['Package.cs', 'IPackage.cs', 'CRC.cs', 'PatchControl.cs', 'Form1.cs', 'LocalUI.csproj']:
        path = 'Nikon-Patch/LocalUI/' + name
        content = subprocess.check_output(['git', '-C', str(REPO), 'show', f'{COMMIT}:{path}'])
        (snapshots / name).write_bytes(content)
        provenance.append(dict(file=path, sha256=sha(content), url=f'https://github.com/simeonpilgrim/nikon-firmware-tools/blob/{COMMIT}/{path}'))
    build = out / 'probe'
    build.mkdir()
    for name in ['Package.cs', 'IPackage.cs', 'CRC.cs']:
        (build / name).write_bytes((snapshots / name).read_bytes())
    patch_control = (snapshots / 'PatchControl.cs').read_text(encoding='utf-8-sig')
    start = patch_control.index('    static class Sys\n')
    end = patch_control.index('    public class Firmware\n', start)
    (build / 'Sys.cs').write_text('using System;\nusing System.Text;\nnamespace Nikon_Patch {\n' + patch_control[start:end] + '}\n')
    (build / 'Probe.cs').write_text(RUNNER)
    (build / 'Probe.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework><UseAppHost>false</UseAppHost><DisableTransitiveFrameworkReferenceDownloads>true</DisableTransitiveFrameworkReferenceDownloads></PropertyGroup></Project>\n')
    (build / 'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>\n')
    copy = out / 'S33_ORIGINAL_COPIA.bin'
    copy.write_bytes(data)
    env = dict(os.environ, DOTNET_CLI_HOME=str(out / 'dotnet_home'), DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_NOLOGO='1')
    for name, command in [
        ('build', ['dotnet', 'build', str(build / 'Probe.csproj'), '-c', 'Release', '--nologo']),
        ('run', ['dotnet', str(build / 'bin/Release/net8.0/Probe.dll'), str(copy), str(out)]),
    ]:
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=90)
        (out / f'{name}.log').write_text(result.stdout + result.stderr)
        assert result.returncode == 0, (name, result.stdout, result.stderr)
    probe = json.loads(result.stdout)
    assert probe['positive_control'] and probe['negative_control'] and probe['error'] is None
    assert source.read_bytes() == data == copy.read_bytes()
    spec = importlib.util.spec_from_file_location('s33_extract', ROOT / 'coolpix-s33-re/s33_extract.py')
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    sections, info = module.parse_firmware(data)
    tbm = next(s for s in sections if s.name == 'TBM_SK501')
    manifest = json.loads((ROOT / 'S33-sections/TBM_blocks/manifest.json').read_text())
    payloads = [b for b in manifest if b['within_file']]
    assert len(payloads) == 16 and [b['index'] for b in manifest if not b['within_file']] == [16]
    for block in payloads:
        payload = data[tbm.data_start + block['offset']:tbm.data_start + block['offset'] + block['size']]
        assert len(payload) == block['size'] and sha(payload) == block['sha256']
    decoded = (out / 'decoded_NON_INSTALLARE.out.bin').read_bytes()
    report = dict(commit=COMMIT, source=str(source.relative_to(ROOT)), source_size=len(data), source_sha256=sha(data),
                  sources=provenance, probe=probe, decoded_sha256=sha(decoded),
                  decoded_header_be=list(struct.unpack_from('>4I', decoded, 0x20)),
                  s33_parser_sections=[s.name for s in sections], s33_payload_hashes_verified=len(payloads),
                  originals_unchanged=True, hardware_access=False,
                  limitations=['Package/IPackage/CRC unchanged; Sys class extracted verbatim; Windows UI not executed.',
                               'Header selection reproduced from Form1; only original S33 V1.1 tested.',
                               'XOR output is a rejected analysis artifact, not installable firmware.'])
    (out / 'verified_evidence.json').write_text(json.dumps(report, indent=2) + '\n')
    (parent / 'latest.json').write_text(json.dumps(dict(evidence=str((out / 'verified_evidence.json').relative_to(ROOT))), indent=2) + '\n')
    print(json.dumps(dict(output=str(out), probe=probe, decoded_sha256=sha(decoded)), indent=2))


if __name__ == '__main__':
    main()
