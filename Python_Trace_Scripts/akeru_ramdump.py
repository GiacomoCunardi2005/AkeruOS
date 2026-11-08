#!/usr/bin/env python3
"""AkeruRAM v1 host client and byte-stream simulator. No firmware/hardware binding yet."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import time
import zlib

HEADER = struct.Struct('<4sHHIIIIII')
HELLO, GET_MAP, READ_RAM, GET_STATUS, ABORT = range(1, 6)
RESPONSE = 0x8000
MAX_BLOCK = 4096
MAX_REGIONS = 16
OK, BAD_REQUEST, BAD_RANGE, READ_ERROR, ABORTED = range(5)
MMIO_START = 0x0FE00000


class ProtocolError(ValueError):
    pass


class DeviceError(ProtocolError):
    def __init__(self, status):
        self.status = status
        super().__init__(f'device status {status}')


def frame(op, sequence, address=0, length=0, status=0, payload=b''):
    if len(payload) > MAX_BLOCK:
        raise ProtocolError('payload too large')
    prefix = HEADER.pack(b'AKRM', 1, op, sequence, address, length, status, len(payload), 0)
    crc = zlib.crc32(payload, zlib.crc32(prefix[:28]))
    return prefix[:28]+struct.pack('<I', crc)+payload


def decode(data):
    if len(data) < HEADER.size:
        raise ProtocolError('short header')
    magic, version, op, seq, address, length, status, size, crc = HEADER.unpack_from(data)
    if magic != b'AKRM' or version != 1 or size > MAX_BLOCK or len(data) != HEADER.size+size:
        raise ProtocolError('invalid frame header/length')
    if zlib.crc32(data[32:], zlib.crc32(data[:28])) != crc:
        raise ProtocolError('CRC mismatch')
    return op, seq, address, length, status, data[32:]


def validate_map(regions):
    if not 0 < len(regions) <= MAX_REGIONS:
        raise ProtocolError('empty/oversized RAM whitelist')
    end = 0
    for address, length in regions:
        if length <= 0 or address < end or address+length > MMIO_START:
            raise ProtocolError('invalid/overlapping/MMIO RAM whitelist')
        end = address+length
    return regions


def plan(regions, block):
    for address, length in regions:
        for offset in range(0, length, block):
            yield address+offset, min(block, length-offset)


class SimulatedDevice:
    """Synthetic immutable fixture only; these addresses are not a Nikon RAM map."""
    regions = [(0x1000, 9000), (0x8000, 513)]
    epoch = hashlib.sha256(b'AkeruRAM immutable synthetic fixture v1').digest()[:16]

    def __init__(self):
        self.aborted = False
        self.reads = 0
        self.last_address = self.last_length = self.last_status = 0
        self.fail_address = None

    def handle(self, request):
        op, seq, address, length, status, payload = decode(request)
        result, reply = OK, b''
        if status or payload or op not in (HELLO, GET_MAP, READ_RAM, GET_STATUS, ABORT):
            result = BAD_REQUEST
        elif op != READ_RAM and (address or length):
            result = BAD_REQUEST
        elif op == HELLO:
            reply = b'AkeruRAM'+self.epoch+struct.pack('<II', MAX_BLOCK, 1)  # flag1: synthetic, map incomplete
        elif op == GET_MAP:
            reply = b''.join(struct.pack('<II', *r) for r in self.regions)
        elif op == ABORT:
            self.aborted = True
        elif op == GET_STATUS:
            reply = struct.pack('<IIIII', self.reads, self.last_address, self.last_length,
                                self.last_status, int(self.aborted))
        elif self.aborted:
            result = ABORTED
        elif not 0 < length <= MAX_BLOCK or address+length > 0x100000000 or not any(
                a <= address and address+length <= a+n for a, n in self.regions):
            result = BAD_RANGE
        elif address == self.fail_address:
            result = READ_ERROR
        else:
            reply = bytes(((a ^ (a >> 8)) & 255) for a in range(address, address+length))
            self.reads += 1
        if op == READ_RAM:
            self.last_address, self.last_length, self.last_status = address, length, result
        return frame(op | RESPONSE, seq, address, length, result, reply)


class SimulatedBulk:
    """Fragmented bulk byte-stream boundary; no USB controller/kernel emulation."""
    def __init__(self, device=None, fragment=37):
        self.device = device or SimulatedDevice()
        self.fragment = fragment
        self.incoming = bytearray()
        self.outgoing = bytearray()

    def write(self, data, timeout):
        n = min(len(data), self.fragment)
        self.incoming.extend(data[:n])
        if len(self.incoming) >= 32:
            size = HEADER.unpack_from(self.incoming)[7]
            if size > MAX_BLOCK:
                raise ProtocolError('oversized simulator request')
            if len(self.incoming) == 32+size:
                self.outgoing.extend(self.device.handle(bytes(self.incoming)))
                self.incoming.clear()
        return n

    def read(self, size, timeout):
        if not self.outgoing:
            raise TimeoutError('simulated endpoint timeout')
        n = min(size, self.fragment, len(self.outgoing))
        data = bytes(self.outgoing[:n]); del self.outgoing[:n]
        return data

    def close(self):
        pass


class PyUSBBulk:
    def __init__(self, vid, pid):
        import usb.core
        import usb.util
        self.util = usb.util
        self.device = None
        devices = list(usb.core.find(find_all=True, idVendor=vid, idProduct=pid))
        if len(devices) != 1:
            raise ProtocolError('need exactly one explicitly selected USB device')
        dev = devices[0]
        try:
            self._claim(dev)
        except Exception:
            self.util.dispose_resources(dev)
            raise

    def _claim(self, dev):
        cfg = dev.get_active_configuration()
        interfaces = list(cfg)
        if len(interfaces) != 1:
            raise ProtocolError('dedicated single-interface mode required')
        interface = interfaces[0]
        if (interface.bInterfaceClass, interface.bInterfaceSubClass, interface.bInterfaceProtocol,
                interface.bAlternateSetting) != (255, 0x41, 1, 0):
            raise ProtocolError('not the AkeruRAM dedicated interface')
        endpoints = list(interface)
        if len(endpoints) != 2 or any(ep.bmAttributes & 3 != 2 or
                ep.wMaxPacketSize not in (64,512) or ep.bEndpointAddress & 15 == 0 for ep in endpoints):
            raise ProtocolError('need exactly two bulk endpoints')
        ins = [ep for ep in endpoints if ep.bEndpointAddress & 128]
        outs = [ep for ep in endpoints if not ep.bEndpointAddress & 128]
        if len(ins) != 1 or len(outs) != 1:
            raise ProtocolError('need one IN and one OUT endpoint')
        self.number = interface.bInterfaceNumber
        if dev.is_kernel_driver_active(self.number):
            raise ProtocolError('interface has a kernel driver; refusing detach')
        self.util.claim_interface(dev, self.number)
        self.device, self.ep_in, self.ep_out = dev, ins[0].bEndpointAddress, outs[0].bEndpointAddress
        packet = ins[0].wMaxPacketSize
        self.read_size = ((MAX_BLOCK+32+packet-1)//packet)*packet
        self.pending = bytearray()

    def write(self, data, timeout):
        return self.device.write(self.ep_out, data, timeout=timeout)

    def read(self, size, timeout):
        if not self.pending:
            # Read whole USB packets even when the framing layer only needs a header.
            self.pending.extend(self.device.read(self.ep_in, self.read_size, timeout=timeout))
        data = bytes(self.pending[:size]); del self.pending[:size]
        return data

    def close(self):
        if self.device is not None:
            try:
                self.util.release_interface(self.device, self.number)
            finally:
                self.util.dispose_resources(self.device)
                self.device = None


class Client:
    def __init__(self, bulk, timeout_ms=2000):
        if not 0 < timeout_ms <= 60000:
            raise ValueError('timeout must be 1..60000 ms')
        self.bulk, self.timeout_ms = bulk, timeout_ms
        self.sequence, self.poisoned = 0, False
        self.info = None

    def _remaining(self, deadline):
        ms = int((deadline-time.monotonic())*1000)
        if ms <= 0:
            raise TimeoutError('whole transaction deadline')
        return ms

    def _read(self, count, deadline):
        result = bytearray()
        while len(result) < count:
            data = self.bulk.read(count-len(result), self._remaining(deadline))
            if not 0 < len(data) <= count-len(result):
                raise ProtocolError('zero/oversized bulk read')
            result.extend(data)
        return bytes(result)

    def request(self, op, address=0, length=0):
        if self.poisoned or self.sequence == 0xFFFFFFFF:
            raise ProtocolError('transport unusable; reconnect before another request')
        self.sequence += 1
        request = frame(op, self.sequence, address, length)
        deadline = time.monotonic()+self.timeout_ms/1000
        try:
            sent = 0
            while sent < len(request):
                n = self.bulk.write(request[sent:], self._remaining(deadline))
                if not 0 < n <= len(request)-sent:
                    raise ProtocolError('zero/oversized bulk write')
                sent += n
            header = self._read(32, deadline)
            size = HEADER.unpack(header)[7]
            if size > MAX_BLOCK:
                raise ProtocolError('response exceeds buffer limit')
            response = decode(header+self._read(size, deadline))
            code, seq, addr, count, status, payload = response
            if (code, seq, addr, count) != (op | RESPONSE, self.sequence, address, length):
                raise ProtocolError('response identity mismatch')
            if status:
                if status not in range(1, 5) or payload:
                    raise ProtocolError('malformed error response')
                raise DeviceError(status)
            expected = {HELLO:32, GET_STATUS:20, ABORT:0}.get(op)
            if expected is not None and len(payload) != expected:
                raise ProtocolError('wrong command response size')
            return payload
        except DeviceError:
            raise
        except Exception:
            self.poisoned = True
            raise

    def hello(self):
        data = self.request(HELLO)
        if len(data) != 32 or data[:8] != b'AkeruRAM':
            self.poisoned = True
            raise ProtocolError('HELLO identity mismatch')
        maximum, flags = struct.unpack_from('<II', data, 24)
        if not 0 < maximum <= MAX_BLOCK or flags & ~3 or data[8:24] == bytes(16):
            self.poisoned = True
            raise ProtocolError('invalid capabilities/epoch')
        self.info = dict(epoch=data[8:24].hex(), max_block=maximum,
                         synthetic=bool(flags & 1), full_map=bool(flags & 2), atomic=False)
        return self.info

    def memory_map(self):
        data = self.request(GET_MAP)
        try:
            if len(data) % 8:
                raise ProtocolError('invalid map size')
            return validate_map(list(struct.iter_unpack('<II', data)))
        except ProtocolError:
            self.poisoned = True
            raise

    def read_ram(self, address, length):
        if self.info is None or not 0 < length <= self.info['max_block']:
            raise ProtocolError('HELLO required and block must fit negotiated limit')
        data = self.request(READ_RAM, address, length)
        if len(data) != length:
            self.poisoned = True
            raise ProtocolError('partial RAM response')
        return data


def save_manifest(path, report):
    with tempfile.NamedTemporaryFile(mode='w',dir=path.parent,prefix=path.name+'.',delete=False) as f:
        temporary = Path(f.name)
        try:
            json.dump(report, f, indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def dump(client, output, resume=False):
    output = Path(output)
    manifest = output.with_name(output.name+'.json')
    info = client.hello()
    regions = client.memory_map()
    identity = dict(protocol='AkeruRAM1', **info, regions=[list(r) for r in regions])
    if resume:
        report = json.loads(manifest.read_text())
        if report['identity'] != identity:
            raise ProtocolError('resume epoch/map/capabilities changed')
    else:
        if manifest.exists():
            raise FileExistsError(manifest)
        report = dict(identity=identity, blocks=[], errors=[], complete=False)
    with output.open('r+b' if resume else 'xb') as f:
        requests = iter(plan(regions, info['max_block']))
        committed = 0
        for block in report['blocks']:
            wanted = next(requests, None)
            if wanted != (block['address'], block['length']) or block['offset'] != committed or block['status'] != OK:
                raise ProtocolError('invalid resume block order/status')
            data = f.read(block['length'])
            if len(data) != block['length'] or f'{zlib.crc32(data):08x}' != block['crc32']:
                raise ProtocolError('resume data CRC mismatch/truncation')
            committed += len(data)
        f.seek(0, 2)
        if f.tell() != committed:
            raise ProtocolError('uncommitted/trailing data; preserve files for manual recovery')
        save_manifest(manifest, report)
        for address, length in requests:
            try:
                data = client.read_ram(address, length)
            except Exception as exc:
                report['complete'] = False
                report['errors'].append(dict(address=address, length=length,
                    status=getattr(exc, 'status', None), error=str(exc)))
                save_manifest(manifest, report)
                raise
            f.write(data); f.flush(); os.fsync(f.fileno())
            report['blocks'].append(dict(address=address, length=length, offset=committed,
                crc32=f'{zlib.crc32(data):08x}', status=OK))
            committed += len(data)
            save_manifest(manifest, report)
        report['complete'] = True
        save_manifest(manifest, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    transport = parser.add_mutually_exclusive_group(required=True)
    transport.add_argument('--simulate', action='store_true')
    transport.add_argument('--usb', action='store_true')
    parser.add_argument('--vid', type=lambda x: int(x, 0))
    parser.add_argument('--pid', type=lambda x: int(x, 0))
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--info', action='store_true'); action.add_argument('--map', action='store_true')
    action.add_argument('--dump', action='store_true'); action.add_argument('--status', action='store_true')
    action.add_argument('--abort', action='store_true')
    parser.add_argument('--output', type=Path); parser.add_argument('--resume', action='store_true')
    args = parser.parse_args()
    if args.usb and (args.vid is None or args.pid is None):
        parser.error('--usb requires explicit --vid and --pid; no production identity assigned')
    if args.dump and args.output is None or args.resume and not args.dump:
        parser.error('--dump requires --output; --resume is only for --dump')
    bulk = SimulatedBulk() if args.simulate else PyUSBBulk(args.vid, args.pid)
    try:
        client = Client(bulk)
        if args.dump:
            result = dump(client, args.output, args.resume)
            print(json.dumps(dict(complete=result['complete'], blocks=len(result['blocks']),
                identity=result['identity']), indent=2))
        else:
            info = client.hello()
            result = info if args.info else client.memory_map() if args.map else list(struct.unpack('<IIIII', client.request(GET_STATUS))) if args.status else client.request(ABORT).hex()
            print(json.dumps(result, indent=2))
    finally:
        bulk.close()


if __name__ == '__main__':
    main()
