"""Offline protocol/client tests; USB transport exercised with a fake PyUSB API."""
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import akeru_ramdump as a


class ReplyDevice(a.SimulatedDevice):
    def __init__(self, alter):
        super().__init__(); self.alter = alter

    def handle(self, data):
        return self.alter(super().handle(data))


class Tests(unittest.TestCase):
    def client(self, device=None, fragment=37):
        return a.Client(a.SimulatedBulk(device, fragment))

    def test_crc_known_vector_and_frame(self):
        blob = a.frame(a.READ_RAM, 7, 0x1000, 3, payload=b'abc')
        self.assertEqual(blob.hex(), '414b524d0100030007000000001000000300000000000000030000003897afb4616263')
        self.assertEqual(a.zlib.crc32(b'123456789'), 0xcbf43926)
        self.assertEqual(a.decode(blob), (3, 7, 0x1000, 3, 0, b'abc'))
        for bad in (blob[:31], blob[:-1], blob+b'x', bytes([0])+blob[1:], blob[:-1]+b'X'):
            with self.subTest(bad=bad.hex()), self.assertRaises(a.ProtocolError):
                a.decode(bad)

    def test_fragmented_all_commands(self):
        for fragment in (1, 7, 37, 512, 8192):
            with self.subTest(fragment=fragment):
                client = self.client(fragment=fragment)
                self.assertTrue(client.hello()['synthetic'])
                self.assertFalse(client.info['full_map'])
                self.assertEqual(client.memory_map(), a.SimulatedDevice.regions)
                self.assertEqual(client.read_ram(0x1000, 64), bytes(k^16 for k in range(64)))
                self.assertEqual(struct.unpack('<IIIII', client.request(a.GET_STATUS)), (1,0x1000,64,0,0))
                self.assertEqual(client.request(a.ABORT), b'')
                with self.assertRaises(a.DeviceError) as error:
                    client.read_ram(0x1000, 1)
                self.assertEqual(error.exception.status, a.ABORTED)

    def test_no_ram_write_opcode(self):
        device = a.SimulatedDevice()
        for opcode in (0,6,255,0x8003):
            response = a.decode(device.handle(a.frame(opcode, 1, 0x1000, 4)))
            self.assertEqual(response[4:], (a.BAD_REQUEST,b''))
        self.assertEqual(device.reads, 0)

    def test_device_refuses_write_payload_and_control_arguments(self):
        device=a.SimulatedDevice()
        for request in (a.frame(a.READ_RAM,1,0x1000,1,payload=b'x'),
                        a.frame(a.GET_MAP,1,address=1),a.frame(a.HELLO,1,status=1)):
            self.assertEqual(a.decode(device.handle(request))[4:],(a.BAD_REQUEST,b''))
        self.assertEqual(device.reads,0)

    def test_malformed_error_reply_poisoned(self):
        for status,payload in ((99,b''),(a.READ_ERROR,b'x')):
            def alter(blob):
                op,seq,addr,n,_,_=a.decode(blob)
                return a.frame(op,seq,addr,n,status,payload)
            client=self.client(ReplyDevice(alter))
            with self.assertRaises(a.ProtocolError):client.hello()
            self.assertTrue(client.poisoned)

    def test_invalid_hello_capabilities(self):
        for maximum,flags in ((0,1),(4097,1),(4096,4)):
            def alter(blob):
                op,seq,addr,n,status,payload=a.decode(blob)
                return a.frame(op,seq,addr,n,status,payload[:24]+struct.pack('<II',maximum,flags))
            client=self.client(ReplyDevice(alter))
            with self.assertRaises(a.ProtocolError):client.hello()
            self.assertTrue(client.poisoned)

    def test_read_boundaries_and_overflow(self):
        client = self.client(); client.hello()
        for address,length in [(0x0fff,1),(0x1000,0),(0x1000,4097),(0x3327,2),
                               (0x7000,1),(0x0fe00000,1),(0xffffffff,2)]:
            with self.subTest(address=address,length=length), self.assertRaises(a.ProtocolError):
                client.read_ram(address,length)
        self.assertEqual(client.bulk.device.reads,0)

    def test_whitelist_validation(self):
        for regions in ([],[(1,0)],[(1,-1)],[(0x2000,20),(0x200a,1)],
                        [(a.MMIO_START-1,2)],[(1,1)]*17):
            with self.subTest(regions=regions), self.assertRaises(a.ProtocolError):
                a.validate_map(regions)

    def test_read_requires_hello(self):
        with self.assertRaises(a.ProtocolError):
            self.client().read_ram(0x1000,1)

    def test_corrupt_frame_poisoned(self):
        client=self.client(ReplyDevice(lambda b: b[:-1]+bytes([b[-1]^1])))
        with self.assertRaisesRegex(a.ProtocolError,'CRC'):client.hello()
        self.assertTrue(client.poisoned)
        with self.assertRaisesRegex(a.ProtocolError,'unusable'):client.hello()

    def test_response_identity_and_size(self):
        for index,value in [(0,0x8002),(1,123),(2,5),(3,99)]:
            def alter(blob):
                fields=list(a.decode(blob));fields[index]=value
                return a.frame(*fields[:5],payload=fields[5])
            client=self.client(ReplyDevice(alter))
            with self.subTest(index=index),self.assertRaises(a.ProtocolError):client.hello()
            self.assertTrue(client.poisoned)

    def test_partial_ram_reply(self):
        def alter(blob):
            op,seq,addr,n,status,payload=a.decode(blob)
            return a.frame(op,seq,addr,n,status,payload[:-1] if op==0x8003 else payload)
        client=self.client(ReplyDevice(alter));client.hello()
        with self.assertRaisesRegex(a.ProtocolError,'partial RAM'):client.read_ram(0x1000,10)
        self.assertTrue(client.poisoned)

    def test_invalid_map_reply(self):
        def alter(blob):
            op,seq,addr,n,status,payload=a.decode(blob)
            return a.frame(op,seq,addr,n,status,b'X' if op==0x8002 else payload)
        client=self.client(ReplyDevice(alter));client.hello()
        with self.assertRaises(a.ProtocolError):client.memory_map()
        self.assertTrue(client.poisoned)

    def test_io_timeout_no_automatic_retry(self):
        bulk=a.SimulatedBulk()
        with patch.object(bulk,'read',side_effect=TimeoutError('partial USB timeout')) as read:
            client=a.Client(bulk)
            with self.assertRaises(TimeoutError):client.hello()
            self.assertEqual(read.call_count,1)
            self.assertTrue(client.poisoned)

    def test_whole_transaction_deadline(self):
        client=self.client()
        with patch.object(a.time,'monotonic',side_effect=[0,3]):
            with self.assertRaises(TimeoutError):client.hello()

    def test_zero_or_oversized_transfer_count(self):
        for count in (0,33):
            bulk=a.SimulatedBulk()
            with patch.object(bulk,'write',return_value=count):
                client=a.Client(bulk)
                with self.assertRaises(a.ProtocolError):client.hello()
        bulk=a.SimulatedBulk()
        with patch.object(bulk,'read',return_value=b''):
            with self.assertRaises(a.ProtocolError):a.Client(bulk).hello()

    def test_dump_and_resume_after_read_error(self):
        with tempfile.TemporaryDirectory() as td:
            output=Path(td)/'ram.bin';device=a.SimulatedDevice();device.fail_address=0x2000
            with self.assertRaises(a.DeviceError):a.dump(self.client(device),output)
            report=json.loads(output.with_name('ram.bin.json').read_text())
            self.assertFalse(report['complete']);self.assertEqual(len(report['blocks']),1)
            self.assertEqual(output.stat().st_size,4096)
            self.assertEqual(report['errors'][0]['address'],0x2000)
            device.fail_address=None
            report=a.dump(self.client(device),output,resume=True)
            self.assertTrue(report['complete']);self.assertEqual(len(report['blocks']),4)
            expected=b''.join(bytes((x^(x>>8))&255 for x in range(addr,addr+n)) for addr,n in device.regions)
            self.assertEqual(output.read_bytes(),expected)
            self.assertEqual(sum(b['length'] for b in report['blocks']),9513)
            self.assertEqual(len(report['errors']),1)

    def test_resume_rejects_changed_epoch_and_corruption(self):
        with tempfile.TemporaryDirectory() as td:
            output=Path(td)/'ram.bin';a.dump(self.client(),output)
            device=a.SimulatedDevice();device.epoch=b'x'*16
            with self.assertRaisesRegex(a.ProtocolError,'epoch'):a.dump(self.client(device),output,True)
            saved=output.read_bytes();output.write_bytes(b'x'+saved[1:])
            with self.assertRaisesRegex(a.ProtocolError,'CRC'):a.dump(self.client(),output,True)

    def test_resume_rejects_uncommitted_tail(self):
        with tempfile.TemporaryDirectory() as td:
            output=Path(td)/'ram.bin';a.dump(self.client(),output)
            with output.open('ab') as f:f.write(b'uncommitted')
            with self.assertRaisesRegex(a.ProtocolError,'trailing'):a.dump(self.client(),output,True)
            self.assertTrue(output.read_bytes().endswith(b'uncommitted'))

    def test_dump_preserves_existing_files(self):
        with tempfile.TemporaryDirectory() as td:
            output=Path(td)/'ram.bin';output.write_bytes(b'photo')
            with self.assertRaises(FileExistsError):a.dump(self.client(),output)
            self.assertEqual(output.read_bytes(),b'photo')

    def test_pyusb_claim_and_refuse_msdc_without_writing(self):
        class Interface(list):
            bInterfaceClass=255;bInterfaceSubClass=0x41;bInterfaceProtocol=1
            bAlternateSetting=0;bInterfaceNumber=0
        interface=Interface([SimpleNamespace(bmAttributes=2,bEndpointAddress=0x81,wMaxPacketSize=512),
                             SimpleNamespace(bmAttributes=2,bEndpointAddress=2,wMaxPacketSize=512)])
        calls=[]
        class USB:
            def get_active_configuration(self):return [interface]
            def is_kernel_driver_active(self,n):return False
            def read(self,endpoint,size,timeout):
                self.assert_packet=(endpoint==0x81 and size==4608)
                calls.append('read');return b'abcdef'
        dev=USB()
        core=SimpleNamespace(find=lambda **kw:[dev])
        util=SimpleNamespace(claim_interface=lambda *x:calls.append('claim'),
            release_interface=lambda *x:calls.append('release'),dispose_resources=lambda *x:calls.append('dispose'))
        module=SimpleNamespace(core=core,util=util)
        with patch.dict(sys.modules,{'usb':module,'usb.core':core,'usb.util':util}):
            bulk=a.PyUSBBulk(1,2)
            self.assertEqual(bulk.read(2,100),b'ab');self.assertEqual(bulk.read(4,100),b'cdef')
            self.assertTrue(dev.assert_packet)
            bulk.close();self.assertEqual(calls,['claim','read','release','dispose'])
            calls.clear();interface.bInterfaceClass=8
            with self.assertRaises(a.ProtocolError):a.PyUSBBulk(0x04b0,0x035d)
            self.assertEqual(calls,['dispose'])


if __name__=='__main__':unittest.main()
