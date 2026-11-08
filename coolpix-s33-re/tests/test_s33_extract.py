"""Run with python3 -m unittest discover -s tests -v (from repo root)."""
import sys
from pathlib import Path
import struct
import unittest
from functools import reduce
from operator import xor

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from s33_extract import parse_firmware, FormatError


def fixture():
    d = bytearray(b"\xAA" * 0x210)
    d[0:4] = bytes.fromhex("f99b4abd")
    d[4:8] = b"V2.0"
    d[0x20:0x2E] = b"TBIB_SK501.BIN"
    struct.pack_into("<III", d, 0x60, 0x6C, 0x80, 0xEC)
    d[0xEC:0xFA] = b"TBM_SK501.BIN"
    struct.pack_into("<III", d, 0x12C, 0x138, 0x50, 0x188)
    d[0x188:0x18E] = b"P1RES\x00"
    struct.pack_into("<III", d, 0x1C8, 0x1D4, 0x30, 0)
    struct.pack_into("<I", d, 0x1D4, 1000)
    d[0x204:0x210] = bytes.fromhex("000102030405060708090a0b")
    struct.pack_into('<I', d, 0, reduce(xor, (w[0] for w in struct.iter_unpack('<I', d[4:])), 0))
    return bytes(d)


class TestS33(unittest.TestCase):
    def test_sections_and_trailer(self):
        sections, info = parse_firmware(fixture())
        self.assertEqual([x.name for x in sections], ["TBIB_SK501", "TBM_SK501", "P1RES"])
        self.assertEqual([x.data_start for x in sections], [0x6C, 0x138, 0x1D4])
        self.assertEqual([x.data_end for x in sections], [0xEC, 0x188, 0x204])
        self.assertEqual(info["trailer"]["size"], 12)
        self.assertEqual(info["gap_before_P1RES"]["size"], 0)
        self.assertEqual(info["P1RES_unknown_u32_after_length"], [0])
        self.assertEqual(info["P1RES_first_64_bytes_hex"][:11], "e8 03 00 00")

    def test_reject_corrupt_length(self):
        d = bytearray(fixture())
        struct.pack_into("<I", d, 0x64, 0x81)
        with self.assertRaises(FormatError):
            parse_firmware(bytes(d))

    def test_reject_corrupt_package_xor(self):
        d = bytearray(fixture())
        d[0x70] ^= 1
        with self.assertRaisesRegex(FormatError, 'XOR mismatch'):
            parse_firmware(bytes(d))

    def test_accept_recomputed_package_xor(self):
        d = bytearray(fixture())
        d[0x70] ^= 1
        struct.pack_into('<I', d, 0, reduce(xor, (w[0] for w in struct.iter_unpack('<I', d[4:])), 0))
        self.assertEqual(parse_firmware(bytes(d))[0], parse_firmware(fixture())[0])

    def test_reject_short_resource_metadata(self):
        d = bytearray(fixture())
        struct.pack_into('<I', d, 0x1CC, 1)
        with self.assertRaisesRegex(FormatError, 'P1RES descriptor'):
            parse_firmware(bytes(d))

    def test_reject_payload_truncation(self):
        for end in (0xEB, 0x187, 0x203):
            with self.subTest(end=end), self.assertRaises(FormatError):
                parse_firmware(fixture()[:end])

    def test_reject_descriptor_outside_file(self):
        for descriptor in (0x60, 0x12C, 0x1C8):
            d = bytearray(fixture())
            struct.pack_into('<I', d, descriptor, len(d)+1)
            with self.subTest(descriptor=descriptor), self.assertRaises(FormatError):
                parse_firmware(bytes(d))


if __name__ == "__main__":
    unittest.main()
