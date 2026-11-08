import tempfile
import unittest
from pathlib import Path
from s33_check_memdump_regions import check


class RegionCheck(unittest.TestCase):
    def test_success_missing_short_extra_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            regions = [{'address': 0x4000, 'length': 512}, {'address': 0x8000, 'length': 768}]
            first = directory / '00004000.BIN'; second = directory / '00008000.bin'
            first.write_bytes(bytes(768)); second.write_bytes(bytes(1024))
            self.assertEqual(check(directory, regions)['status'], 'FILES_MATCH_DECLARED_MAP_ONLY')
            second.write_bytes(bytes(1023))
            self.assertEqual(check(directory, regions)['files'][1]['status'], 'size_mismatch')
            second.unlink()
            self.assertEqual(check(directory, regions)['files'][1]['status'], 'missing')
            second.symlink_to(first)
            self.assertEqual(check(directory, regions)['files'][1]['status'], 'not_regular')
            second.unlink(); second.write_bytes(bytes(1024))
            (directory / '00010000.BIN').write_bytes(b'x')
            self.assertEqual(check(directory, regions)['unexpected'], ['00010000.BIN'])

    def test_invalid_maps_and_duplicate_names(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for regions in ([], [{'address': 0, 'length': 0}],
                            [{'address': 0, 'length': 2}, {'address': 1, 'length': 2}],
                            [{'address': 0x0fdfffff, 'length': 2}],
                            [{'address': True, 'length': 2}]):
                with self.assertRaises(ValueError): check(directory, regions)
            (directory / '0000ABCD.BIN').touch(); (directory / '0000abcd.bin').touch()
            with self.assertRaises(ValueError): check(directory, [{'address': 0xabcd, 'length': 1}])


if __name__ == '__main__':
    unittest.main()
