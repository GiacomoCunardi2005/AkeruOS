#!/usr/bin/env python3
"""Check compiled marker identity against original Nikon read-open/close paths."""
from s33_verify_ram_dump_sd_io_port import main

if __name__ == '__main__':
    main(marker=True)
