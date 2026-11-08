# Nikon COOLPIX S33 research notes

Findings from an independent interoperability study of the Nikon COOLPIX
S33 (firmware V1.1, ARCompact/ARC700 CPU, board code `SK501`). The study
was carried out with the GNU ARC700 simulator ([arc700-gnu-simulator](https://github.com/GiacomoCunardi2005/arc700-gnu-simulator)),
Ghidra and static analysis, and a small number of tests on one camera
owned by the author.

The project is paused. These notes publish the results; they are not a
how-to for modifying cameras.

Start with [getting started](getting-started.md), [compatibility](compatibility.md),
the [research index](research-index.md), the [tool guide](tools-index.md),
and [safety and limits](safety-and-limits.md).

| Document | Content |
|---|---|
| [01-overview.md](01-overview.md) | Summary of all research areas: firmware container, boot chain, memory, kernel, GUI, keys, exposure, RAW, emulator |
| [02-dsp-muldw.md](02-dsp-muldw.md) | The `muldw`/`muludw`/`mulrdw` DSP multiply family: usage census, inferred semantics, emulator limits |
| [03-boot-sd-path.md](03-boot-sd-path.md) | Boot-stage SD loader (`TBM_SK501.BIN`), its guard and FAT constraints |
| [04-keys.md](04-keys.md) | Physical buttons vs. key-controller bits, logical keys and factory key test |
| [05-dsptest-incident.md](05-dsptest-incident.md) | A hardware test that left the camera unbootable: what happened and lessons |

## Evidence levels

Every statement is tagged with how it was established:

* **static**: read from the firmware code or data, not executed;
* **emulated**: original instructions executed in the GNU simulator or the
  Ghidra p-code emulator, with modelled peripherals and synthetic inputs;
* **hardware**: observed on the physical camera.

Emulated results depend on the models of memory and peripherals used and do
not prove hardware behaviour.

## What is not published, and why

* No Nikon firmware, no extracted blocks (TBIB, MainCode, resources), no
  firmware-derived ELF/binaries, no disassembly listings, traces or byte
  dumps: they are Nikon's copyrighted material.
* No RAM or NAND dumps, calibration data, photos or other personal data
  from the camera used in the study.
* No modified firmware images. The C sources of the RAM-dump prototypes and
  historical scripts are included as research material; some scripts write
  generated files. The source of the DSP test payload, which made the test
  camera unbootable, is excluded
  ([05-dsptest-incident.md](05-dsptest-incident.md)).
* Many historical verification scripts are included but depend on inputs
  and tooling not supplied here. See the [tool guide](tools-index.md).

Addresses (for example `0x16E6E0`) refer to the CPU address space of the
original V1.1 firmware and are given only to make the findings checkable by
someone who owns that firmware. They must not be transferred to other
firmware versions without verification.

## Warning

Installing unofficial firmware on a camera can make it unbootable and may
void the warranty. Nothing here has been certified on hardware unless
explicitly marked **hardware**. Nikon, COOLPIX and EXPEED are trademarks of
Nikon Corporation; this work is not affiliated with or endorsed by Nikon.

Licence of these notes: GPL-3.0-or-later, like the other original
sources and documentation in this repository (see `../LICENSE`).
