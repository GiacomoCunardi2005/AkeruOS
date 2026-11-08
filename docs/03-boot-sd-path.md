# Boot-stage SD loader (`TBM_SK501.BIN`)

The TBIB boot stage (code at `0x01000000`) can load the camera image from the
SD card **before** loading MainCode from NAND. `SK501` is the main board code
printed on the S33 board label, so this looks like a factory/service path for
this board. It is not documented publicly. It was **never made to work on
hardware** in this study. Unless marked otherwise, everything below is
**static** or **emulated**.

## Source selection (BootTask)

The volume `B:` is the SD card in the TBIB device table (`DEVSD:`/`PMSD:`).
`A:` is NAND.

1. **Early attempt** of `B:\TBM_SK501.BIN`: runs only if flag byte
   `0x01041104` is set and guard `0x01000488` returns non-zero.
2. **Sector loader** from NAND, the normal case.
3. **Fallback** `A:\TBM_SK501.BIN`: runs only if the sector loader failed.
4. **Fallback** `B:\TBM_SK501.BIN`: runs if (3) failed and flag
   `0x01041105` is set.

A camera whose NAND image is valid but misbehaves, for example the one in
[05-dsptest-incident.md](05-dsptest-incident.md), takes path 2. Only path 1
can bypass it.

## The early-attempt guard

During TBIB initialisation, the code reads a key-state word with the getter
at `0x01005A2C`, which returns a RAM word filled by a debounced key scan. It
stores the complement and tests **bit 15**. When that bit is set, it sets
`0x01041104 = 1` (early attempt enabled).

* The key scan reads `(0x0FE70224 << 10) | 0x0FE70228`, the key controller
  (see [04-keys.md](04-keys.md)). The keys are active low.
* Bit 15 of the snapshot is logical key 10, `KeyRight`: the right side of
  the multi selector.
* The key-state word is committed only after the value is stable over
  several scans. If no scan has completed when the decision runs, the word
  is still 0, and `NOT 0` has bit 15 set. In that case the early attempt
  would run regardless of keys. Whether a scan completes before the decision
  on real hardware is not known.

## File format expected

* The file must start with `RHIR`. The reader checks a 16-byte header, then
  walks the descriptors: it copies type 1 blocks with their checksum and
  publishes the type 2 entry.
* The public update package is rejected (status 11), because there `RHIR`
  starts at offset `0x480B8`. A valid file is the V1.1 package from that
  offset onward. Type 1 blocks 0, 1 and 8 all lie within the first
  ~9.2 MB.

Status codes of the reader (emulated with I/O fixtures): 8 mount failed,
9 open failed, 10 short header or descriptor, 11 wrong magic,
13 checksum or short payload.

## FAT driver constraints of the boot stage

The boot stage has its own small FAT driver, separate from MainCode.

* **MBR:** the first partition must have flag `0x00` or `0x80`, type
  1/4/6/0x0B/0x0C/0x0E, and a non-zero size.
* **Boot sector:** signature `55AA`, jump byte `0xEB` or `0xE9`,
  **512 bytes per sector**, **1-16 sectors per cluster** (≤ 8 KiB
  clusters), media `0xF8` (`0xF0` is checked on an alternative path).
* **FAT type** by cluster count: < 4085 FAT12, < 65525 FAT16, otherwise
  FAT32. **There is no exFAT support**, so SDXC cards in their default
  exFAT format cannot be read.
* **Names:** the directory scan builds 8.3 names and skips LFN entries in
  that loop. A non-8.3 name (`TBM_SK501` has 9 characters) is sent to a
  long-name branch (`0x01038CF0`, maximum path 260), so long names appear to
  be supported. This was not executed end to end.

## Hardware attempts (all unsuccessful)

**hardware**: three attempts, holding the multi-selector right button at
power-on:

1. 128 GB exFAT card: could not work, because exFAT is not supported.
2. The same card reformatted FAT32 with 8 KiB clusters.
3. An 8 GB SDHC FAT32 card.

In all three, the power lamp lit for a few seconds and then went off. The
lens did not extend and the USB port did not enumerate.

Unknowns that cannot be resolved offline:

* SD controller initialisation by the boot-stage driver;
* the timing of the key scan relative to the decision;
* the handoff to the loaded image.
