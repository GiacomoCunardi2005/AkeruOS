# Overview of findings

Firmware V1.1, CPU address space unless noted. Evidence levels: see
[README](README.md).

## 1. Firmware package and blocks

* The public update package (`firmware/firmware.bin`, 29,602,084 bytes) is
  a container. The block table that the boot code understands starts with
  the magic `RHIR` at package offset `0x480B8`. **static**
* The V1.1 table has 17 descriptors. Type 1 descriptors are code blocks
  copied to RAM by the boot stage (blocks 0, 1 and 8). Type 0 descriptors
  are resources. Block 16 is type 2 and carries the entry address used for
  the handoff. For type 1, one field packs
  `(size_in_sectors << 16) | start_sector`, with 512-byte sectors. **static**
* Integrity protection found in the analysed code: a 32-bit sum per block,
  sum/complement word pairs over the table, and an XOR word over the
  package. No cryptographic signature was identified in the analysed code
  paths. A rebuilt package with corrected sums was accepted by the
  camera's own update menu. **static + hardware**
* Load addresses of the main blocks: 0 at `0x000AD800` (MainCode),
  1 at `0x00360800`, 2 at `0x005FE800`, 3 at `0x00669800`,
  4 at `0x00796800`, 5 at `0x00897800`, 6 at `0x009A3800`,
  7 at `0x00C67800`, 8 at `0x00C8E800`, 9 at `0x00C8F800` (resources),
  10 at `0x00F20800`. Blocks 11-15 share `0x01044800` (overlays).
  Residency of blocks 0-10 was confirmed in a RAM dump. **hardware**

## 2. Boot chain

* NAND first stage (base candidate `0x0F800000`) loads the TBIB boot stage
  to `0x01000000`, verifies its checksum and jumps to it. **static/emulated**
* The DDR size ID configured by the first stage gives 256 MiB. This is a
  configured value, not a verified physical memory map. **static**
* The TBIB boot stage loads MainCode from NAND. Before that, under a guard,
  it can load a full image from the SD card (`B:\TBM_SK501.BIN`). Details
  and constraints are in [03-boot-sd-path.md](03-boot-sd-path.md). **static/emulated**

## 3. RAM dump obtained on hardware

* A test firmware hooked a boot-time signal, started a task and called
  Nikon's own diagnostic writer (`0x16ED40`) through a file handle held
  open by the task. On the camera it produced a 17,041,228-byte file, which
  is the RAM range `[0, 0x0104074C)`. **hardware**
* The dump is not atomic: it was taken while the system ran. It covers only
  about 6.4 % of the configured 256 MiB. **hardware**
* The task's stack use was 1,584 of 32,768 bytes, and the dump was written
  during the second write phase. A table of 111 runtime memory-region
  records at `0x3766F4` matches the software layout model. **hardware**

## 4. RTOS kernel (MQX-style)

* Kernel data `K = [0x369348]` (0x1800 in the dump), current task at
  `K+0x1C`, tick counter at `K+0x34`, timed list at `K+0x4C..0x54`, global
  task list at `K+0x46C`. Ready queues are at `0x27AC - 16*priority`.
  49 task control blocks are present, with names such as `WindowMgr`,
  `UITimer`, `CapMgrTask` and `LensCtrl`. **hardware (dump) + static**
* Context frames are 164 bytes:
  * the IRQ entry `0xB3054` saves r0-r12, lp, blink, status32, ilink,
    `aux_macmode`, r56, r57 and xmac0-2;
  * the voluntary switch `0xB2C74` saves r13-r25, gp and fp, but **not**
    the DSP accumulators;
  * the frame type can be recognised because the IRQ frame stores ilink
    twice and the voluntary frame stores blink twice.

  **static**

## 5. GUI and window manager

* Message ring: `post(arg,msg,param)` at `0x17BC7C`, 64 entries of
  12 bytes. The dispatcher `0x169E1C` calls the per-window procedure
  `0x169D78`, which has pre and post hooks and a jump table for messages
  `0x4401`-`0x4409`. **static + emulated**
* Window table at `0x366E94` (197 entries). Open by id with `0x1453E4`.
  The manager `0x145180` is the only writer of the current-window cell
  `0x366EA4`, and the open protocol sends `0x4403`, `0x4401`, `0x4405`. A
  custom window opened through the Nikon manager received keys from
  `WindowMgr`. **emulated**
* OSD plane: 8 bits per pixel, 640 bytes per row, at `0x0F688400`, with a
  second buffer at `0x0F610800`. Nikon's fill routine `0x17B104` and text
  service `0x186D08` can be reused. The display-layer registers written by
  `0x208C84` are `0x0FEE0184..0x0FEE01A0`. **static + emulated**
* A return to Live View after closing a custom window was not demonstrated.
  It needs scheduler and interrupt modelling, together with a repair of the
  non-atomic kernel lists of the dump. **emulated, open**

## 6. Keys

* Key controller registers are `0x0FE70224` and `0x0FE70228`, with a ready
  flag at `0x0FE7020C`. The snapshot is `(r224 << 10) | r228` and the keys
  are active low. The normalizer `0x16E6E0` samples bits
  {7, 8, 12, 13, 15, 16, 20, 21}, and a record table at `0x392F04` maps bits
  to logical keys. Events are `logical << 7` for a press and
  `(logical << 7) | 1` for a release. **static + emulated**
* The mapping to physical buttons is in [04-keys.md](04-keys.md).

## 7. Exposure, ISO, iris and flash

* The diagnostic ISO list has 24 positions: Exit, Auto, ISO 50 ... 3200.
  ISO and exposure-time setters, confirmation and restore paths, the entry
  of the exposure calculation, iris conversions and the flash setting were
  traced through the original code with synthetic inputs. **emulated**
* The real AE tables, optics and the full capture sequence were not
  reproduced. **open**

## 8. RAW and image paths

* Debug RAW frames written by the camera: 26,527,232 bytes, 16-bit
  little-endian 4208×3152 with values 0-4092. The accompanying CFA file has
  a 20,808-byte header (offset, width, height, RGGB declared) whose payload
  equals the first 13,263,616 bytes of the frame. **hardware files, offline
  analysis**
* A monochrome-from-RAW reference pipeline was prototyped offline. Black
  and white levels and the colour matrix were not calibrated. **offline**

## 9. DSP instructions

* `muldw`/`muludw` are used in about 1,580 places by compiled code. See
  [02-dsp-muldw.md](02-dsp-muldw.md).

## 10. Simulator work

* The patches in [arc700-gnu-simulator](https://github.com/GiacomoCunardi2005/arc700-gnu-simulator/tree/main/patches) cover:
  * an AUX register model and the DC_CTRL read;
  * a delay-slot correction;
  * a provisional DSP subset;
  * defined-memory tracking.
* Further laboratory engines (scheduler tick, kernel-list repair) remained
  local and experimental and are not published.
* Ghidra p-code models `mul*dw` as opaque `CALLOTHER` operations with no
  effect on r56/r57. The original GNU simulator does not decode these
  instructions. **static/emulated**
