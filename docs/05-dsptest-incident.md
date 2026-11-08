# Incident: a DSP hardware test left the camera unbootable

Date: 8 November 2026. Published so that others do not repeat the same
mistakes.

## Goal of the test

Measure `muldw`/`muludw`/`macdw`/`macudw` on the real CPU to confirm the
semantics inferred in [02-dsp-muldw.md](02-dsp-muldw.md). The emulator and
the static analysis could not reach that certainty.

## What the test firmware did

* It reused the RAM-dump firmware path that had already worked on the same
  camera: a boot-signal hook, then a task, then Nikon's diagnostic writer
  through a held file handle.
* The only change was the task. Before dumping RAM, it ran 608 DSP
  operations and recorded their inputs, r56 and r57 in a table on its own
  stack. The operations covered:
  * edge values, including negative and ±32768 operands;
  * `aux_macmode` 0 and 8;
  * random pairs;
  * accumulate sequences, including `macdw`.
* It passed offline checks: build with checksums, full emulated run in a
  p-code/FAT model (with a declared DSP model, because Ghidra treats these
  instructions as opaque), and regression of the earlier dump path.

The source of this test payload is **not published**.

## What happened (hardware)

* The update completed. The first boot reached Live View and froze after a
  few seconds.
* Every later power-on showed only the power lamp for a few seconds, then
  nothing: no screen, no lens extension, no USB enumeration.
* No result file was written. The task crashed or hung **before** creating
  its output file, which means during the DSP probe.

## Probable causes (not proven)

1. **An unsupported instruction.** The firmware never uses `macdw`
   (accumulate, signed); it uses only `macudw`. If this CPU's DSP option
   lacks `macdw`, its first execution raises an instruction-error exception.
   The probe runs at every boot, before any SD check, so the camera stops at
   every boot.
2. **A corrupted firmware file on the SD card.** The kernel log of the PC
   shows that the card reader was unplugged 19 seconds after the copy, with
   a lost asynchronous write. The hash check after copying had read the
   page cache, not the card.

The two causes cannot be told apart from outside.

## Recovery attempts

* The official recovery path needs the camera's own menu, which is
  unreachable.
* The boot-stage SD loader ([03-boot-sd-path.md](03-boot-sd-path.md)) was
  tried three times with cards meeting all the FAT constraints found in the
  code. It never started.
* Remaining options: Nikon service, a replacement main board (sold as a
  spare part, or taken from a donor camera), or hardware access (UART/JTAG)
  that has not been mapped.

## Lessons

1. A hardware probe must use **only instructions and encodings that the
   original firmware already executes** on that CPU.
2. Risky code must **not run unconditionally at every boot**. It should be
   gated behind a trigger file on the SD card, checked first, so that
   removing the card restores a bootable camera.
3. After writing a firmware file to a card, verify it with an **uncached
   read** (for example `dd iflag=direct | sha256sum`) and **unmount the
   card cleanly** before removing it.
4. Passing tests in emulation (with a modelled instruction) does not show
   that the instruction exists on the real CPU.
