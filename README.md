# AkeruOS — Nikon COOLPIX S33 research

AkeruOS was an experiment to give the Nikon COOLPIX S33 (firmware V1.1,
ARCompact/ARC700 CPU) a minimal shooting-oriented user interface. It runs
inside the original firmware and uses Nikon's own window manager, text and
graphics services.

**Status: paused (November 2026).** This repository publishes the research
results and the original source code written during the project.

## Contents

| Path | What it is |
|---|---|
| [`docs/`](docs/README.md) | Research findings: firmware structure, boot chain, kernel, GUI, keys, DSP instructions, boot-stage SD loader, incident report |
| `ui/` | AkeruOS menu model (four flexible buttons), labels, mono scanline renderer |
| `camera/` | Colour/mono selection, Mono RAW row processing, iris action adapter |
| `nikon_v11_runtime.*` | Thin ABI wrappers around V1.1 services (task creation, delay, critical sections) |
| `nikon_v11_sd_*`, `nikon_v11_memdump_*`, `ram_dump*` | RAM-dump prototypes that write through Nikon's SD/diagnostic services. One variant produced a real RAM dump on the camera |
| `usb_ram*` | Prototype RAM transfer over the USB stack (offline only) |
| `tests/` | Host unit tests and fixtures |

## Building and testing

* Target code is built with an ARC GNU toolchain (`-mcpu=arc700`). See the
  `Makefile`.
* The `*-verify` Makefile targets call private verification scripts that
  need the Nikon firmware and camera dumps. Those scripts and inputs are not
  part of this repository.
* The host unit tests are plain C11, for example:

```sh
cc -std=c11 -Wall -Wextra -I. -Iui -Icamera \
   ui/menu.c ui/menu_labels.c ui/menu_color.c camera/color_mode.c \
   camera/iris_action.c camera/mono_raw.c tests/menu_test.c -o menu_test && ./menu_test
cc -std=c11 -Wall -Wextra -I. -Icamera camera/mono_raw.c tests/mono_raw_test.c -o mono_raw_test && ./mono_raw_test
```

The CPU simulator used for emulation is in the companion repository
[arc700-gnu-simulator](https://github.com/GiacomoCunardi2005/arc700-gnu-simulator).

## What is not here

* No Nikon firmware and no extracted or derived binaries.
* No disassembly listings or traces.
* No camera dumps, calibration data, photos or personal data.
* No builders that produce modified firmware images.
* No source for the DSP hardware test that made the test camera
  unbootable.

Details are in [`docs/README.md`](docs/README.md).

## Warning

The code that runs inside the camera firmware was written for one firmware
version (V1.1) and depends on hard-coded addresses of that version.
Installing modified firmware on a camera can leave it unbootable and may
void the warranty: see
[`docs/05-dsptest-incident.md`](docs/05-dsptest-incident.md). Nothing here
is certified on hardware unless the documentation says so explicitly.

Nikon, COOLPIX and EXPEED are trademarks of Nikon Corporation. This project
is not affiliated with or endorsed by Nikon.

## Licence

GPL-3.0-or-later. See [`LICENSE`](LICENSE).
