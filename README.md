# AkeruOS — Nikon COOLPIX S33 research

AkeruOS was an experiment to give the Nikon COOLPIX S33 (firmware V1.1,
ARCompact/ARC700 CPU) a minimal shooting-oriented user interface. Its
prototypes were designed to use the original firmware's window manager, text
and graphics services; they are not an installable release.

**Status: paused (November 2026).** This repository publishes the research
results and the original source code written during the project.

**New here?** Begin with [getting started](docs/getting-started.md), check
[camera compatibility](docs/compatibility.md), then browse the
[research](docs/research-index.md) and [tools](docs/tools-index.md) indexes.
A [firmware map](docs/firmware-map.md) identifies known boot, autofocus,
flash, image and other research locations, with their evidence and limits.
A hardware test left the research camera unbootable; read the
[incident report](docs/05-dsptest-incident.md) before considering hardware work.

## Contents

| Path | What it is |
|---|---|
| [`docs/`](docs/README.md) | Research findings: firmware structure, boot chain, kernel, GUI, keys, DSP instructions, boot-stage SD loader, incident report |
| [`references/`](references/README.md) | Reference documents, source links and third-party licences |
| [`MDs/`](MDs/) | Original research reports, kept under their workspace paths; this collection is incomplete |
| [`Python_Trace_Scripts/`](Python_Trace_Scripts/) | Original analysis and verification scripts; some dependencies and inputs are not included |
| [`coolpix-s33-re/`](coolpix-s33-re/) | Firmware container parser and synthetic tests, with their original MIT licence |
| [`ui/`](ui/) | AkeruOS menu model (four flexible buttons), labels, mono scanline renderer |
| [`camera/`](camera/) | Colour/mono selection, Mono RAW row processing, iris action adapter |
| [`tests/`](tests/) | Host unit tests and fixtures |
| [`S33-sections/analysis_codex/static_common.py`](S33-sections/analysis_codex/static_common.py) | Static-analysis helper; its firmware inputs and other dependencies are not all included |
| [`nikon_v11_runtime.c`](nikon_v11_runtime.c), [`nikon_v11_runtime.h`](nikon_v11_runtime.h) | Thin ABI wrappers around V1.1 services (task creation, delay, critical sections) |
| [`ram_dump.c`](ram_dump.c), [`nikon_v11_sd_io.c`](nikon_v11_sd_io.c), [`nikon_v11_memdump_worker.c`](nikon_v11_memdump_worker.c) | Examples of RAM-dump and SD prototypes; related source files are also in the repository root |
| [`usb_ram.c`](usb_ram.c), [`usb_ram_transport.c`](usb_ram_transport.c) | Prototype RAM transfer over the USB stack (offline only) |

The source files listed after the directories live directly in the repository
root; they are not names of additional folders. Some older reports describe
the original laboratory workspace and contain links to files that were not
published. See [the tool guide](docs/tools-index.md) for missing dependencies.

## Building and testing

* Target code is built with an ARC GNU toolchain (`-mcpu=arc700`). See the
  `Makefile`.
* Some `*-verify` targets depend on scripts or inputs that are not included.
  Many research scripts require Nikon firmware, camera dumps or local tools;
  they are preserved for reference and are not necessarily runnable here.
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
* No source for the DSP hardware test that made the test camera
  unbootable.

Original reports may refer to local paths or other reports and evidence that
are not included here. Their presence in a reference does not mean those
files are published. Further workspace material remains to be reviewed.

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
The files in `coolpix-s33-re/` retain their own [MIT licence](coolpix-s33-re/LICENSE).
Third-party material in `references/` retains its original terms; see
[`references/README.md`](references/README.md).
