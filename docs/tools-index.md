# Code and tools

| Location | Purpose | Inputs and limitations |
|---|---|---|
| [`ui/`](../ui/), [`camera/`](../camera/), [`tests/`](../tests/) | Menu model, camera-facing prototypes and host tests | Host tests use fixtures and do not prove camera behaviour; build commands are in the [root README](../README.md#building-and-testing). |
| [`coolpix-s33-re/`](../coolpix-s33-re/) | Firmware container parser and synthetic tests | Synthetic tests need Python only; parsing real firmware requires a separately obtained input. Own [MIT licence](../coolpix-s33-re/LICENSE). |
| [`Python_Trace_Scripts/`](../Python_Trace_Scripts/) | Historical analysis, emulation and verification scripts | Many expect proprietary inputs, separately installed tools or the original workspace layout; some generate output or modified files. Read a script and its dependencies before running it. |
| [`S33-sections/analysis_codex/`](../S33-sections/analysis_codex/) | Published static-analysis helper | Depends on local inputs and additional tools. |
| [ARC700 simulator repository](https://github.com/GiacomoCunardi2005/arc700-gnu-simulator) | Separate experimental CPU simulator | Its documented CPU and peripheral limitations apply; not a camera emulator. |

Historical `Makefile` verification targets refer to `../Python_Trace_Scripts/`
and many scripts expect a larger workspace containing an `AkeruOS/` directory,
firmware, dumps or tool builds. They are not guaranteed to work in a standalone
clone. Use the host and synthetic tests in [getting started](getting-started.md)
without assuming that other targets are ready to run.
