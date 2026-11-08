# Nikon COOLPIX S33 V1.1 firmware map

This is a navigation map of the **studied S33 firmware V1.1**, not an ARC700
memory map or a compatibility list for other cameras. Addresses are CPU-space
addresses unless explicitly described as a package offset, event code or MMIO
register. They are entry points or observed data sites, not proven boundaries
of entire subsystems. Hexadecimal addresses in older notes refer to V1.1 even
when the camera used for some observations was identified as V1.0.

**Evidence:** S = static analysis; E = CPU emulation with fixtures or modelled
peripherals; H = observation on the research camera. H applies only to the
particular observation, not to all entries nearby. A marker or name is a clue,
not proof that a complete physical feature works. Historical reports may link
to unpublished firmware, dumps and laboratory outputs.

## Startup, memory and kernel

| Area | Location | What was observed | Evidence and source |
|---|---|---|---|
| Firmware container | Package offset `0x480B8` | `RHIR` block table; this is a file offset, not a CPU address. | S: [overview](01-overview.md#1-firmware-package-and-blocks) |
| Early boot | `0x0F800000` candidate base; TBIB loaded at `0x01000000` | First-stage and boot-stage load path; first-stage base is a candidate. | S/E: [boot overview](01-overview.md#2-boot-chain) |
| Boot-stage SD path | `B:\TBM_SK501.BIN` | Conditional loader path, with guards and filesystem constraints; not a proven recovery procedure. | S/E: [boot-stage SD path](03-boot-sd-path.md) |
| Main firmware block | `0x000AD800` | Candidate load base of MainCode block 0; other blocks and overlays have separate addresses. | S/H: [block map](01-overview.md#1-firmware-package-and-blocks) |
| Kernel context | `[0x369348]`; current task at `K+0x1C` | Kernel pointer and task-context fields in the analysed model/dump. | S/H: [kernel overview](01-overview.md#4-rtos-kernel-mqx-style) |
| Task switching | `0x0B3054`, `0x0B2C74` | IRQ entry and voluntary switch, respectively; they save different register sets. | S: [kernel overview](01-overview.md#4-rtos-kernel-mqx-style) |
| Diagnostic memory writer | `0x16ED40` | Diagnostic writer used by one RAM-dump experiment; a partial, non-atomic dump was observed on hardware. | H for that dump: [report](../MDs/S33_MEMDUMP_Primo_Dump_Hardware_20261106.md) |

## Shooting, autofocus and flash

| Area | Location | What was observed | Evidence and source |
|---|---|---|---|
| Shutter / capture UI | Event table `0x7833EC`; handler `0x654FE8` | CaptureLiveview event table and S1-associated handler. Physical half-press attribution remains inferred. | S: [two-stage shutter](../MDs/S33_Shutter_Due_Stadi_S1_S2.md) |
| Autofocus clues | Around `0x0DB470`; marker literals at `0x0DB4D8`, `0x0DB4E0` | Sites contain `AF start` and `AF lock` marker values. These are **literal sites**, not proven entry points for an autofocus algorithm. The path to the optics is unresolved. | S: [S1 / AE / AF markers](../MDs/S33_Shutter_Due_Stadi_S1_S2.md) |
| Optical module protocol | BCIP operation codes `0x9205`, `0x9206`, `0x9207` | Table describes focus move, status and reset commands. These are protocol operation codes, not firmware addresses; their runtime path and AF algorithm are not established here. | S: [optical command report and correction](../MDs/S33_Obiettivo_Zoom_MCU_Interface_e_BCIP.md) |
| Flash setting | `0x0DE3A4`, `0x0DE3E4` | Setter/application and getter were exercised with synthetic menu contexts; later propagation, persistence and flash firing were not proved. | E: [flash selection test](../MDs/S33_GUI_Flash_Applicazione_Oggetto_CPU_20261031.md) |
| Flash / strobe task | `0x165C84`; service `0x165640` | Strobe task record and a firing-service entry identified statically; the firing-service body is not reconstructed. | S: [flash and strobe](../MDs/S33_Flash_Strobe_Task_e_Controllo.md) |
| Strobe MMIO | `0x0FED18A0`, `0x0FED18AC`, `0x0FED18B0` | Accesses attributed to strobe code; physical meaning of the bits is not fully established. | S: [flash and strobe](../MDs/S33_Flash_Strobe_Task_e_Controllo.md) |
| Exposure / ISO / iris | See linked analyses | Menu selections and parts of exposure and iris paths were exercised with synthetic inputs; full AE, optics and capture are open. | E: [overview](01-overview.md#7-exposure-iso-iris-and-flash), [iris calculation](../MDs/S33_GUI_Iride_Calcolo_Esposizione_CPU_20261031.md) |
| JPEG worker | `0x15A764`; callback cell `0x367384` | JPEG-related task and shared callback mechanism; completion notification is distinct from success. It is not a complete shoot-and-save function. | S: [JPEG request and result](../MDs/S33_JPEG_Richiesta_e_Risultato.md) |
| RAW / image data | See linked analyses | RAW dimensions and files observed from the research camera; the complete image-processing and capture paths remain open. | H / offline: [RAW overview](01-overview.md#8-raw-and-image-paths) |

## User interface, storage and USB

| Area | Location | What was observed | Evidence and source |
|---|---|---|---|
| Window manager | `0x145180`, `0x1453E4`, table `0x366E94` | Manager, window opening and window table. Custom-window execution was demonstrated in an emulator. | S/E: [GUI overview](01-overview.md#5-gui-and-window-manager) |
| UI messages | `0x17BC7C`, `0x169E1C` | Message posting and dispatch path. | S/E: [GUI overview](01-overview.md#5-gui-and-window-manager) |
| Display / OSD | `0x0F688400`, `0x0F610800`; fill routine `0x17B104` | Two modelled buffer addresses and fill routine; physical display refresh is not established by emulation. | S/E: [GUI overview](01-overview.md#5-gui-and-window-manager) |
| Buttons | `0x16E6E0`; MMIO `0x0FE70224`, `0x0FE70228` | Key snapshot normalizer and logical events. The physical-button mapping remains incomplete. | S/E: [keys](04-keys.md) |
| SD and filesystem | `0x2A0890`, `0x2A0534`; backend `0x1684B4` | Write wrapper, raw-file layer and SD backend entry. Counts, error flags and persistence are distinct. | S: [SD device and completion](../MDs/S33_Dispositivo_SD_e_Completamento.md) |
| USB | `0x279488`, `0x2DBCF8` | Endpoint lookup and controller configuration boundaries studied with fixtures; not a complete physical USB map. | E with fixtures: [USB endpoint and allocation](../MDs/S33_AkeruUSB_Apertura_Endpoint_e_Allocazioni_20261026.md) |
| NAND / firmware update | See [NAND write map](../MDs/NAND_WRITE_MAP.md) | Storage flash and firmware update are separate from the photographic strobe. Existing analysis does not establish a safe write or recovery procedure. | S: [NAND write map](../MDs/NAND_WRITE_MAP.md) |

## Open boundaries

The map is deliberately incomplete: AF-to-optics and shutter execution, the
complete flash sequence, a verified physical RAM map, device-specific MMIO,
and end-to-end capture and recovery remain open. ARC instructions and CPU
semantics must be distinguished from Nikon-specific software and peripherals.
See the [research index](research-index.md), [compatibility](compatibility.md),
and [safety and evidence limits](safety-and-limits.md).
