# Camera and firmware compatibility

| Target | Evidence | Status |
|---|---|---|
| Nikon COOLPIX S33, firmware V1.1 | Static analysis and emulation of V1.1; selected physical observations on the research camera | Research reference only; not an installable release |
| S33 with another firmware version | V1.1 addresses and layouts have not been established for it | Unverified |
| Other Nikon models or other brands | Similar appearance or CPU is not proof of compatible firmware or peripherals | Unverified |

Some historical notes discuss a camera identified as V1.0 alongside V1.1
firmware analysis. Check the version and evidence in each individual report;
do not assume that all observations used the same firmware version.

A CPU family or board marking alone does not prove the memory map, boot
process, button mapping, ABI or addresses. A different target needs its own
analysis. [Start here](getting-started.md) and keep a record of target model,
firmware version, input provenance, tools, evidence and unresolved questions.
See also [safety and limits](safety-and-limits.md).
