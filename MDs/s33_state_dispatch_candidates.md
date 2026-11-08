# S33 — CaptureImage state/dispatch candidates

Firmware V1.1 static analysis; camera observed V1.0.

Hash-verified 16 blocks; GNU ARC linear disassembly of blocks 0, 1, 2, 3.

## Results

- PC-relative state literal loads in scanned disassembly: **41**
- Proximate store candidates at offsets +0x1D or +0: **2**
- PC-relative 0x4405 literal loads in scanned disassembly: **1**
- The CaptureImage table raw bytes are saved in the JSON; they do not establish a dispatch algorithm.

## State pointer loads

| Site | Literal address | Value | Target register |
|---|---|---|---|
| `0x65ed4c` | `0x65ed64` | `0x68200d` | `r0` |
| `0x65ed8a` | `0x65f0ec` | `0x681ff0` | `r14` |
| `0x65f4c4` | `0x65f5fc` | `0x681ff0` | `r0` |
| `0x65f542` | `0x65f5fc` | `0x681ff0` | `r0` |
| `0x65f5c4` | `0x65f5fc` | `0x681ff0` | `r0` |
| `0x65f64e` | `0x65f5fc` | `0x681ff0` | `r13` |
| `0x65fe58` | `0x65fe74` | `0x681ff0` | `r0` |
| `0x65fe68` | `0x65fe74` | `0x681ff0` | `r0` |
| `0x65ff76` | `0x65fe74` | `0x681ff0` | `r14` |
| `0x6602c8` | `0x66043c` | `0x681ff0` | `r14` |
| `0x660514` | `0x6608a8` | `0x681ff0` | `r0` |
| `0x660772` | `0x6608a8` | `0x681ff0` | `r0` |
| `0x66092e` | `0x6609a4` | `0x681ff0` | `r0` |
| `0x66095e` | `0x6609a4` | `0x681ff0` | `r0` |
| `0x660af2` | `0x660bec` | `0x681ff0` | `r0` |
| `0x660b2c` | `0x660bec` | `0x681ff0` | `r2` |
| `0x660b68` | `0x660bec` | `0x681ff0` | `r0` |
| `0x660ba0` | `0x660bec` | `0x681ff0` | `r0` |
| `0x660cb6` | `0x660ec4` | `0x681ff0` | `r0` |
| `0x660cc4` | `0x660ec4` | `0x681ff0` | `r0` |
| `0x660e9c` | `0x660ec4` | `0x681ff0` | `r0` |
| `0x660f02` | `0x660ec4` | `0x681ff0` | `r13` |
| `0x660f54` | `0x660f80` | `0x68200d` | `r0` |
| `0x661608` | `0x661644` | `0x681ff0` | `r1` |
| `0x66162a` | `0x661644` | `0x681ff0` | `r1` |
| `0x661652` | `0x661644` | `0x681ff0` | `r13` |
| `0x66170e` | `0x661770` | `0x681ff0` | `r0` |
| `0x66175a` | `0x661770` | `0x681ff0` | `r0` |
| `0x661cf4` | `0x662008` | `0x681ff0` | `r13` |
| `0x662414` | `0x66254c` | `0x681ff0` | `r0` |
| `0x662516` | `0x66254c` | `0x681ff0` | `r1` |
| `0x662574` | `0x66254c` | `0x681ff0` | `r15` |
| `0x6626c0` | `0x662934` | `0x681ff0` | `r0` |
| `0x662734` | `0x662934` | `0x681ff0` | `r0` |
| `0x662816` | `0x662934` | `0x681ff0` | `r0` |
| `0x662828` | `0x662934` | `0x681ff0` | `r0` |
| `0x662970` | `0x662be8` | `0x681ff0` | `r0` |
| `0x6629e6` | `0x662be8` | `0x681ff0` | `r0` |
| `0x662acc` | `0x662be8` | `0x681ff0` | `r0` |
| `0x662adc` | `0x662be8` | `0x681ff0` | `r0` |
| `0x662c02` | `0x662be8` | `0x681ff0` | `r14` |

## Candidate stores (not proven register data flow)

| Load site | Store site | Store instruction |
|---|---|---|
| `0x65ed4c` | `0x65ed4e` | `65ed4e:	a840                	stb_s	r2,[r0,0]` |
| `0x660f54` | `0x660f98` | `660f98:	a8e0                	stb_s	r15,[r0,0]` |

## Literal references to service ID 0x4405

The following are PC-relative references in the scanned blocks, not a recovered dispatcher.

- block 0 at `0x14530e` loads `0x145378`

## Limitations

- All raw ID occurrences and PC literal loads are candidates, not proven code xrefs.
- A load-to-store proximity check does not track register clobbering or aliasing.
- ARC objdump is linear and can disassemble data as code. Review CFG manually.
- No firmware or camera commands were executed or modified.

Next: inspect store candidate windows, separate tables from executable code, and only then attempt control/data-flow links to the physical shutter S2.

