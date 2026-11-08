# Getting started

AkeruOS is a paused research project, not an installable firmware release.
The reference is the Nikon COOLPIX S33 firmware V1.1; see
[compatibility](compatibility.md) before applying any finding to another camera.
A hardware test left the research camera unbootable; see the
[incident report](05-dsptest-incident.md).

## Choose a starting point

1. Read the [research overview](01-overview.md) for the findings and their evidence.
2. Explore the [research index](research-index.md) by topic, or the original
   reports in [`MDs/`](../MDs/).
3. For code and available tests, see the [tool guide](tools-index.md).
4. For another camera, record model, hardware revision, firmware version and
   source, and distinguish observed facts from hypotheses. Do not transfer
   addresses or assume a similar model shares firmware or hardware.

## Test without a camera

The container parser has synthetic tests; from the repository root:

```sh
cd coolpix-s33-re
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

The root [README](../README.md#building-and-testing) also gives host C tests.
Neither kind of test demonstrates camera boot, screen output, or hardware safety.
The parser needs a separately obtained, legally usable firmware file for real
input; firmware and camera dumps are not supplied here.

For limits, missing evidence, and the distinction between static analysis,
emulation and physical observation, read [safety and limits](safety-and-limits.md).
