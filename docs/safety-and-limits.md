# Safety, evidence and publication limits

AkeruOS is paused and has no supported installable firmware. A physical DSP
experiment left the research camera unable to boot; the cause was not conclusively
established. Read the [incident report](05-dsptest-incident.md).

## Evidence levels

- **Static:** derived from code or data, without observing execution.
- **Emulated:** instructions were executed in a model; peripherals, memory or
  inputs may be fixtures. This does not demonstrate real hardware behaviour.
- **Hardware:** an observation on a particular camera and setup, limited to
  what was actually measured. A successful dump does not establish a complete
  physical RAM map or a safe installation path.

Historical firmware candidates remain **NON_INSTALLARE**. Do not infer that a
blank region is free RAM, that configured DDR size proves the physical map, or
that an address applies to another firmware version. See [compatibility](compatibility.md).

## Materials and rights

The repository is intended to publish original research and source code with
applicable licences. It does not intentionally distribute Nikon firmware,
extracted firmware binaries, camera dumps, calibration data or photographs.
Some historical scripts depend on such inputs and may generate derived output;
those inputs and outputs are not included just because a script references them.
Some material and existing publications still require provenance and rights
review. Consult the applicable licence and the rights holder before redistributing
third-party files; no blanket legal clearance is implied.
