# The `muldw` / `muludw` / `mulrdw` DSP multiply family

ARC700 DSP option instructions used by the S33 firmware. All results here are
**static** (code reading and compiler-usage inference) unless marked.
No hardware measurement of these instructions was obtained (see
[05-dsptest-incident.md](05-dsptest-incident.md)).

## Encoding

* Major opcode 5, 32-bit register form; sub-opcode in bits 21-16:
  `muldw` 0x0C (signed), `muludw` 0x0D (unsigned), `mulrdw` 0x0E (rounding).
* Form used by the firmware: `mul?dw 0,b,c`. The destination field is 62,
  so the result is discarded, and there is no `.f`. Results are read from
  the accumulators **r56/r57**.
* Example word: `muludw 0,r0,r1` = `0x280D007E`
  (halfwords stored high first in little-endian).
* GNU binutils (`arc-tbl.h`) knows the mnemonics; the historical GNU
  simulator enumerates them but has no semantics for them.

## Usage census (block 0, MainCode)

A site counts as real when its destination is 0 and r56/r57 is read within
three instructions. The disassembly is linear, so a few sites may be
misclassified.

| | decoded | real | read r57 only | read r56+r57 |
|---|---|---|---|---|
| `muldw` | 280 | 234 | 234 | 0 |
| `muludw` | 1456 | 1343 | 1214 | 129 |
| `mulrdw` | 4 | 0 | – | – |

`macudw` (accumulate, unsigned) follows a seed `muludw` in 52 real sites.
`macdw` (accumulate, signed) has **no** real use.

## Inferred semantics (MACMODE = 0)

* Operand preparation follows the type of the product:
  * `muludw` operands come from zero-extending loads or ops (`ldb`, `ldh`,
    `extw`): 1052 of 1053 cases;
  * `muldw` operands come from sign extension (`sexw`, `ldh.x`, `ldw.x`)
    in 139 cases, and from small unsigned values in 79 cases.
* The compiler therefore uses them as 16×16→32 products:

```text
muldw  0,b,c : r57 = (int16)b[15:0]  * (int16)c[15:0]   (32-bit result)
               r56 = (int16)b[31:16] * (int16)c[31:16]  (never read after muldw)
muludw 0,b,c : r57 = b[15:0]  * c[15:0]
               r56 = b[31:16] * c[31:16]
macudw 0,b,c : r57 += b[15:0] * c[15:0]   (lane-wise accumulate)
```

* The 32×32 multiply helper at `0x3342A8` (and its inline copies, 129 sites)
  does the following:
  1. writes 0 to `aux_macmode`;
  2. rotates the second operand by 16 and executes `muludw`;
  3. adds r56 and r57;
  4. executes `muludw` again and adds the first sum shifted left by 16.

  This yields `a*b mod 2^32` **only** if r56 is the high-lane product and
  r57 the low-lane product, with no saturation. A conventional "high/low
  word of a 32×32 product" in r56/r57 would give a wrong result (for
  example 1 × 0x10000 → 0x20000).
* Idioms seen in the code: sums of squares, byte blending
  `(0xFF-p)*q+16 >> 5`, scaling loops storing `r57` as 16 bit, and a
  resampler accumulating byte × Q15 weights with `macudw`, then `asr r57,15`.

Confidence: high for the MACMODE-0 behaviour used by this firmware. It is
not proven on hardware. The r56 lane of `muldw`, rounding and saturation
are not established.

## `aux_macmode` (AUX 0x41)

* The code writes 0 before DSP use 1207 times.
* The IRQ entry and the task switch save and restore macmode, r56, r57 and
  xmac0-2, so the accumulators are per-context state.
* Bit 3 is set (`or 0x8`) only in the resampler around `0x272E70..0x273D68`
  (7 sites) and is not cleared there. Its meaning (saturation?) is unknown.

## Limits of the experimental simulator patch

[`s33-dsp-v7-experimental.patch`](https://github.com/GiacomoCunardi2005/arc700-gnu-simulator/blob/main/patches/s33-dsp-v7-experimental.patch) in the
[arc700-gnu-simulator](https://github.com/GiacomoCunardi2005/arc700-gnu-simulator) repository is a deliberately restricted model:

* `muldw` accepts only operands 0..0x7FFF, or one zero operand. Negative,
  sign-extended operands, which are common, stop the simulator with
  `S33_DSP_GUARD`.
* It handles only the register-register form: 6 `muldw` sites with a limm
  or a register ≥ 32, and 12 `muludw` sites in u6 form, are not decoded.
* It has no `macudw`/`macdw` and does not support MACMODE ≠ 0, so the
  resampler is rejected.

Extending it to the inferred semantics above is possible, but it is an
inference until a hardware measurement exists.
