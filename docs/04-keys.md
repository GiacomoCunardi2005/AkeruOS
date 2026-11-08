# Buttons, key-controller bits and logical keys

Combines the official S33 user's manual (button names and functions) with
three firmware tables. Unless marked otherwise, the results are **static**.

## Physical controls (S33 user's manual, "Parts of the Camera")

* **Top:** shutter-release button (half press and full press), power
  switch with lamp, ● movie-record button.
* **Back:** four "flexible buttons" in the left column (their function
  follows the on-screen icons), a round **multi selector** and the
  ▶ shooting/playback button.
* **Multi selector use:** ▲ zooms in (+) and ▼ zooms out (−) when
  shooting; ◀ shows the previous image and ▶ the next image in playback.
  It has no centre button.
* The S33 has **no** physical OK, Menu, Delete, Mode or separate zoom
  buttons. Those names exist in the firmware because it shares a base with
  other COOLPIX models.

## Key controller

* Snapshot = `(read16(0x0FE70224) << 10) | read16(0x0FE70228)`. The bits are
  active low (idle `0xFFFF`), and the ready flag is at `0x0FE7020C`.
* The record table at `0x392F04` has 16 records of 20 bytes. Each record
  holds a bit mask and the word `(logical_key << 8) | bit_position`.
* Events are `logical << 7` for a press and `(logical << 7) | 1` for a
  release.

| Physical control | Snapshot bit | Logical key / firmware name | Confidence |
|---|---|---|---|
| Flexible buttons 1-4 | 12, 7, 8, 13 | 11, 14, 67, 78 (the four GUI slots) | high as a group; top-to-bottom order not verified |
| Multi selector ▲ (zoom +) | 20 | 7 `KeyUp` | high |
| Multi selector ▼ (zoom −) | 16 | 8 `KeyDown` | high |
| Multi selector ◀ (previous) | 21 | 9 `KeyLeft` | high |
| Multi selector ▶ (next) | **15** | **10 `KeyRight`** | high |
| Shutter half/full, movie, playback, power | other bits (3, 30, 31 and the second register half) | 3, 98, 99-102, 106, 118 | not individually mapped |

Bits 12 and 13 are each the OR of two sources: `0x0FE70224` bit 2 or 3, and
`0x0FE70228` bit 12 or 13. **emulated**

## Factory key test

* The firmware contains a key test screen (`"%s series Key Test"`) with
  labels OK, UP, DOWN, LEFT, RIGHT, MODE, REVIEW, MENU, DELETE, TELE, WIDE,
  S1, S2, Video and MB1-MB4.
* Its init routine (around `0x2CFE22`) hides the OK, MODE, MENU, DELETE,
  TELE and WIDE widgets. What remains, UP, DOWN, LEFT, RIGHT, REVIEW, S1,
  S2, Video and MB1-MB4, is exactly the S33's physical button set.
* So, in Nikon's own S33 test screen, RIGHT is a real physical key: the
  right side of the multi selector. The flexible buttons are MB1-MB4.
* The link from each label to its bit through the window's event handlers
  was not traced. The label/value widget pairing was read from the widget
  ID scheme, not executed.

## Diagnostic command names

The diagnostic script command table (`0x9A0D20`, 234 records) contains,
among others: `KeyUp` (event 0x380), `KeyDown` (0x400), `KeyLeft` (0x480),
`KeyRight` (0x500), `KeyOK` (0x580), `KeyMenu` (0x700). It also has
`KeyTele`, `KeyWide`, `KeyReview`, `KeyVideoRec`, `KeyPowerOff`, `KeyMB`
and the hold/release variants `KeyHold*` and `KeyRelease*`. **emulated**
for the six with events, **static** for the rest.
