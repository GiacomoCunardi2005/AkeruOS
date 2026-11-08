#!/usr/bin/env python3
"""Scanner originale e dispatcher verso modello C tramite descrittore sintetico."""
import struct
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_queue_cpu as queue
from s33_verify_key_scanner_shared_cpu import dispatch_buffer
from s33_verify_key_scanner_menu_model_cpu import EXPECTED


def main():
    blocks, payloads, _ = fan.verified_payloads(fan.ROOT)
    block = next(b for b in blocks if b['index'] == 5)
    off = 0x9802AC - block['load_address_candidate']
    desc = bytearray(payloads[5][off:off+28])
    assert len(desc) == 28 and struct.unpack_from('<I', desc, 12)[0] == 0x7CAFE8
    struct.pack_into('<H', desc, 6, 0)
    struct.pack_into('<I', desc, 8, 0)
    struct.pack_into('<I', desc, 12, 0x300800)
    struct.pack_into('<I', desc, 20, 0)
    descriptor = ''.join(fan.write_word(0x367700 + 4*i, value)
                         for i, value in enumerate(struct.unpack('<7I', desc)))
    specs = []
    for order in (0x16E588, 0x323A00):
        for slot, key in enumerate((11, 14, 67, 78)):
            base = next(s for s in queue.build_specs() if s['name'] == f'c{key}_o{order:x}_g0')
            for screen, choices in EXPECTED.items():
                next_screen, action = choices[slot]
                extra = base['extra'] + descriptor + fan.write_word(0x366EA4, 0x367700)
                extra += fan.write_word(0x366EAC, 0) + fan.write_word(0x367600, screen)
                extra += dispatch_buffer(0) + dispatch_buffer(1)
                event = (0x580, 0x700, 0x2180, 0x2700)[slot]
                checks = base['checks'] + [(0x367600, 4, next_screen), (0x367604, 4, action),
                                           (0x367608, 4, 2), (0x367610, 4, event),
                                           (0x367614, 4, event + 1)]
                specs.append(dict(name=f'o{order:x}_screen{screen}_slot{slot+1}',
                                  extra=extra, checks=checks,
                                  trace=['0x169e1c', '0x16a6e4', '0x16a028', '0x300800'],
                                  success=0xDEADB200+len(specs)))
        for slot, key in enumerate((11, 14, 67, 78)):
            base = next(s for s in queue.build_specs() if s['name'] == f'c{key}_o{order:x}_g1')
            count = 0 if key in (11, 14) else 4
            extra = base['extra'] + descriptor + fan.write_word(0x366EA4, 0x367700)
            extra += fan.write_word(0x366EAC, 0) + fan.write_word(0x367600, 0)
            extra += ''.join(dispatch_buffer(i) for i in range(count))
            checks = base['checks'] + [(0x367600, 4, 0),
                                       (0x367604, 4, 7 if key == 78 else 0),
                                       (0x367608, 4, count)]
            if count:
                event = (0x580, 0x700, 0x2180, 0x2700)[slot]
                checks += [(0x367610 + 4*i, 4, ev) for i, ev in
                           enumerate((0x4006, event, 0x4006, event + 1))]
            specs.append(dict(name=f'o{order:x}_gate1_slot{slot+1}', extra=extra, checks=checks,
                              trace=['0x300800'] if count else ['0x16f72c'],
                              trace_absent=[] if count else ['0x300800'],
                              success=0xDEADC200+len(specs)))
    base = next(s for s in queue.build_specs() if s['name'] == 'c14_o16e588_g0')
    extra = base['extra'] + descriptor + fan.write_word(0x366EA4, 0)
    extra += fan.write_word(0x367600, 0) + dispatch_buffer(0) + dispatch_buffer(1)
    specs.append(dict(name='no_current_window', extra=extra,
                      checks=base['checks'] + [(0x367600, 4, 0), (0x367604, 4, 0), (0x367608, 4, 0)],
                      trace=['0x169e1c'], trace_absent=['0x300800'], success=0xDEADB2FF))
    fan.main(specs, scanner=True, queue=True, dispatch=True, window=True,
             menu_model=True, menu_bridge=True)


if __name__ == '__main__':
    main()
