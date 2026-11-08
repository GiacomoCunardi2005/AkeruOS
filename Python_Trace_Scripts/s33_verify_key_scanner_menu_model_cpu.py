#!/usr/bin/env python3
"""Scanner originale -> coda -> eventi consegnati esplicitamente al modello menu."""
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_queue_cpu as queue


EXPECTED = {
        0: [(1, 1), (2, 1), (0, 0), (0, 7)],
        1: [(0, 1), (1, 2), (5, 1), (3, 1)],
        2: [(0, 1), (2, 5), (2, 6), (2, 0)],
        3: [(1, 1), (3, 4), (4, 1), (3, 0)],
        4: [(3, 1), (4, 8), (4, 9), (4, 0)],
        5: [(1, 1), (5, 12), (5, 13), (5, 0)],
    }


def main():
    specs = []
    for order in (0x16E588, 0x323A00):
        for slot, key in enumerate((11, 14, 67, 78)):
            base = next(s for s in queue.build_specs() if s['name'] == f'c{key}_o{order:x}_g0')
            for screen, choices in EXPECTED.items():
                next_screen, action = choices[slot]
                extra = base['extra'] + fan.write_word(0x367600, screen)
                extra += fan.write_word(0x367608, 99) + fan.write_word(0x36760C, 99)
                for i, result in ((0, 0x367610), (1, 0x367614)):
                    extra += (f' mov r0,0x367600\n mov r1,{hex(queue.BUF+16*i+4)}\n'
                              f' ldh r1,[r1,0]\n mov r2,{hex(0x367608+4*i)}\n'
                              f' bl akeru_menu_event\n mov r1,{hex(result)}\n st r0,[r1,0]\n')
                checks = base['checks'] + [(0x367600, 4, next_screen),
                                           (0x367608, 4, action), (0x36760C, 4, 0),
                                           (0x367610, 4, 1), (0x367614, 4, 1)]
                specs.append(dict(name=f'o{order:x}_screen{screen}_slot{slot+1}',
                                  extra=extra, checks=checks, success=0xDEADA100+len(specs)))
    fan.main(specs, scanner=True, queue=True, menu_model=True)


if __name__ == '__main__':
    main()
