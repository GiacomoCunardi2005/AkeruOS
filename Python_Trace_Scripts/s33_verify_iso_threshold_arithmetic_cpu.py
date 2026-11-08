#!/usr/bin/env python3
"""Propagazione del correttivo ISO nell'aritmetica V1.1, con fixture."""
import s33_verify_key_fanout_callbacks_cpu as fan


def main():
    specs = []
    for index, value, enabled, guard in [(1, 50, 1, 0), (6, 125, 1, 0),
                                          (7, 140, 1, 0), (19, 1600, 1, 0),
                                          (22, 3200, 1, 0), (19, 1600, 0, 0),
                                          (19, 1600, 1, 1)]:
        correction = -7 if enabled and not guard and value > 125 else 0
        extra = ''.join(fan.write_word(a, v, op) for a, v, op in (
            (0x367604, 0x367720, 'st'), (0x36760C, 0x367730, 'st'),
            (0x367720, enabled, 'stb'), (0x367722, 125, 'sth'),
            (0x367724, 0xFFF9, 'sth'), (0x367734, guard, 'stb'),
            (0x367614, 40, 'st'), (0x367704, 12, 'sth')))
        extra += (f' mov r0,{index}\n mov r12,0xd03b8\n jl_s [r12]\n'
                  ' mov fp,0xc90000\n mov r0,10\n st r0,[fp,-176]\n'
                  ' mov r0,20\n st r0,[fp,-180]\n mov r0,5\n st r0,[fp,-184]\n'
                  ' mov r13,0x367800\n mov r17,100\n mov r24,3\n'
                  ' mov r26,threshold_return\n mov r12,0xd8d0a\n j_s [r12]\n'
                  'threshold_return:\n')
        total = 78 + correction
        specs.append(dict(name=f'iso{value}_enabled{enabled}_guard{guard}', extra=extra,
                          checks=[(0x367700, 4, correction & 0xffffffff),
                                  (0x367708, 4, 100 - total), (0x36770C, 4, total),
                                  (0x367610, 4, 1), (0x37FBF2, 2, value)],
                          trace=['0x0d8d0a', '0x0d8d38', '0x0d8d52',
                                 '0x0d8d66', '0x0d8d72', '0x0d8d7c'],
                          success=0xDEAD9200 + len(specs)))
    fan.main(specs, iso_threshold=True, iso_threshold_math=True)


if __name__ == '__main__':
    main()
