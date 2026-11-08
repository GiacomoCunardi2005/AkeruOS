#!/usr/bin/env python3
"""Frammento originale V1.1 di confronto ISO e correttivo, con fixture."""
import s33_verify_key_fanout_callbacks_cpu as fan


def main():
    specs = []
    cases = [(0, 0, 1, 0), (1, 50, 1, 0), (6, 125, 1, 0),
             (7, 140, 1, 0), (19, 1600, 1, 0), (22, 3200, 1, 0),
             (19, 1600, 0, 0), (19, 1600, 1, 1)]
    for index, value, enabled, guard in cases:
        active = enabled and not guard and value > 125
        extra = ''.join(fan.write_word(a, v, op) for a, v, op in (
            (0x367604, 0x367720, 'st'), (0x36760C, 0x367730, 'st'),
            (0x367720, enabled, 'stb'), (0x367722, 125, 'sth'),
            (0x367724, 0xFFF9, 'sth'), (0x367734, guard, 'stb')))
        extra += (f' mov r0,{index}\n mov r12,0xd03b8\n jl_s [r12]\n'
                  ' mov r26,threshold_return\n mov r12,0xd8d0a\n j_s [r12]\n'
                  'threshold_return:\n')
        trace = ['0x0d03b8', '0x17c320', '0x0de78c', '0x0d8d0a', '0x0d8d0e', '0x0d8d14']
        if not guard and enabled:
            trace += ['0x0f6f0c', '0x0d8d2a']
        specs.append(dict(name=f'iso{value}_enabled{enabled}_guard{guard}', extra=extra,
                          checks=[(0x367700, 4, 0xFFFFFFF9 if active else 0),
                                  (0x367600, 4, 1), (0x367608, 4, 1),
                                  (0x365787, 1, index), (0x367BC8, 1, index),
                                  (0x37FBF2, 2, value)], trace=trace,
                          trace_absent=[] if active else ['0x0d8d34'],
                          success=0xDEAD9100+len(specs)))
    fan.main(specs, iso_threshold=True)


if __name__ == '__main__':
    main()
