#!/usr/bin/env python3
"""Snapshot sintetico, scanner originale, menu e testi del modello."""
import struct
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_snapshot_menu_bridge_cpu as bridge


def main():
    labels = (
        ('Esposizione', 'Colore / Mono', None, 'Impostazioni'),
        ('Indietro', 'ISO', 'Apertura', 'Altro'),
        ('Indietro', 'Colore', 'Mono RAW', None),
        ('Indietro', 'Tempo', 'Flash', None),
        ('Indietro', 'Acceso', 'Spento', None),
        ('Indietro', 'Posizione A', 'Posizione B', None),
    )
    specs = bridge.build_specs()
    for spec in specs:
        screen = next(value for address, width, value in spec['checks']
                      if address == 0x367600 and width == 4)
        for slot, label in enumerate(labels[screen], 1):
            dest = 0x367780 + (slot - 1) * 16
            spec['extra'] += (f' mov r0,0x367600\n ld r0,[r0]\n mov r1,{slot}\n'
                              ' mov r12,akeru_menu_label\n jl_s [r12]\n'
                              f' mov r1,{dest:#x}\n')
            if label is None:
                spec['extra'] += ' st r0,[r1,0]\n'
                spec['checks'].append((dest, 4, 0))
            else:
                spec['extra'] += ' mov r3,0\n st r3,[r1,0]\n st r3,[r1,4]\n st r3,[r1,8]\n st r3,[r1,12]\n'
                for offset, byte in enumerate(label.encode('ascii') + b'\0'):
                    spec['extra'] += f' ldb r2,[r0,{offset}]\n stb r2,[r1,{offset}]\n'
                padded = (label.encode('ascii') + b'\0').ljust(16, b'\0')
                spec['checks'] += [(dest + offset, 4, value) for offset, value in
                                   zip(range(0, 16, 4), struct.unpack('<4I', padded))]
    fan.main(specs, scanner=True, queue=True, dispatch=True, window=True,
             menu_model=True, menu_bridge=True, snapshot_input=True, menu_labels=True)


if __name__ == '__main__':
    main()
