#!/usr/bin/env python3
"""Snapshot MMIO sintetico -> scanner -> modello -> catena testo originale."""
import struct
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_snapshot_menu_bridge_cpu as bridge

LABELS = (
    ('Esposizione', 'Colore / Mono', None, 'Impostazioni'),
    ('Indietro', 'ISO', 'Apertura', 'Altro'),
    ('Indietro', 'Colore', 'Mono RAW', None),
    ('Indietro', 'Tempo', 'Flash', None),
    ('Indietro', 'Acceso', 'Spento', None),
    ('Indietro', 'Posizione A', 'Posizione B', None),
)


def main():
    specs = bridge.build_specs()
    for spec in specs:
        screen = next(value for address, width, value in spec['checks']
                      if address == 0x367600 and width == 4)
        extra = fan.write_word(0x366868, 1, 'stb')
        extra += fan.write_word(0x367f3e, 1, 'sth')
        extra += fan.write_word(0x505030, 0x502000)
        extra += fan.write_word(0x505036, 1, 'stb')
        extra += fan.write_word(0x506010, 1)
        extra += fan.write_word(0x506014, 0x506100)
        extra += fan.write_word(0x506108, 1000, 'sth')
        extra += fan.write_word(0x50610a, 1000, 'sth')
        for slot, label in enumerate(LABELS[screen], 1):
            dest = 0x500000 + (slot - 1) * 32
            extra += (f' mov r0,0x367600\n ld r0,[r0]\n mov r1,{slot}\n'
                      ' mov r12,akeru_menu_label\n jl_s [r12]\n'
                      ' mov r1,0x502000\n st r0,[r1,12]\n'
                      ' mov r1,0x504000\n mov r0,0\n st r0,[r1,16]\n st r0,[r1,28]\n'
                      ' mov r0,0x505000\n mov r1,0\n mov r2,12\n mov r3,30\n'
                      ' mov r12,0x631f44\n jl [r12]\n'
                      ' mov r0,0x504000\n ld r1,[r0,28]\n ld r2,[r0,16]\n'
                      ' mov r0,0x502000\n ld r3,[r0,12]\n xor r2,r2,r3\n'
                      f' mov r0,{dest:#x}\n st r1,[r0]\n st r2,[r0,4]\n')
            spec['checks'] += [(dest, 4, int(label is not None)), (dest+4, 4, 0)]
            if label is not None:
                extra += (f' mov r0,0x502000\n ld r0,[r0,12]\n mov r1,{dest+8:#x}\n')
                for offset, byte in enumerate(label.encode('ascii') + b'\0'):
                    extra += f' ldb r2,[r0,{offset}]\n stb r2,[r1,{offset}]\n'
                padded = (label.encode('ascii') + b'\0').ljust(16, b'\0')
                spec['checks'] += [(dest+8+off, 4, value) for off, value in
                                   zip(range(0, 16, 4), struct.unpack('<4I', padded))]
        spec['extra'] += extra
        nonempty = sum(label is not None for label in LABELS[screen])
        spec['trace'] += ['0x631f44', '0x186d08', '0x186c40', '0x186b14']
        spec['trace_counts'] = [('0x631f44', 4), ('0x186d08', nonempty),
                                ('0x186c40', 2*nonempty), ('0x186b14', 2*nonempty)]
    fan.main(specs, scanner=True, queue=True, dispatch=True, window=True,
             menu_model=True, menu_bridge=True, snapshot_input=True,
             menu_labels=True, menu_text=True)


if __name__ == '__main__':
    main()
