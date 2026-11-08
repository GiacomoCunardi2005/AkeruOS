#!/usr/bin/env python3
"""Scanner e due callback fino a inserimento ed estrazione coda originali."""
import s33_verify_key_callback_16e588_cpu as cb
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_machine_static_map_cpu as km

QUEUE, RECORDS, BUF = 0x367BBC, 0x47A848, 0x367400


def build_specs():
    specs = []
    for order in [(0x16E588, 0x323A00), (0x323A00, 0x16E588)]:
        for gate in (0, 1):
            for classe, bit, event in [(11, 12, 0x580), (14, 7, 0x700),
                                       (67, 8, 0x2180), (78, 13, 0x2700)]:
                setup = fan.write_word(0x367364, 1) + km.setup_asm()
                setup += cb.presets(ret_c9bf8=gate, ret_cb618=1)
                for i, address in enumerate(order):
                    setup += fan.write_word(0x446A08 + 4*i, address)
                setup += fan.write_word(0x3678F9, 1, 'stb')
                setup += fan.write_word(0x446808 + 4*classe + 2, 1, 'sth')
                setup += km.scanner_asm(1 << bit, 0) + km.scanner_asm(0, 0)
                events = ([(event, 0), (event+1, 0)] if gate == 0 else
                          [(0x4006, classe), (event, 1), (0x4006, classe), (event+1, 0)]
                          if classe in (67, 78) else [])
                for i in range(len(events)):
                    setup += f' mov r0,{hex(BUF+16*i)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
                checks = [(QUEUE, 2, len(events)),
                          (QUEUE+2, 2, len(events)),
                          (0x367368, 4, len(events)),
                          (km.C150_COUNT, 4, 1), (km.REC(classe), 1, 0)]
                checks += km.c150_entry(0, 2, 1, event, event+1)
                for i, (queued_event, arg) in enumerate(events):
                    checks += [(RECORDS+12*i, 4, 0), (RECORDS+12*i+4, 2, queued_event),
                               (RECORDS+12*i+8, 4, arg), (BUF+16*i, 4, 0),
                               (BUF+16*i+4, 2, queued_event), (BUF+16*i+8, 4, arg)]
                specs.append(dict(name=f'c{classe}_o{order[0]:x}_g{gate}',
                                  extra=setup, checks=checks,
                                  success=0xDEADD100+len(specs)))
    return specs


def main():
    fan.main(build_specs(), scanner=True, queue=True)


if __name__ == '__main__':
    main()
