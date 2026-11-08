#!/usr/bin/env python3
"""Scanner V1.1 fino al fan-out con callback originali; servizi fixture."""
import s33_verify_key_callback_16e588_cpu as cb
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_machine_static_map_cpu as km


def main():
    specs = []
    for order in [(0x16E588, 0x323A00), (0x323A00, 0x16E588)]:
        for gate in (0, 1):
            for classe, bit, event in [(11, 12, 0x580), (14, 7, 0x700),
                                       (67, 8, 0x2180), (78, 13, 0x2700)]:
                setup = km.setup_asm() + cb.presets(ret_c9bf8=gate, ret_cb618=1)
                for i, address in enumerate(order):
                    setup += fan.write_word(0x446A08 + 4 * i, address)
                setup += fan.write_word(0x3678F9, 1, 'stb')
                setup += fan.write_word(0x446808 + 4 * classe + 2, 1, 'sth')
                setup += km.scanner_asm(1 << bit, 0) + km.scanner_asm(0, 0)
                rings = 2 if gate == 0 else 0
                posts = 4 if gate == 1 and classe in (67, 78) else 0
                checks = [(km.RING_COUNT, 4, rings), (cb.POST_COUNT, 4, posts),
                          (km.C150_COUNT, 4, 1), (km.REC(classe), 1, 0),
                          (0x3678F0, 4, 0), (0x3678F4, 4, 0)]
                checks += km.c150_entry(0, 2, 1, event, event + 1)
                if rings:
                    checks += km.ring_entry(0, event, 0, 1)
                    checks += km.ring_entry(1, event + 1, 0, 1)
                if posts:
                    checks += cb.post_entry(0, 0, 0x4006, classe)
                    checks += cb.post_entry(1, 0, event, 1)
                    checks += cb.post_entry(2, 0, 0x4006, classe)
                    checks += cb.post_entry(3, 0, event + 1, 0)
                specs.append(dict(name=f'c{classe}_o{order[0]:x}_g{gate}',
                                  extra=setup, checks=checks,
                                  success=0xDEADC100 + len(specs)))
    fan.main(specs, scanner=True)


if __name__ == '__main__':
    main()
