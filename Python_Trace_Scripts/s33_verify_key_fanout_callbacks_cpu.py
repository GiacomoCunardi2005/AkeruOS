#!/usr/bin/env python3
"""Fan-out V1.1 con due callback originali; servizi e RAM sono fixture."""
import hashlib
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import s33_verify_key_callback_16e588_cpu as cb
import s33_verify_key_machine_static_map_cpu as km
from s33_trace_state_dispatch import verified_payloads
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, elf_loads


def write_word(addr, value, op='st'):
    return f' mov r0,{hex(value)}\n mov r1,{hex(addr)}\n {op} r0,[r1,0]\n'


def event_table_stub():
    return ('.section .s_eventtable,"ax",@progbits\n push_s blink\n'
            ' mov r5,0x367500\n ld r6,[r5,0]\n asl r7,r6,5\n'
            ' add r7,r7,r5\n add r7,r7,16\n'
            ' st r0,[r7,0]\n st r1,[r7,4]\n st r2,[r7,8]\n'
            ' st r3,[r7,12]\n st r4,[r7,16]\n'
            ' add r6,r6,1\n st r6,[r5,0]\n mov r0,0\n'
            ' pop_s blink\n j_s [blink]\n')


def shared_handler_stub(section, counter):
    text = cb.stub_post().replace('.s_post', section)
    return text.replace(' push_s blink\n',
                        f' push_s blink\n mov r5,{hex(counter)}\n ld r6,[r5,0]\n'
                        ' add r6,r6,1\n st r6,[r5,0]\n', 1)


def case(classe, event, order, gate, number, threshold=0, state=1):
    extra = cb.presets(ret_c9bf8=gate, ret_cb618=1)
    for i, addr in enumerate(order):
        extra += write_word(0x446A08 + 4 * i, addr)
    extra += write_word(0x3678F9, 1, 'stb')
    extra += write_word(0x446808 + 4 * classe + 2, 1, 'sth')
    extra += write_word(0x370670, threshold)
    extra += write_word(0x37066C, 0x55)
    extra += write_word(0x370678, 0x66)
    extra += (f' mov r0,{classe}\n mov r1,{state}\n mov r2,{hex(event)}\n'
              ' mov r3,0x42\n mov r4,1\n mov r12,0x16f6b0\n jl_s [r12]\n')
    ring = int(gate == 0 and classe != 1)
    posts = 0 if gate == 0 or classe in (11, 14) or (classe == 1 and order[0] == 0x323A00) else 2
    checks = [(km.RING_COUNT, 4, ring), (cb.POST_COUNT, 4, posts)]
    if ring:
        checks += km.ring_entry(0, event, 0x42, 1)
    if posts:
        checks += cb.post_entry(0, 0, 0x4006, classe)
        checks += cb.post_entry(1, 0, event, state)
    if classe == 1:
        invoked = order[0] == 0x323A00 or gate == 0
        checks += [(cb.CNT_C9BF8, 4, int(order[0] != 0x323A00)),
                   (0x37066C, 4, int(threshold <= 130) if invoked else 0x55),
                   (0x370678, 4, int(threshold > 130) if invoked else 0x66)]
    else:
        checks += [(0x37066C, 4, 0x55), (0x370678, 4, 0x66)]
    return dict(name=f'c{classe}_o{order[0]:x}_g{gate}_t{threshold}_s{state}',
                extra=extra, checks=checks, success=0xDEADB100 + number)


def main(specs=None, scanner=False, queue=False, dispatch=False, window=False, table=False, shared=False, handler700=False, manager700=False, lifecycle_stub=False, lifecycle_real=False, iso_confirm=False, control_confirm=False, navigation=False, handler2180=False, iso_threshold=False, menu_model=False, menu_bridge=False, menu_return_table=False, return_purge_real=False, color_model=False, time_window=False, snapshot_input=False, iris_backend=False, iso_threshold_math=False, menu_labels=False, menu_text=False, iso_threshold_call=False, iso_threshold_apply=False):
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    label = 'key_snapshot_menu_iris' if iris_backend else 'key_snapshot_menu_bridge' if snapshot_input else 'key_scanner_menu_time' if time_window and menu_bridge else 'key_scanner_time_window' if time_window else 'key_scanner_menu_color' if color_model else 'key_scanner_menu_iso_purge' if return_purge_real else 'key_scanner_menu_iso_return' if menu_return_table else 'key_scanner_menu_iso_navigation' if menu_bridge and navigation else 'key_scanner_menu_iso_open' if menu_bridge and manager700 else 'key_scanner_menu_bridge' if menu_bridge else 'key_scanner_menu_model' if menu_model else 'iso_threshold_slice' if iso_threshold else 'key_scanner_handler2180' if handler2180 else 'key_scanner_iso_navigation' if navigation else 'key_scanner_control_confirm' if control_confirm else 'key_scanner_iso_confirm' if iso_confirm else 'key_scanner_lifecycle_real700' if lifecycle_real else 'key_scanner_lifecycle700' if lifecycle_stub else 'key_scanner_manager700' if manager700 else 'key_scanner_handler700' if handler700 else 'key_scanner_shared' if shared else 'key_scanner_table' if table else 'key_scanner_window' if window else 'key_scanner_dispatch' if dispatch else 'key_scanner_queue' if queue else 'key_scanner_callbacks' if scanner else 'key_fanout_callbacks'
    if menu_labels: label = 'key_snapshot_menu_labels'
    if menu_text: label = 'key_snapshot_menu_text'
    if iso_threshold_call: label = 'iso_threshold_call'
    if iso_threshold_apply: label = 'iso_threshold_apply'
    out = ROOT / 'Risultati/GUI_S33' / f'{label}_cpu_{stamp}'
    blocks, payloads, _ = verified_payloads(ROOT)
    bases = {b['index']: b['load_address_candidate'] for b in blocks}
    windows = [cb.W_CB, cb.W_KMACH, cb.W_MODEGET, cb.W_MODEPOOL,
               cb.W_MILI, (0, 0x323600, 0x323A3C, '.cb2')]
    stubs = cb.STUB_SECTIONS + [('.s_ring', 0x17BC7C, km.stub_ring)]
    if menu_text:
        assert menu_labels
        windows += [(2, 0x631F44, 0x632576, '.textitem'),
                    (2, 0x6337C4, 0x6337F4, '.textlookup'),
                    (0, 0x1286C4, 0x128704, '.textlanguage'),
                    (0, 0x14507C, 0x145180, '.texthelpers'),
                    (0, 0x186B14, 0x186C40, '.textdraw'),
                    (0, 0x186C40, 0x186D08, '.textmeasure'),
                    (0, 0x186D08, 0x186E38, '.textlayout'),
                    (0, 0x187010, 0x187020, '.textpool')]
        noop = ' mov r0,0\n j_s [blink]\n'
        fixtures = [('metric_a', 0x26E464, noop), ('metric_b', 0x26E418, noop),
                    ('icon', 0x26E3C0, noop), ('mode', 0xD0A84, noop),
                    ('text_setup', 0x1EB438, noop), ('color', 0x18BA80, noop),
                    ('text_context', 0x20E320, ' mov r0,0x506000\n j_s [blink]\n'),
                    ('metric_mode', 0x14C768, noop), ('metric_end', 0x14C6F4, noop),
                    ('byte_class', 0x23AD30, noop),
                    ('glyph_width', 0x23ACC4, ' mov r0,10\n j_s [blink]\n'),
                    ('measure_callback', 0x187168, noop),
                    ('draw_recorder', 0x1870DC, ' mov r12,0x504000\n st r0,[r12,16]\n ld r0,[r12,28]\n add r0,r0,1\n st r0,[r12,28]\n mov r0,1\n j_s [blink]\n')]
        stubs += [(f'.s_text_{name}', addr,
                   lambda name=name, code=code: f'.section .s_text_{name},"ax",@progbits\n' + code)
                  for name, addr, code in fixtures]
    if scanner:
        windows += [km.W_DESC, km.W_SHIFT64]
        stubs += [s for s in km.STUB_SECTIONS if s[0] not in ('.s_ring', '.s_cb')]
    if snapshot_input:
        stubs = [s for s in stubs if s[0] != '.s_e6e0']
        windows += [(0, 0x14064C, 0x140650, '.snapshotcallbackpool'),
                    (0, 0x1406D0, 0x140700, '.snapshotcallback'),
                    (0, 0x16E6E0, 0x16E830, '.snapshotnormalize'),
                    (0, 0x16EC38, 0x16EC86, '.snapshotadapter'),
                    (0, 0x2D62D8, 0x2D6300, '.snapshotreader')]
    if queue:
        windows += [(0, 0x17BC7C, 0x17BD98, '.queuecode'),
                    (0, 0x17BFF4, 0x17C004, '.queuepool'),
                    (0, 0x169EB4, 0x169F00, '.postcode'),
                    (0, 0x16A128, 0x16A138, '.postpool')]
        stubs = [s for s in stubs if s[0] not in ('.s_ring', '.s_lock_ac', '.s_post')]
        stubs += [('.s_lock_ac', 0x1593AC, lambda: cb.stub_ret('.s_lock_ac', 0x367360, 0x367364)),
                  ('.s_qenter', 0x1786E8, lambda: km.stub_ret0('.s_qenter')),
                  ('.s_qleave', 0x179354, lambda: km.stub_ret0('.s_qleave')),
                  ('.s_signal', 0x158CBC, lambda: cb.stub_count('.s_signal', 0x367368))]
    if dispatch:
        windows = [w for w in windows if w[3] not in ('.postcode', '.postpool')]
        windows += [(0, 0x169D78, 0x169F00, '.dispatchcode'),
                    (0, 0x16A128, 0x16A164, '.dispatchpool'),
                    (0, 0x1453F4, 0x1453FA, '.resolve'),
                    (0, 0x14579C, 0x1457A0, '.resolvepool')]
        stubs += [('.s_delivery', 0x16A6E4, lambda: cb.stub_post().replace('.s_post', '.s_delivery'))]
    if window:
        stubs = [s for s in stubs if s[0] != '.s_delivery']
        windows += [(0, 0x16A6E4, 0x16A7A4, '.delivery'),
                    (0, 0x16A028, 0x16A05C, '.callbackdispatch'),
                    (0, 0x14503C, 0x14507C, '.callbacklookup'),
                    (0, 0x145790, 0x145796, '.controlget'),
                    (0, 0x1457D0, 0x1457D4, '.controlpool'),
                    (4, 0x7CAFE8, 0x7CB020, '.windowcallback'),
                    (5, 0x9802AC, 0x9802C8, '.windownode')]
        if table:
            windows += [(0, 0x169F60, 0x169FB4, '.eventlookup'),
                        (5, 0x982384, 0x9823B4, '.eventtable')]
            stubs += [('.s_default', 0x20E814, lambda: cb.stub_post().replace('.s_post', '.s_default')),
                      ('.s_match', 0x7CB0D8, lambda: cb.stub_count('.s_match', 0x367504, fields_base=0x367510))]
        else:
            stubs += [('.s_eventtable', 0x169F60, event_table_stub)]
    if shared:
        stubs = [s for s in stubs if s[0] != '.s_default']
        windows += [(0, 0x20E814, 0x20E848, '.defaultcode'),
                    (1, 0x3E8BB4, 0x3E8DCC, '.sharedtable')]
        stubs += [(sec, addr, lambda sec=sec, counter=counter: shared_handler_stub(sec, counter))
                  for sec, addr, counter in [('.s_shared_700', 0x20EAF4, 0x3675B0),
                                             ('.s_shared_2180', 0x20E940, 0x3675B4),
                                             ('.s_shared_4006', 0x20F414, 0x3675B8)]]
    if handler700:
        stubs = [s for s in stubs if s[0] != '.s_shared_700']
        windows += [(0, 0x20EAF4, 0x20EB32, '.handler700')]
        stubs += [('.s_cad5c', 0xCAD5C, lambda: cb.stub_ret('.s_cad5c', 0x3675C0, 0x3675C4)),
                  ('.s_cd9c8', 0xCD9C8, lambda: cb.stub_ret('.s_cd9c8', 0x3675C8, 0x3675CC)),
                  ('.s_request', 0x1453E4, lambda: '.section .s_request,"ax",@progbits\n mov r12,0x300800\n j_s [r12]\n'),
                  ('.s_request_impl', 0x300800, lambda: cb.stub_count('.s_request_impl', 0x3675D0, fields_base=0x3675D4))]
    if handler2180:
        stubs = [s for s in stubs if s[0] != '.s_shared_2180']
        windows += [(0, 0x20E932, 0x20EA5C, '.handler2180'),
                    (0, 0xCAD58, 0xCAD64, '.state3'),
                    (0, 0xCB4A4, 0xCB4B0, '.state6'),
                    (0, 0x16E41C, 0x16E43E, '.const42'),
                    (0, 0x1453FC, 0x145414, '.idresolver')]
        stubs += [('.s_query2180', 0x17BE18, lambda: cb.stub_count('.s_query2180', 0x367600, fields_base=0x367604, ret_cell=0x367610)),
                  ('.s_cancel2180', 0x17C074, lambda: cb.stub_post().replace('.s_post', '.s_cancel2180').replace(hex(cb.POST_COUNT), '0x367640')),
                  ('.s_notify2180', 0x1564C0, lambda: cb.stub_count('.s_notify2180', 0x367618, fields_base=0x36761C)),
                  ('.s_request2180', 0x1453E4, lambda: '.section .s_request2180,"ax",@progbits\n mov r12,0x300800\n j_s [r12]\n'),
                  ('.s_request2180_impl', 0x300800, lambda: cb.stub_count('.s_request2180_impl', 0x367620, fields_base=0x367624))]
    if iso_threshold:
        windows += [(0, 0xD8D0A, 0xD8DE6 if iso_threshold_call else 0xD8D7E if iso_threshold_math else 0xD8D38, '.thresholdslice'),
                    (0, 0xF6F0C, 0xF6F14, '.thresholdbase'),
                    (0, 0xC979A, 0xC97A8, '.thresholdisoepi'),
                    (0, 0xD03B8, 0xD03D8, '.thresholdisoset'),
                    (0, 0xDE19A, 0xDE1AA, '.thresholdparamepi'),
                    (0, 0xDE78C, 0xDE7A8, '.thresholdparamset'),
                    (0, 0x17C320, 0x17C3F8, '.thresholdconvert')]
        stubs += [('.s_threshold_table', 0xE309C, lambda: cb.stub_ret('.s_threshold_table', 0x367600, 0x367604)),
                  ('.s_threshold_ctx', 0x103F70, lambda: cb.stub_ret('.s_threshold_ctx', 0x367608, 0x36760C)),
                  ('.s_threshold_end', 0xD8DE6 if iso_threshold_call else 0xD8D7E if iso_threshold_math else 0xD8D38, lambda: '.section .s_threshold_end,"ax",@progbits\n mov r0,0x367700\n st r25,[r0,0]\n' + (' st r14,[r0,8]\n' if iso_threshold_math else '') + (' st r4,[r0,12]\n' if iso_threshold_math and not iso_threshold_call else '') + ' j [r26]\n')]
        if iso_threshold_math:
            windows += [(0, 0xD90DC, 0xD90E0, '.thresholdpool')]
            stubs += [('.s_threshold_math', 0x1AA2B0, lambda: cb.stub_ret('.s_threshold_math', 0x367610, 0x367614))]
        if iso_threshold_call:
            assert iso_threshold_math
            for name, addr, value in [('f70c0', 0xF70C0, 0), ('f70e8', 0xF70E8, 0),
                                      ('e0f94', 0xE0F94, 0), ('e0fb8', 0xE0FB8, 0),
                                      ('c634', 0x18C634, 36)]:
                stubs.append((f'.s_threshold_{name}', addr,
                              lambda name=name, value=value: f'.section .s_threshold_{name},"ax",@progbits\n mov r0,{value}\n j_s [blink]\n'))
            if iso_threshold_apply:
                windows += [(0, 0x18C90C, 0x18C958, '.thresholdconsumer')]
            else:
                stubs.append(('.s_threshold_c90c', 0x18C90C, lambda: '''.section .s_threshold_c90c,"ax",@progbits
 mov r12,0x367740
 st r0,[r12,0]
 st r1,[r12,4]
 st r2,[r12,8]
 st r3,[r12,12]
 st r4,[r12,16]
 ld r0,[r12,20]
 add r0,r0,1
 st r0,[r12,20]
 j_s [blink]
'''))
    if manager700:
        stubs = [s for s in stubs if s[0] not in ('.s_request', '.s_request_impl')]
        windows = [w for w in windows if w[3] != '.resolve']
        windows += [(0, 0x14507C, 0x145180, '.managerhelpers'),
                    (0, 0x145180, 0x1453FA, '.manager'),
                    (0, 0x145798, 0x14579C, '.managerpool'),
                    (1, 0x3F5900, 0x3F5C14, '.windowtable'),
                    (5, 0x989FCC, 0x989FE8, '.isonode')]
    if lifecycle_stub:
        stubs += [('.s_isolifecycle', 0x7D252C, lambda: cb.stub_ret('.s_isolifecycle', 0x3675E0, 0x3675E4)),
                  ('.s_lifecycle_init', 0x16A05C, lambda: cb.stub_ret('.s_lifecycle_init', 0x3675E8, 0x3675EC)),
                  ('.s_lifecycle_next', 0x16A188, lambda: cb.stub_ret('.s_lifecycle_next', 0x3675F0, 0x3675F4))]
    if lifecycle_real:
        windows += [(0, 0x16A05C, 0x16A128 if menu_return_table else 0x16A0BC, '.lifecycleinit'),
                    (0, 0x16A17C, 0x16A188, '.lifecyclepool'),
                    (0, 0x16A188, 0x16A240, '.lifecycleevents'),
                    (0, 0x17C3E8, 0x17C3F8, '.isoget'),
                    (2, 0x641128, 0x641174, '.isofind'),
                    (4, 0x7D252C, 0x7D25B0, '.isocallback'),
                    (5, 0x989DA4, 0x989F84, '.isorecords'),
                    (5, 0x989FEC, 0x98A010, '.isotables')]
        stubs += [('.s_enum', 0x1455E4, lambda: cb.stub_count('.s_enum', 0x367600)),
                  ('.s_focus_clear', 0x145920, lambda: km.stub_ret0('.s_focus_clear')),
                  ('.s_focus_set', 0x14592C, lambda: km.stub_ret0('.s_focus_set')),
                  ('.s_special_post', 0x17BE80, lambda: cb.stub_ret('.s_special_post', 0x367624, 0x367628)),
                  ('.s_resource', 0x145654, lambda: cb.stub_ret('.s_resource', 0x367604, 0x367608)),
                  ('.s_select', 0x641064, lambda: cb.stub_count('.s_select', 0x36760C, fields_base=0x367610))]
    if iso_confirm:
        windows = [w for w in windows if w[3] not in ('.isocallback', '.isofind', '.isoget')]
        windows += [(0, 0xC979A, 0xC97A8, '.isoepilogue'),
                    (0, 0xD03B8, 0xD03D8, '.isosetter'),
                    (0, 0xDE19A, 0xDE1AA, '.param_epilogue'),
                    (0, 0xDE78C, 0xDE7A8, '.param_setter'),
                    (0, 0xF6F0C, 0xF6F14, '.param_base'),
                    (0, 0x17C320, 0x17C3F8, '.isoconvert'),
                    (2, 0x6410F4, 0x641174, '.isogetfind'),
                    (4, 0x7D252C, 0x7D25F0, '.isowindow')]
        stubs += [('.s_4409', 0x16A29C, lambda: cb.stub_count('.s_4409', 0x367630, fields_base=0x367634))]
    if control_confirm:
        windows += [(0, 0x145020, 0x14503C, '.classlookup'),
                    (0, 0x16A63C, 0x16A640, '.deliverycontextpool'),
                    (2, 0x6406D8, 0x64070C, '.class9callback'),
                    (2, 0x640ED4, 0x640FF0, '.class9confirm'),
                    (3, 0x77F728, 0x77F780, '.classtable'),
                    (3, 0x77F97C, 0x77FA04, '.class9table')]
        stubs += [('.s_control_update', 0x633868, lambda: cb.stub_count('.s_control_update', 0x367640))]
    if navigation:
        stubs = [s for s in stubs if s[0] != '.s_select']
        windows = [w for w in windows if w[3] != '.class9confirm']
        windows += [(2, 0x640E64, 0x640FF0, '.class9navigation'),
                    (2, 0x641064, 0x6410D0, '.selectoriginal'),
                    (2, 0x641174, 0x641430, '.navigateoriginal')]
        stubs += [('.s_refresh', 0x145490, lambda: cb.stub_count('.s_refresh', 0x367648))]
    if menu_return_table:
        if return_purge_real:
            windows += [(0, 0x17BEE8, 0x17BFCC, '.returnpurge')]
        else:
            stubs += [('.s_return_queue_purge', 0x17BF60, lambda: cb.stub_count('.s_return_queue_purge', 0x367658, fields_base=0x36765C))]
        stubs += [('.s_return_timer', 0x149134, lambda: cb.stub_count('.s_return_timer', 0x36764C))]
    if time_window:
        assert window and table
        windows += [(4, 0x7D22F0, 0x7D2528, '.timehandlers'),
                    (5, 0x989CD8, 0x989D40, '.timedesc'),
                    (5, 0x899AD4, 0x899ADF, '.timeformat'),
                    (0, 0xD03E0, 0xD0408, '.timesetter'),
                    (0, 0xC979A, 0xC97A8, '.timeepilogue'),
                    (0, 0xDE19A, 0xDE1AA, '.timeparamepilogue'),
                    (0, 0xDE7B4, 0xDE7D0, '.timeparam'),
                    (0, 0xF6F0C, 0xF6F14, '.timebase')]
        stubs += [('.s_timeformat', 0x12CE54, lambda: cb.stub_count('.s_timeformat', 0x367750, fields_base=0x367754)),
                  ('.s_timetext', 0x633020, lambda: cb.stub_count('.s_timetext', 0x367764)),
                  ('.s_timerefresh', 0x145490, lambda: cb.stub_count('.s_timerefresh', 0x367768))]
        if not lifecycle_real:
            stubs += [('.s_timeresource', 0x145654, lambda: cb.stub_ret('.s_timeresource', 0x367610, 0x367614))]
        if not manager700:
            stubs += [('.s_timeopen', 0x1453E4, lambda: '.section .s_timeopen,"ax",@progbits\n mov r12,0x300800\n j_s [r12]\n'),
                      ('.s_timeopen_impl', 0x300800, lambda: cb.stub_count('.s_timeopen_impl', 0x367620, fields_base=0x367624))]
        if manager700 and not iso_confirm:
            stubs += [('.s_time4409', 0x16A29C, lambda: cb.stub_count('.s_time4409', 0x367630, fields_base=0x367634))]
    if iris_backend:
        windows += [(0, 0x18B788, 0x18B78C, '.irispool'),
                    (0, 0x18B85C, 0x18B8D4, '.irissetter')]
        stubs += [('.s_irisacquire', 0x235A1C, lambda: '''.section .s_irisacquire,"ax",@progbits
 mov r3,0x1234
 sth r3,[r1,0]
 mov r3,0x36772c
 ld r4,[r3,0]
 add r4,r4,1
 st r4,[r3,0]
 mov r3,0x367720
 ld r0,[r3,0]
 j_s [blink]
'''),
                  ('.s_irisguard', 0x235DA0, lambda: cb.stub_ret('.s_irisguard', 0x367730, 0x367724)),
                  ('.s_irisrequest', 0x235B0C, lambda: '''.section .s_irisrequest,"ax",@progbits
 mov r12,0x367744
 st r0,[r12,0]
 st r1,[r12,4]
 st r2,[r12,8]
 st r3,[r12,12]
 mov r12,0x367734
 ld r3,[r12,0]
 add r3,r3,1
 st r3,[r12,0]
 mov r12,0x367728
 ld r0,[r12,0]
 j_s [blink]
'''),
                  ('.s_irisrelease', 0x23524C, lambda: cb.stub_count('.s_irisrelease', 0x367738)),
                  ('.s_iriscleanup', 0x18B9D4, lambda: cb.stub_count('.s_iriscleanup', 0x36773C))]
    if menu_bridge:
        assert menu_model and window
        model_base = 0x3676A0 if manager700 else 0x367600
        stubs += [('.s_menu_bridge', 0x301000 if menu_return_table or color_model else 0x300800, lambda: f'''.section .s_menu_bridge,"ax",@progbits
.global menu_bridge_callback
menu_bridge_callback:
 push_s blink
 mov r3,{hex(model_base + 8)}
 ld r4,[r3,0]
 asl r5,r4,2
 add r5,r5,r3
 st r1,[r5,8]
 add r4,r4,1
 st r4,[r3,0]
 mov r0,{hex(model_base)}
 mov r2,{hex(model_base + 4)}
 {'mov r3,0x367660' if color_model else 'nop_s'}
 bl {'akeru_color_menu_event' if color_model else 'akeru_menu_defer_event'}
 pop_s blink
 j_s [blink]
''')]
    if specs is None:
        specs = []
        for order in [(0x16E588, 0x323A00), (0x323A00, 0x16E588)]:
            for gate in (0, 1):
                for classe, event in [(11, 0x580), (14, 0x700), (67, 0x2180), (78, 0x2700)]:
                    for state in (1, 0):
                        specs.append(case(classe, event + (1 - state), order, gate, len(specs), state=state))
            for gate, threshold in [(0, 130), (0, 131), (1, 130)]:
                specs.append(case(1, 0x80, order, gate, len(specs), threshold))
    result = dict(status='RUNNING', utc=stamp, cases=[], windows={},
                  limits=('V1.1; RAM e servizi sintetici; '
                          + ('post e ring originali; ' if queue else 'post e ring intercettati; ')
                          + ('callback, default e lookup condiviso originali, handler finali intercettati; ' if shared else 'callback e lookup originali, handler finale intercettato; ' if table else 'callback originale CaptureMenu, lookup 0x169f60 intercettato; ' if window else 'dispatcher originale, consegna 0x16a6e4 intercettata; ' if dispatch else '')
                          + ('handler 0x20eaf4 originale; getter fixture; ' if manager700 else 'handler 0x20eaf4 originale; getter e richiesta fixture; ' if handler700 else '')
                          + ('manager 0x1453e4/0x145180 originali; ' if manager700 else '')
                          + ('callback ISO 0x7d252c e servizi lifecycle 0x16a05c/0x16a188 stub; ' if lifecycle_stub else '')
                          + ('lifecycle e callback ISO originali; risorse e selezione stub; ' if lifecycle_real else '')
                          + ('conferma e setter ISO originali; 0x4409 intercettato; ' if iso_confirm else '')
                          + ('classe9 e generazione conferma originali; controllo sintetico; ' if control_confirm else '')
                          + ('selettore e navigazione lista originali; refresh stub; ' if navigation else '')
                          + ('handler 0x20e940 originale; query/cancel/notifica/richiesta fixture; ' if handler2180 else '')
                          + ('frammento soglia originale, ingresso e uscita sintetici; tabella e contesto fixture; ' if iso_threshold else '')
                          + ('0x18c90c originale, servizi intermedi fixture; ' if iso_threshold_apply else 'chiamata 0x18c90c intercettata, servizi intermedi fixture; ' if iso_threshold_call else '')
                          + ('eventi estratti consegnati al dispatcher, callback sintetico verso modello compilato; ' if menu_bridge else 'eventi estratti passati esplicitamente al modello menu compilato; ' if menu_model else '')
                          + ('descrittore e callback del menu sintetici; ' if menu_bridge else '')
                          + ('tabella destinazioni di ritorno sintetica; ' if menu_return_table else '')
                          + ('callback e modifica tempo originali, servizi di visualizzazione e apertura stub; ' if time_window else '')
                          + ('lettore snapshot originale su celle MMIO simulate, callback richiamato dal banco; ' if snapshot_input else '')
                          + ('setter iride originale, acquisizione e richiesta fixture; ' if iris_backend else '')
                          + ('catena testo originale chiamata dal banco, metriche e glifi fixture; ' if menu_text else '')
                          + 'ordine imposto; niente hardware; NON_INSTALLARE'))
    try:
        r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN,
                                   output=out, action='key-fanout-callbacks'))
        r.prepare()
        if menu_model:
            sources = [ROOT / 'AkeruOS/ui/menu.c']
            headers = [ROOT / 'AkeruOS/ui/menu.h']
            if menu_labels:
                sources.append(ROOT / 'AkeruOS/ui/menu_labels.c')
            if iris_backend:
                sources.append(ROOT / 'AkeruOS/camera/iris_action.c')
                headers.append(ROOT / 'AkeruOS/camera/iris_action.h')
            if color_model:
                sources += [ROOT / 'AkeruOS/ui/menu_color.c', ROOT / 'AkeruOS/camera/color_mode.c', ROOT / 'AkeruOS/camera/mono_raw.c']
                headers += [ROOT / 'AkeruOS/camera/color_mode.h', ROOT / 'AkeruOS/camera/mono_raw.h']
            result['model_sha256'] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources + headers}
            model_objects = []
            for i, source in enumerate(sources):
                model_obj = out / f'menu_{i}.o'
                assert r.command(f'compile_menu_{i}', ['arc-snps-elf-gcc', '-mcpu=arc700', '-mno-sdata', '-mlong-calls', '-O2', '-ffreestanding', '-fno-builtin', '-c', source, '-o', model_obj]).returncode == 0
                model_objects.append(model_obj)
            if color_model:
                libgcc = r.command('libgcc', ['arc-snps-elf-gcc', '-mcpu=arc700', '-mno-sdata', '-mlong-calls', '-print-libgcc-file-name'])
                assert libgcc.returncode == 0
                model_objects.append(libgcc.stdout.strip())
        for idx, spec in enumerate(specs):
            name = spec['name']
            asm = cb.harness(spec['extra']) + ''.join(gen() for _, _, gen in stubs)
            asm += cb.probe(spec['checks'], spec['success'], idx)
            source, obj = out / f'{name}.s', out / f'{name}.o'
            source.write_text(asm)
            assert r.command(f'{name}_as', [TOOLCHAIN / 'arc-elf32-as', '-mcpu=arc700', '-EL', '-o', obj, source]).returncode == 0
            objects = []
            for pidx, lo, hi, section in windows:
                assert cb.payload_of(blocks, lo) == pidx
                data = payloads[pidx][lo-bases[pidx]:hi-bases[pidx]]
                binary, bo = out / f'{name}_{section}.bin', out / f'{name}_{section}.o'
                binary.write_bytes(data)
                assert r.command(f'{name}_{section}_oc', [TOOLCHAIN / 'arc-elf32-objcopy', '-I', 'binary', '-O', 'elf32-littlearc', '-B', 'arc', '--rename-section', f'.data={section},alloc,load,readonly,code,contents', '--change-section-vma', f'.data={hex(lo)}', '--strip-all', binary, bo]).returncode == 0
                objects.append(bo)
                result['windows'][section] = hashlib.sha256(data).hexdigest()
            elf, ld = out / f'{name}.elf', out / f'{name}.ld'
            ld.write_text('ENTRY(_start)\nSECTIONS {\n .text 0x1000 : { *(.text .text.*) }\n'
                          + (' .modelrodata 0x302000 : { *(.rodata .rodata.*) *(.data.rel.ro.local*) }\n' if menu_labels else '')
                          + ''.join(f' {sec} {hex(lo)} : {{ *({sec}) }}\n' for _, lo, _, sec in windows)
                          + ''.join(f' {sec} {hex(addr)} : {{ *({sec}) }}\n' for sec, addr, _ in stubs)
                          + ''.join(f' {sec} {hex(addr)} (NOLOAD) : {{ . += {size}; }}\n' for sec, addr, size in cb.RAM_SECTIONS if sec != '.l26b')
                          + (' .scanctx 0x3678e0 (NOLOAD) : { . += 0x40; }\n' if scanner else ' .gate 0x3678f8 (NOLOAD) : { . += 8; }\n')
                          + ' .ctx 0x370664 (NOLOAD) : { . += 0x18; }\n'
                          + (' .hooks 0x367800 (NOLOAD) : { . += 0x18; }\n .queueidx 0x367bbc (NOLOAD) : { . += 0x14; }\n .queuerec 0x47a848 (NOLOAD) : { . += 0x600; }\n' if queue else '')
                          + (' .wmctx 0x366e94 (NOLOAD) : { . += 0x28; }\n' if manager700 else ' .current 0x366ea4 (NOLOAD) : { . += 12; }\n' if dispatch else '')
                          + (' .exclude 0x899858 (NOLOAD) : { . += 0x20; }\n' if table else '')
                          + (' .isobyte 0x365780 (NOLOAD) : { . += 0x10; }\n .isoparam 0x37fbd0 (NOLOAD) : { . += 0x30; }\n' if iso_confirm or time_window else '')
                          + (' .timework 0x899ac0 (NOLOAD) : { . += 0x14; }\n' if time_window else '')
                          + (' .state2180 0x365750 (NOLOAD) : { . += 0x20; }\n' if handler2180 else '')
                          + (' .thresholdram 0x37fbd0 (NOLOAD) : { . += 0x30; }\n .thresholdisobyte 0x365780 (NOLOAD) : { . += 0x10; }\n .thresholdisoindex 0x367bc8 (NOLOAD) : { . += 4; }\n' if iso_threshold else '')
                          + (' .returntable 0x370000 (NOLOAD) : { . += 0x314; }\n' if menu_return_table else '')
                          + (' .snapshotctx 0x366de8 (NOLOAD) : { . += 4; }\n' if snapshot_input else '')
                          + (' .irisstate 0x367fe8 (NOLOAD) : { . += 8; }\n' if iris_backend else '')
                          + (' .textflag 0x366868 (NOLOAD) : { . += 4; }\n .textmode 0x367f3c (NOLOAD) : { . += 4; }\n .textruntime 0x681b68 (NOLOAD) : { . += 8; }\n .textresults 0x500000 (NOLOAD) : { . += 0x100; }\n .textfixture 0x502000 (NOLOAD) : { . += 0x4200; }\n' if menu_text else '')
                          + f' .probe {hex(cb.PROBE_AT)} : {{ *(.probe) }}\n .log {hex(cb.LOG)} : {{ *(.log) }}\n .stack 0xC8F000 (NOLOAD) : {{ *(.stack) }}\n' + '}\n')
            assert r.command(f'{name}_ld', [TOOLCHAIN / 'arc-elf32-ld', '-EL', '-T', ld, '-o', elf, obj] + objects + (model_objects if menu_model else [])).returncode == 0
            ep, segments = elf_loads(elf)
            assert ep == 0x1000
            for pidx, lo, hi, _ in windows:
                seg = [s for s in segments if s['address'] <= lo and hi <= s['address'] + s['size']]
                assert len(seg) == 1 and seg[0]['data'][lo-seg[0]['address']:hi-seg[0]['address']] == payloads[pidx][lo-bases[pidx]:hi-bases[pidx]]
            if snapshot_input:
                (out / 'snapshot_mmio.bin').write_bytes(bytes(16))
            executed, _ = r.run(name, '/result/' + name + '.elf',
                                options=['--memory-mapfile', '/result/snapshot_mmio.bin', '--memory-region', '0xfe70224,8'] if snapshot_input else (),
                                trace=bool(spec.get('trace')))
            assert executed['exit_code'] == 11 and executed['fault']['operation'] == 'read' and int(executed['fault']['address'], 16) == spec['success'], (name, executed)
            if spec.get('trace'):
                trace = (out / f'{name}.trace').read_text().splitlines()
                executed_pcs = {line.split()[0] for line in trace if line.startswith('0x')}
                assert set(spec['trace']) <= executed_pcs, (name, spec['trace'])
                assert not set(spec.get('trace_absent', [])) & executed_pcs, (name, spec['trace_absent'])
                for pc, count in spec.get('trace_counts', []):
                    assert sum(line.startswith(pc + ' ') for line in trace) == count, (name, pc, count)
                for pc, fragment in spec.get('trace_values', []):
                    assert any(line.startswith(pc + ' ') and fragment in line for line in trace), (name, pc, fragment)
            result['cases'].append(dict(name=name, fault=executed['fault'], checks=spec['checks'],
                                        trace=spec.get('trace', []), trace_absent=spec.get('trace_absent', []),
                                        trace_counts=spec.get('trace_counts', []), trace_values=spec.get('trace_values', [])))
            print('PASS', name, flush=True)
        result['status'] = 'PASS'
    except Exception as exc:
        result['status'] = 'FAIL'
        result['error'] = repr(exc)
        raise
    finally:
        out.mkdir(parents=True, exist_ok=True)
        (out / 'verified_evidence.json').write_text(json.dumps(result, indent=2) + '\n')
        print('Evidence:', out, flush=True)


if __name__ == '__main__':
    main()
