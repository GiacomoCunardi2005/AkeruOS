#!/usr/bin/env python3
"""Join separately qualified register evidence without promoting it to hardware."""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path


def load(path):
    return json.loads(path.read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    out = args.directory.resolve()
    evidence = out/'evidence'
    inventory = load(out/'inventory.json')
    architecture = load(evidence/'cpu_aux_catalog.json')
    mmio = load(evidence/'mmio_documented.json')
    trace = load(evidence/'firmware_aux_trace.json')
    metadata = load(out/'atlas_metadata.json') if (out/'atlas_metadata.json').exists() else {}
    atlas_date = metadata.get('date', architecture['date'])
    static_aux = load(evidence/'aux_firmware_expansion.json') if (evidence/'aux_firmware_expansion.json').exists() else {}
    extra = load(evidence/'cpu_aux_extended.json') if (evidence/'cpu_aux_extended.json').exists() else {}
    mmio_families = load(evidence/'mmio_parametric_families.json') if (evidence/'mmio_parametric_families.json').exists() else {}
    mmio_windows = load(evidence/'mmio_transfer_windows.json') if (evidence/'mmio_transfer_windows.json').exists() else {}
    mmio_overlaps = load(evidence/'mmio_window_overlaps.json') if (evidence/'mmio_window_overlaps.json').exists() else {}
    records = list(architecture['records'])
    by_key = {(r['space'], r['number']): r for r in records}
    for record in extra.get('records', []):
        key = (record['space'], record['number'])
        if key in by_key:
            # Keep independent assertions and their provenance. Never silently
            # overwrite conflicting names, access modes or bit definitions.
            by_key[key].setdefault('additional_documentation', []).append(record)
        else:
            records.append(record);by_key[key] = record
    for resolved in static_aux.get('resolved_custom_indices', []):
        index = int(resolved['index'], 0)
        key = ('aux', index)
        if key not in by_key:
            record = dict(space='aux',number=index,number_hex=hex(index),
                          name=f"CUSTOM_channel{resolved['channel']}_offset{resolved['offset']}",
                          width_bits=32,access='static_firmware_access_see_callee_proof',
                          classification='firmware_static_custom_index_resolved',
                          sources=[dict(file=str(evidence/'aux_firmware_expansion.json'),line=1)],
                          bit_fields=[],hardware_verified=False,
                          emulator_status='outside_2048_slot_model_bank')
            records.append(record);by_key[key]=record
        by_key[key].setdefault('firmware_static_index_proofs',[]).append(resolved)
        by_key[key]['firmware_static_access_confirmed']=True
    for site in static_aux.get('documented_register_sites', []):
        key=('aux',int(site['index'],0))
        if key not in by_key:
            record=dict(space='aux',number=key[1],number_hex=site['index'],
                        name=site.get('name','/'.join(site.get('aliases',[]))) or 'UNKNOWN',
                        width_bits=32,access='static_firmware_access_see_proof',
                        classification='firmware_static_access_toolchain_name_only',
                        sources=[],bit_fields=[],hardware_verified=False)
            records.append(record);by_key[key]=record
        by_key[key].setdefault('firmware_static_access_sites',[]).append(site)
        by_key[key]['firmware_static_access_confirmed']=True
    custom_cfg=load(evidence/'custom_aux_cfg.json')if(evidence/'custom_aux_cfg.json').exists()else{}
    dispatch_contract=load(evidence/'dispatch_contract.json')if(evidence/'dispatch_contract.json').exists()else{}
    for item in custom_cfg.get('qualified_indices',[]):
        index=int(item['index'],0);key=('aux',index)
        if key not in by_key:
            record=dict(space='aux',number=index,number_hex=hex(index),name=f'CUSTOM_AUX_{index:X}',
                        width_bits=32,access='/'.join(sorted({p['operation']for p in item['proofs']})),
                        classification='firmware_call_anchored_local_cfg_static',hardware_verified=False,
                        emulator_status='outside_2048_slot_model_bank_not_executed',bit_fields=[],
                        sources=[dict(file=str(evidence/'custom_aux_cfg.json'),line=1)],
                        notes=['Width refers to LR/SR operand; physical implementation and semantics unknown.',
                               'Caller/code boundary and local CFG are static evidence; global reachability and branch feasibility unproved.'])
            records.append(record);by_key[key]=record
        record=by_key[key]
        record['firmware_static_access_confirmed']=True
        record['firmware_custom_cfg_access_sites']=sorted({p['pc']for p in item['proofs']})
        record['firmware_custom_cfg_entries']=sorted({p['entry']for p in item['proofs']})
        record['firmware_custom_cfg_proof_file']=str(evidence/'custom_aux_cfg.json')
        if custom_cfg.get('cpu_verified_callback_anchor'):
            entries={hex(a['target'])for a in custom_cfg['cpu_verified_callback_anchor']['anchors']}
            if any(p['entry']in entries for p in item['proofs']):
                record['cfg_callback_target_cpu_support']=str(evidence/'register_dual_callback_cpu.json')
                record['sources'].append(dict(file=str(evidence/'register_dual_callback_cpu.json'),line=1))
                if record['classification']=='firmware_call_anchored_local_cfg_static':record['classification']='firmware_cpu_bound_callback_target_local_cfg_static'
        if dispatch_contract and index in [0x10001,0x10110,0x10111]:
            record['sources'].append(dict(file=str(evidence/'dispatch_contract.json'),line=1))
            record['software_dispatch_contract_file']=str(evidence/'dispatch_contract.json')
            if index==0x10001:
                record['software_dispatch_bits']=dispatch_contract['dispatch_bits']
                record['structural_bit7_accessor']=dispatch_contract['unreferenced_bit7_accessor']
                record['bit_fields'] += [dict(name=f"software_dispatch_bit{d['bit']}",lsb=d['bit'],msb=d['bit'],
                                              callback_slot=d['slot'],physical_meaning='unknown',source_file=str(evidence/'dispatch_contract.json'))for d in dispatch_contract['dispatch_bits']]
            else:
                record['software_callback_branches']=dispatch_contract['branches']
                bits=[14,15]if index==0x10111 else[0,1]
                record['bit_fields'] += [dict(name=('software_callback_gate'if index==0x10111 else'software_test_then_set')+str(bit),
                                              lsb=bit,msb=bit,physical_meaning='unknown',source_file=str(evidence/'dispatch_contract.json'))for bit in bits]
                record.setdefault('notes',[]).append('Software RMW and callback dependencies do not establish W1C, acknowledgment or physical side effects.')
        if custom_cfg.get('cpu_verified_indirect_anchors'):
            indirect_entries={hex(a['target'])for a in custom_cfg['cpu_verified_indirect_anchors']['anchors']}
            if any(p['entry']in indirect_entries for p in item['proofs']):
                record['cfg_indirect_target_cpu_support']=str(evidence/'register_indirect_cpu.json')
                record['sources'].append(dict(file=str(evidence/'register_indirect_cpu.json'),line=1))
                if record['classification']=='firmware_call_anchored_local_cfg_static':
                    record['classification']='firmware_cpu_bound_indirect_target_local_cfg_static'
            if index in [0x10803,0x10903,0x10a03,0x10b03,0x10c03]:
                record['bit_fields'].append(dict(name='software_low2_replaced_with1_in_handler_branch',lsb=0,msb=1,
                                                 physical_meaning='unknown',source_file=str(evidence/'custom_aux_cfg.json')))
            if index==0x10036:
                record['bit_fields'] += [dict(name=f'software_selected_byte_{i}',lsb=i*8,msb=i*8+7,
                                              selector=i,physical_meaning='unknown',source_file=str(evidence/'custom_aux_cfg.json'))for i in range(4)]
            if index==0x10037:
                record['bit_fields'].append(dict(name='software_selector_set_clear_bits',lsb=0,msb=3,
                                                 physical_meaning='unknown',source_file=str(evidence/'custom_aux_cfg.json')))
        if custom_cfg.get('cpu_verified_millicode_return'):
            functions={f['entry']:f for f in custom_cfg['functions']}
            if any(any(0x33413c<=d['pc']<0x3341e4 for d in functions[p['entry']]['instructions'])for p in item['proofs']):
                record['cfg_shared_return_cpu_support']=str(evidence/'millicode_return_cpu.json')
                record['sources'].append(dict(file=str(evidence/'millicode_return_cpu.json'),line=1))
        if index in [0x10030,0x10032,0x10034]:
            record['bit_fields'].append(dict(name='software_low_nibble_argument_field',lsb=0,msb=3,
                                              operation='preserve_upper28_replace_low4',physical_meaning='unknown',
                                              source_file=str(evidence/'custom_aux_cfg.json')))
    by_aux = {}
    for run in trace['runs']:
        for event in run['semantic_result_observed_records']:
            by_aux.setdefault(event['aux_index'], []).append(dict(run=run['name'], **event))
    names = {}
    for definition in inventory['aux_definitions']:
        names.setdefault(definition['index'], []).append(definition['name'])
    for number in by_aux:
        if ('aux', number) not in by_key:
            record = dict(space='aux', number=number, number_hex=hex(number),
                          name='/'.join(dict.fromkeys(names.get(number, []))) or 'UNKNOWN',
                          width_bits=32, access='unknown_physical',
                          classification='firmware_guest_access_toolchain_name_only', sources=[],
                          bit_fields=[], hardware_verified=False)
            records.append(record);by_key[('aux', number)] = record
    for record in records:
        if record['space'] == 'aux':
            index = record['number']
            events = by_aux.get(index, [])
            record['firmware_observed'] = bool(events)
            if events and record['classification'] == 'simulator_probe_only':
                record['prior_catalog_assertion'] = {k:record.get(k) for k in ['name','classification','notes']}
                record['classification'] = 'firmware_guest_access_toolchain_name_only'
                record['name'] = '/'.join(dict.fromkeys(names.get(index, []))) or record['name']
                record['notes'] = ['Fresh original-firmware guest traces supersede the earlier probe-only classification; toolchain naming does not establish physical semantics.']
            record['firmware_trace_record_count'] = len(events)
            record['firmware_trace_sites'] = sorted({e['pc_hex'] for e in events})
            record['firmware_trace_values'] = sorted({e['trace_value_hex'] for e in events})
            record['trace_value_warning'] = 'SR values are setter operands, not guaranteed post-mask state; trace is not retirement proof.'
            record['toolchain_aliases'] = list(dict.fromkeys(names.get(index, [])))
            candidates = inventory['aux_candidate_groups'].get(hex(index), [])
            record['linear_candidate_count'] = len(candidates)
    for record in mmio['records']:
        normalized=dict(record)
        normalized.update(space='soc_mmio',number=int(record['address'],16),
                          number_hex=record['address'],name=record['subsystem'],
                          classification=record['confidence'])
        records.append(normalized)
    keys = [(r['space'], r['number']) for r in records]
    assert len(keys) == len(set(keys))
    assert all(r['hardware_verified'] is False for r in records)
    counts = Counter(r['space'] for r in records)
    gaps = [g for g in architecture['gaps']
            if 'must be joined from independent inventory' not in g
            and 'Cache/debug/performance' not in g] + list(extra.get('gaps', [])) + [
        'AUX guest traces cover boot prefixes and explicitly seeded isolated callers; other firmware paths remain unobserved.',
        'Nikon physical extension/BCR values, custom register assignments and hardware reset state are unknown.',
        'Cache/debug/performance reference definitions are added, but their optional Nikon implementations are unverified.',
        ('Initial pool-only MMIO candidates now have access evidence; whole-firmware MMIO coverage beyond this starting set remains unproven.'
         if mmio['counts']['literal_only_candidates']==0 else
         'Most linear AUX candidates and remaining pool-only MMIO candidates lack CFG/access confirmation.'),
        'TBIB whole-payload linear disassembly was rejected by the existing OOB guard; its bytes were not padded or truncated.',
        'Physical MMIO semantics, FIFO/W1C behavior, IRQ delivery, timing and DMA/cache effects require independent evidence.',
        'The generic libsim host AUX accessor differs from the guest ARC700 accessor; do not scan unknown AUX through the host API.',
        'The retained REA6.7 probe exposes207tools but rejectsARC ELF admission; no connected IDA backend forARC is established by this atlas.'
    ]
    result = dict(schema='akeruos_register_atlas_v1', date=atlas_date,
                  status='INCOMPLETE_PHYSICAL_MAP', goal_complete=False,
                  firmware_sha256=mmio['firmware_sha256'], counts=dict(counts),
                  aux_indices_with_guest_semantic_records=sorted(by_aux),
                  hardware_verified_registers=0, records=records,
                  non_target_or_unproven_variants=extra.get('non_target_or_unproven_variants', []),
                  custom_aux_families=static_aux.get('custom_families',[]),
                  computed_mmio_families=mmio_families.get('families',[]),
                  mmio_transfer_windows=mmio_windows.get('windows',[]),
                  mmio_window_overlaps=mmio_overlaps,
                  metadata=metadata,
                  evidence_files=[str(p.relative_to(out)) for p in sorted(evidence.iterdir()) if p.is_file()],
                  gaps=gaps,
                  limits='Documentation, static candidates, guest execution, fixture behavior and hardware are distinct evidence layers.')
    (out/'register_map.json').write_text(json.dumps(result, indent=2)+'\n')
    with (out/'register_map.csv').open('w', newline='') as handle:
        writer = csv.writer(handle)
        writer.writerow(['space','number','name','classification','width_bits','access','guest_aux_records','hardware_verified'])
        for r in records:
            writer.writerow([r['space'],r['number_hex'],r['name'],r['classification'],r.get('width_bits'),r.get('access'),r.get('firmware_trace_record_count',0),False])
    lines = ['# Mappa registri ARC700 / Nikon COOLPIX S33', '',
             atlas_date+' — **mappa fisica incompleta; obiettivo ancora attivo.**', '',
             f"{counts['core']} posizioni core, {counts['aux']} indici AUX consolidati, {counts['soc_mmio']} indirizzi MMIO esaminati.",
             f"Il firmware originale ha prodotto risultati semantici LR/SR su **{len(by_aux)} AUX** nelle tracce GNU fresche. Nessun registro fisico è stato verificato.", '',
             'Le 64 posizioni core includono slot opzionali, riservati e encoding speciali: non sono 64 registri fisici provati.', '',
             '## Evidenze e copertura', '',
             '- [Mappa JSON](register_map.json), [tabella CSV](register_map.csv), [grafo delle fonti](graph.html).',
             '- [Censimento dei 16 payload e TBIB](inventory.json): ogni overlay ha un namespace distinto. Il censimento di parole numeriche non prova MMIO.',
             '- [Tracce AUX firmware](evidence/firmware_aux_trace.json): byte ELF confrontati con il contenitore originale; i valori SR sono input del setter.',
             '- [Verifiche emulatore](evidence/emulator_checks.json): 24 casi AUX, 6 test monitor e harness API; [29 casi di provenienza e boot](evidence/firmware_aux_trace.json).',
             '- [61 probe core r0–r60](evidence/core_guest_checks.json): valori distinti e due sentinelle conservate per ciascun caso; slot opzionali del modello distinti dal silicio Nikon.',
             '- [66 controlli esatti sensore](sensor_field_verification/sensor_aligned_audit.json), con finestre riallineate dopo i literal pool.', '',
             '## Correzioni rispetto alle sintesi storiche', '',
             '- FF98074: RESET e INIT usano bit 8, 2, 3, 6, 7.',
             '- La sequenza 1/80/100/200/800/1000 esadecimale scrive FF98018, non FF98000.',
             '- INIT FF98000 comprende il bit10; FE800F4 cancella il bit4.',
             '- Il cluster DEVNAND conserva attribuzione storage; i vecchi nomi ottici sono ritirati.',
             '- FE50920/FE50010 nel test cancel sono argomenti a helper sostituiti da fixture, non MMIO fisico dereferenziato.',
             '- API AUX512 host: arresto unknown, mentre il guest ARC700 ammette il suo reset. STATUS32 setter host accettato può non cambiare il valore.', '',
             ]
    if metadata.get('mmio_candidates_promoted'):
        lines += ['## Espansione verificata', '',
                  f"Candidati da pool: **{metadata['mmio_candidates_before']} → {metadata['mmio_candidates_after']}**; {metadata['mmio_candidates_promoted']} indirizzi promossi con nuove prove.", '',
                  '- [Audit CFG banco ausiliario](evidence/auxbank_expansion.json): 38 candidati risolti, 47 indirizzi con 169 accessi statici e maschere software.',
                  '- [Confronto indipendente dei 470 accessi sensore](independent_observer_comparison.json): tuple PC/indirizzo/operazione/larghezza/valore identiche; tracce guest byte-identiche.',
                  '- [Osservatore sensore](evidence/observer_sensor.json) e [osservatore dei 12 registri di avvio](evidence/observer_boot.json): frontend esterno, librerie GNU in sola lettura.',
                  '- Le fixture mutate dal primo run vengono ripristinate dai valori iniziali registrati nel manifest, senza ricavarli dalla traccia da confrontare.',
                  '- [AUX custom e siti IDENTITY/cache](evidence/aux_firmware_expansion.json): 19 indici custom concreti oltre 2047, con chiamanti e argomenti risolti staticamente. Non eseguiti nel banco GNU attuale.',
                  '- IDENTITY viene confrontato dal software con 0x13030513; questo non è un valore letto dall’hardware.', '',
                  '### Famiglie AUX parametrizzate', '',
                  '| Formula | Copertura e limiti |', '|---|---|']
        for family in static_aux.get('custom_families',[]):
            detail=family.get('unknown') or family.get('meaning','')
            lines.append(f"| {family['expression']} | {detail} |")
        if metadata.get('total_sensor_observer_events'):
            lines += ['',f"Accessi sensore osservati complessivamente: **{metadata['total_sensor_observer_events']}**; tutti i 115 candidati iniziali hanno ora prove di accesso.",
                      'Le prove aggiuntive comprendono RAM flag0x681145=1 dichiarato dal chiamante sintetico. Non è uno stato Nikon misurato.',
                      'FF900E0 ha un read16 con risultato prima di un arresto successivo su RAM non dichiarata: la routine completa resta non provata.',
                      'Nuove celle FF98068/B4/C4 provengono da accessi effettivi del codice; la loro presenza non era coperta dal solo censimento dei literal pool.','']
    if custom_cfg:
        lines += ['', '## AUX custom: chiamate e CFG statici', '',
                  f"**{len(custom_cfg['qualified_indices'])} indici** con accessi espliciti verificati in tre finestre Main; {metadata.get('new_custom_aux_cfg_indices',0)} nuove voci rispetto all’atlante precedente.",
                  '- [Prova CFG e chiamanti](evidence/custom_aux_cfg.json), [controllo estrazione chiamate contro tracce GNU](evidence/guest_call_decoder_audit.json).',
                  '- Esclusi richiami apparenti dentro gli immediati lunghi tramite controllo indipendente dei confini; gli altri candidati restano separati.',
                  '- Le chiamate e i percorsi sono statici: raggiungibilità globale e fattibilità dei rami non provate. AUX fuori dal banco GNU non eseguiti.',
                  '- AUX10030/10032/10034: il software conserva i28bit alti e sostituisce il nibble basso; significato fisico ignoto.', '']
        if metadata.get('millicode_cpu_cases'):
            lines += [f"Epiloghi condivisi originali: **{metadata['millicode_cpu_cases']} casi CPU**, {metadata['millicode_cpu_instructions']} istruzioni; ripristino di registri, SP e ritorno verificati con frame sintetici.",
                      '- [Prove CPU degli epiloghi](evidence/millicode_return_cpu.json): nessun AUX custom eseguito; il supporto al ritorno completa i CFG di16indici precedentemente non qualificati.',
                      '- Corretto BXOR: è un’operazione sui bit, non un salto. La ricostruzione ora prosegue dopo0x33A9B8.', '']
        if metadata.get('indirect_anchor_cpu_cases'):
            lines += ['### Puntatori e target indiretti', '',
                      '- [Prove CPU](evidence/register_indirect_cpu.json):13casi,4completati e9stop attesi prima di letture AUX fuori banco. Nessun nuovo risultato LR/SR custom.',
                      '- Registrazione callback originale339404→342E88→RAM360AD8=339CDC; il chiamante sintetico rilegge il puntatore e raggiunge il primo LR, fermato dalla guardia.',
                      '- Caller originali33B7F6 e342E34 legano i target342D20 e342DE4. Selettori0..3 raggiungono i siti attesi; selettore4 ritorna senza AUX.',
                      '- CPU, registrazione e calcolo dei salti supportano le ancore; i campi AUX rimangono deduzioni statiche, senza periferica o IRQ fisico.', '']
        if metadata.get('dual_callback_cpu_cases'):
            lines += ['### Contratto software tra AUX10001/10110/10111', '',
                      '- [Tre nuovi casi CPU](evidence/register_dual_callback_cpu.json):2registrazioni complete,1stop prima di LR10111. Constructor342868 registra3428B8 inRAM360AE0; API3428B0 imposta il callback utente inRAM360AD0.',
                      '- [Contratto statico](evidence/dispatch_contract.json):sette bit10001 selezionano slot RAM;10111bit15/14 condizionano10110bit1/0, flagRAM+5/+4 e argomenti callback1/0.',
                      '- Le trasformazioni dei registri e dei flag del gestore sono statiche. Nessun effetto W1C/IRQ/reset dedotto; il bit7 ha solo un accessor strutturale fuori dal dispatch analizzato.', '']
    if metadata.get('fe1_observed_addresses'):
        lines += ['', '## Blocco FE100xx e registri core opzionali', '',
                  f"**{metadata['fe1_observed_addresses']} nuovi indirizzi**, accesso halfword; **{metadata['fe1_observer_events']} scritture** da quattro routine originali, più due casi core/AUX: sei replay con tracce byte-identiche.",
                  '- [Prove FE1](evidence/fe1_register_window.json), [osservatore indipendente](evidence/observer_fe1.json).',
                  '- AUX0x18 letto dal codice originale a0x2931BC con seed esplicito0x01000000; r55 iniziale0x55667788 è anch’esso sintetico.',
                  '- r46/r51/r55/r59: uso software osservato in slot già censiti; nessun significato fisico delle estensioni dedotto.',
                  '- Celle MMIO con semantica storage; nessun completamento periferica, DMA o IRQ modellato.',
                  '- [Provenienza famiglia AUX10010](evidence/aux10010_argument_proof.json): indice dipendente da una tabella runtime, senza promuovere tutti i valori possibili a registri implementati.', '']
    if metadata.get('direct_mmio_new_addresses'):
        lines += ['', '## Sequenza MMIO diretta178D08', '',
                  '- [Prova CPU e fixture](evidence/direct_mmio_sequence.json), [audit indipendente byte/tracce](evidence/direct_mmio_step_audit.json).',
                  '- 22nuovi indirizzi halfword,483eventi nei tre scenari completati; due negativi si fermano al budget. Cinque coppie con tracce identiche, osservatore acceso/spento.',
                  '- Transizioni della fixture separate dagli accessi firmware: bit4FE20008 prima del poll; FFE2014C azzerato nel secondo passaggio dei casi repeat. Nessun timing hardware verificato.',
                  '- Le righe MMIO della traccia a passi sono duplicate; le scritture possono apparire sign-extended. Eventi dell’osservatore e larghezza16 sono verificati indipendentemente.',
                  '- Indirizzi FFE e FE mantenuti distinti; alias fisici ignoti. DC_CTRLbit8 è controllato con seed0/100hex espliciti.', '']
    if metadata.get('remaining_direct_mmio_new_addresses'):
        lines += ['', '## Accessi diretti e percorsi dei vettori', '',
                  '- [Dieci scenari CPU](evidence/remaining_direct_mmio.json), [audit byte/tracce](evidence/remaining_direct_mmio_audit.json):18 eventi halfword e dieci replay identici.',
                  '- Cinque nuovi indirizzi: FEF000C, FEF0050, FEF00E8, FEF00F8 e FEF0328. I quattro candidati rimasti del censimento ristretto sono ora documentati; FEF0328 è emerso da una finestra riallineata.',
                  '- Il censimento iniziale basso diretto è coperto47/47; questo denominatore non misura il processore o tutto il firmware.',
                  '- FEF0050bit6 e FEF0328bit4 selezionano un percorso con RMW che azzera bit0 di FEF00E8/FEF00F8. Nomi fisici, W1C e riconoscimento IRQ ignoti.',
                  '- Stato RAM, base vettori, ilink e SP salvato sono fixture esplicite. Il ritorno del percorso selezionato non prova un ciclo completo di interruzione hardware.',
                  '- AUX0x47 ha un risultato SR originale: operand1, non verifica dello stato cache o del valore dopo il setter.', '']
    if metadata.get('fe6_computed_new_addresses'):
        lines += ['', '## Famiglia MMIO FE6 con indirizzo calcolato', '',
                  '- [Prova CPU](evidence/fe6_computed_registers.json), [audit byte/indirizzi](evidence/fe6_computed_registers_audit.json):96 indirizzi,530 accessi e tre coppie di tracce identiche.',
                  '- Sei accessor originali usano i selettori20..33hex e40..43hex: FE60000+16*selettore con offset0,4,8,C. Il chiamante sintetico esercita tutti24 i valori accettati; non prova i valori usati dai chiamanti Nikon o la presenza fisica di ogni cella.',
                  '- [Chiamanti originali statici](evidence/fe6_original_callers.json):otto chiamate condizionate con selettori letterali24/2C/33hex; il wrapper239F2C inoltra un parametro dopo i controlli di intervallo. La condizione di modo e la raggiungibilità runtime non sono state osservate.',
                  '- Otto selettori negativi,64 chiamate: nessun accesso MMIO. SP e r13/r14/r15 verificati dopo ogni chiamata.',
                  '- Offset0: scrittura di campi e RMW dei bit10..15; offset4: setterbit8 e getterbit9 distinti; offset8/C: due scritture halfword. Scrittura speciale offset8 solo selettore29hex.',
                  '- Seed MMIO0/FFFF/A55A e argomenti sono fixture esplicite; nessuna semantica hardware/IRQ/reset/temporizzazione dedotta.', '']
    if metadata.get('fe6_original_loop_new_addresses'):
        lines += ['', '## Ciclo FE6 e produttore della modalità originali', '',
                  '- [Prova CPU](evidence/fe6_original_loop.json), [audit indipendente](evidence/fe6_original_loop_audit.json):11 scenari,208 accessi,11 coppie di tracce identiche.',
                  '- Il firmware originale1F0980 calcola la cache modalità da quattro ingressi MMIO espliciti;1F0A6C legge il risultato. Flag e RAM cache sono fixture dichiarate, non stato fisico Nikon.',
                  '- Sei scenari attraversano il ciclo239F00:28 scritture ciascuno a FE60010..FE601C0, passo16, selettori1..28 prodotti dal codice originale. Campi scritti12..13, altri bit zero.',
                  '- Nuove letture:FEF0020,FE800BC,FED3000,FED3800. Gate softwareBCbits10..11 e3000bits14..15 modificano il ramo di riempimento cache; nessun nome/ID fisico dedotto.',
                  '- Il chiamante23A270 raggiunge setter/getter e scrittore del selettore24hex. Statusbit9 inizialmente impostato dalla fixture, senza effetto hardware bit8→bit9.',
                  '- Modalità1/3/4 e ingresso non riconosciuto provati: il ciclo dei28 registri viene saltato. Ritorno, SP e r13..r16 verificati.', '']
    if metadata.get('fe6_second_bank_new_addresses'):
        lines += ['', '## Seconda famiglia FE6', '',
                  '- [Prova CPU](evidence/fe6_second_bank.json), [audit indipendente](evidence/fe6_second_bank_audit.json):76 nuovi indirizzi,540 accessi,quattro coppie identiche.',
                  '- Selettori34..3Dhex e44..4Chex: FE64000+16*selettore con offset0,4,8,C. Otto selettori negativi provati senza accessi.',
                  '- Lo scrittore completo dell’offset0 usa bit0..1 e10..15; gli altri sono zero. Il RMW separato conserva0..9. Setterbit8 e getterbit9 restano distinti.',
                  '- Scrittura speciale offset8 solo per4A/4C; offsetC compone bit15 e0..13,bit14zero.',
                  '- Il wrapper originale239F2C completa19 invocazioni; il produttore modalità è originale ma raw/cache/flag e statusbit9 iniziale sono fixture esplicite. Nessuna configurazione o temporizzazione fisica verificata.', '']
    if metadata.get('fe6_controls_mode1_new_addresses'):
        lines += ['', '## Controlli FE6, tabelle modalità1 e limiti firmati', '',
                  '- [Prova CPU](evidence/fe6_controls_mode1.json), [audit di ambito](evidence/fe6_controls_mode1_audit.json):42 indirizzi nuovi,720 eventi ordinari,8 di alias aritmetico e2 tentativi senza risultato; sette coppie di tracce identiche.',
                  '- Rami non negativi dei controlli:selettori0/1/2/4,offset0/4/8. Setterbit1/2/3,RMWbit0/4,maskstatusbit4 e restituzione low15+bit15 tramite byte RAM.',
                  '- Due tabelle modalità1:24 celle daFE60100 e12 daFE64000,passo4; RMWbits12..13. Sei celle avevano già altre prove,30 sono nuove.',
                  '- Il limite signed<=2 non impone un minimo:80000000/80000001 accedono agli stessi indirizzi dei selettori0/1 tramite overflow32bit. Non è una relazione di alias fisico.',
                  '- FFFFFFFF e80000004 raggiungono letture non mappate FE645E0/FE64680: solo tentativi, non registri accessibili o difetti hardware provati. Questi indirizzi sono esclusi dalla promozione.',
                  '- Cache modalità e MMIO sono fixture; non è dimostrato che i chiamanti Nikon usino selettori negativi.', '']
    if metadata.get('fe6_indexed_nominal_new_addresses'):
        lines += ['', '## FE6: controlli e famiglie con indice irrisolto', '',
                  '- [CPU](evidence/fe6_indexed_families.json), [audit](evidence/fe6_indexed_families_audit.json), [formule](evidence/mmio_parametric_families.json). Sei nuovi indirizzi dei rami non negativi0..2;114eventi nominali e12alias aritmetici separati.',
                  '- Due famiglie indicizzate documentate senza ammettere registri concreti:84 scritture di esempio con indice libero, non un censimento di celle fisiche.',
                  '- 2C6B74:baseFE64680 se r0zero,altrimentiFE646D0; aggiunge4*r1 in32bit. 2C6C70:baseFE648D0+256*r0+4*r1,guard signed(r0)<=2 senza minimo.',
                  '- Entrambe scrivono bit15 uguale0 se r2==1,altrimenti1; low12 da r3,bit12..14zero. I domini dei chiamanti restano ignoti.',
                  '- Censimento BL a halfword e puntatori LE/ME in16payload senza candidati verso sei entry; riferimenti calcolati e tail branch non sono esclusi.',
                  '- Sei coppie di tracce identiche; un tentativo non mappato aFE647C0 non viene promosso a registro. Nessuna semantica fisica verificata.', '']
    if metadata.get('ff7_transfer_windows'):
        lines += ['', '## Finestre di scrittura FF7', '',
                  '- [Prova CPU](evidence/ff7_transfer_windows.json), [audit buffer/byte/tracce](evidence/ff7_transfer_windows_audit.json), [finestre](evidence/mmio_transfer_windows.json).',
                  '- Cinque finestre:due da1024 celle e tre da256,2816 offset osservati con stride4 e store16. Sono rappresentate come regioni, non2816 registri di controllo indipendenti.',
                  '- Venti scenari/quaranta run,5732 eventi e20coppie di tracce identiche;18 nuovi controlli/parametri associati ammessi come indirizzi singoli.',
                  '- Flag nonzero salta bulk e RMW controllo, ma scrive ancora tre parametri. Gli inputbyte vengono trasferiti come halfword con valore high8zero.',
                  '- Buffer, controlseed e backing delle finestre sono fixture; nessun reset/permesso/funzione periferica o significato dei gap dedotto.',
                  '- Dieci siti run/PC SR originali LP_START/LP_END aggiunti; gli operandi SR non sono verifica dello stato AUX dopo il setter. Stdout/stderr conservati separati per integrità degli eventi.', '']
    if metadata.get('ff7_packed_writers'):
        lines += ['', '## Tabelle FF7 impacchettate e parametri', '',
                  '- [Prova CPU](evidence/ff7_packed_tables.json), [audit indipendente](evidence/ff7_packed_tables_audit.json):8 writer,34 scenari/68run,678eventi,34coppie di tracce identiche.',
                  '- Questo passo aggiunge cinque finestre da17celle,85offset; nessuna promozione delle celle a controlli indipendenti.',
                  '- Primi16elementi: coppie halfword mascherate7bit, byte alternati o byte contigui. Il17esimo viene copiato separatamente senza maschera7bit.',
                  '- Ventidue nuovi parametri singoli; FF74000 arricchito con setter bit5/6 che impostano solo per argomento1, altrimenti azzerano.',
                  '- Gli OR(arg0,arg1<<4) e OR(arg2,arg1<<10) troncano la halfword completa, senza maschere indipendenti dei campi. Input larghi provati come comportamento software, non come API hardware sicura.',
                  '- Sedici siti SR LP_START/LP_END aggiunti:100siti totali,22indici guest. Input,seed e backing restano fixture; nomi/reset/effetti fisici e domini Nikon non provati.', '']
    if metadata.get('ff7_raw_ffb_new_scalars'):
        lines += ['', '## Tabelle FF7 dirette, coppie FFB e sovrapposizioni software', '',
                  '- [CPU](evidence/ff7_raw_ffb_pairs.json), [audit](evidence/ff7_raw_ffb_pairs_audit.json):32scenari/64run,1012eventi,32coppie di tracce identiche. Venticinque nuovi indirizzi singoli:23FFB e2parametriFF7.',
                  '- Sei nuove finestre raw da12/17/33/33/9/9halfword. Al checkpoint di quel passo:16finestre,3014offset sommati,2982indirizzi unici;le32ripetizioni non sono nuovi registri.',
                  '- FF74088 è parametro finale nel writer impacchettato e indice17 nel writer raw33. [Relazioni esplicite](evidence/mmio_window_overlaps.json):stesso indirizzo software, nessun alias fisico dedotto.',
                  '- Nove setter FFB dividono argomento32bit:prima high13 nella cella+4,poi low16 nella cella base. Getter separati leggono16bit completi nel backing sintetico, anche prima della scrittura.',
                  '- Centododici siti AUX verificati,22indici guest. Domini dei chiamanti Nikon, MMIO fisico, reset/IRQ/timing ancora aperti.', '']
    if metadata.get('ffb_packed_ffc_new_scalars'):
        lines += ['', '## Controlli FFB impacchettati e accessi FFC', '',
                  '- [CPU](evidence/ffb_packed_ffc.json), [audit indipendente](evidence/ffb_packed_ffc_audit.json):98 entry originali,16 scenari/32run,1576 accessi halfword e16 coppie di tracce identiche.',
                  '- Sessantotto nuovi indirizzi singoli:22FFB e46FFC. Nessuna nuova finestra o indice AUX; la mappa fisica resta incompleta.',
                  '- FFB:OR di cinque argomenti spostati0/1/2/3/4bit e coppie spostate8bit, poi troncamento16bit; nessuna maschera indipendente dei campi. Due unpack rileggono ogni cella per estrarre low8/high8 in halfword RAM.',
                  '- FFB80DCbit0 e80F0bit1:set con qualunque argomento nonzero. Entry2E1C24 legge80F0bit0, non lo cancella;80E0/E4/E8/EC restituiscono low8 e80FC low14.',
                  '- FFC:17 setter di coppie scrivono prima low16 poi high16 completo, diversamente dagli FFB high13 prima low16. Le entry2E30C8 e seguenti selezionate sono setter aggiuntivi, non getter.',
                  '- FFC2098:23 RMW bit0..11;209C sostituisce low4 conservando upper12;20A0..20B4 sono sei letture full16 nel modello. Ordine software non prova atomicità, latch o effetti periferici.', '']
    if metadata.get('ffc_controls_new_scalars'):
        lines += ['', '## Coda controlli FFC2000 e gruppo FFC4000', '',
                  '- [CPU](evidence/ffc_controls.json), [audit indipendente](evidence/ffc_controls_audit.json):48 entry,8scenari/16run,1128accessi halfword,8coppie di tracce identiche;24nuovi indirizzi e3esistenti arricchiti.',
                  '- FFC20B4:store full16 da argomento o costanti1/2 e letture booleane bit0/1. Store diretto non prova acknowledgment o W1C.',
                  '- FFC20B8:lettura,store16,bit0/1 RMW e lettura seguita da store del complemento low16 dell’argomento,senza conservare bit dal vecchio valore.',
                  '- FFC20BC:RMW bit0/1/2/5/8 e maschereC/1C/60/E0 forzate a1;20C0/C4 packing OR(arg0,arg1<<8) con troncamento16bit;2098bit12,20A0bit6/7/8.',
                  '- FFC4000bit0/1/8/9 e4100bit0 impostati solo per argomento1;4000bit3/4 ricevono LSB dell’argomento. FFC400C usa arg1 come maschera,set searg0==1,altrimenti clear.',
                  '- Coppie e quartetti di store distribuiscono uno/due argomenti32bit in halfword low16 poi high16. Nessuna atomicità o semantica fisica dedotta;finestre/AUX e sovrapposizioni precedenti conservati.', '']
    if metadata.get('ff7_packed_windows_new'):
        lines += ['', '## FF7: contratti dei writer impacchettati', '',
                  '- [CPU](evidence/ff7_packed_writers.json), [audit buffer/byte](evidence/ff7_packed_writers_audit.json):dieci routine,25 scenari/50run,455scritture e25 coppie di tracce identiche.',
                  '- Sette finestre aggiunte per114celle,non registri di controllo indipendenti;dieci nuovi indirizzi parametro. Le varianti wide/compact condividono tre finestre ma hanno code16/8bit differenti.',
                  '- Solo i primi16elementi sono coppie7bit o8bit; il diciassettesimo è una coda letta separatamente. Cinque equivalenze sui bit ignorati e tre confronti wide/compact verificati sugli outputMMIO.',
                  '- Parametro7bit: uint16((r1<<10)|r2),senza cancellare preventivamente i bit alti di r2. Non descrivere gli argomenti come due campi indipendenti mascherati.',
                  '- Ventisiti run/PC SR LP_START/LP_END aggiunti;mapper host con prefisso base%8,senza cambiare indirizzi guest o GNU.', '']
    if metadata.get('ff7_early_controls_new_scalars'):
        lines += ['', '## FF7: controlli iniziali e argomenti divisi in halfword', '',
                  '- [CPU](evidence/ff7_early_controls.json), [audit indipendente](evidence/ff7_early_controls_audit.json):37 nuovi indirizzi,11scenari/22run,331accessi e11coppie di tracce identiche.',
                  '- Controlli bit0 impostati per argomento1, salvo FF70800 sempre set; campi RMW conservano gli altri bit. OR con shift4/8 non maschera separatamente gli argomenti.',
                  '- FF77000..FF77060:7 writer low16 e9 writer che dividono r0 in low16 poi high16,per25 destinazioni. Due store ordinati non provano atomicità o registro fisico32bit.',
                  '- Nibble15:4celle da15 low-nibble,prima uscita con low4 a0. Sparse5:3celle da byte0/2/4/6/8 e low3 di r1. Le7celle sono finestre separate;3equivalenze sui bit/byte ignorati.',
                  '- Quattro siti run/PC SR LP_START/LP_END aggiunti;nessuna nuova AUX distinta né prova hardware.', '']
    if metadata.get('ff7_remaining_raw_new_windows'):
        lines += ['', '## FF7: restanti writer raw9/33/17', '',
                  '- [CPU](evidence/ff7_remaining_raw_writers.json), [audit indipendente](evidence/ff7_remaining_raw_writers_audit.json):12scenari/24run,244scritture,12coppie di tracce identiche.',
                  '- Tre finestre FF760D0x9,FF76128x33,FF761ACx17 trasferiscono halfword complete con passo output4/input2. Le59celle restano separate dai registri indipendenti.',
                  '- Due nuovi parametri FF760F4/F8 ricevono low16 di r1/r2 dopo il bulk raw9;nessun flag skip. Sei siti run/PC LP_START/END aggiunti;22indici AUX distinti invariati.', '']
    if metadata.get('ffc3000_ffb_new_scalar_addresses'):
        lines += ['', '## FFC3000 e uscite FFB calcolate', '',
                  '- [CPU conservata](evidence/ffc3000_ffb_computed.json), [audit indipendente ricalcolato](evidence/ffc3000_ffb_computed_audit.json):24entry,12scenari/24run,1288accessi halfword,12tracepair identiche.',
                  '- 35nuovi indirizzi singoli:28FFC e7FFB. FFC3000bit5:set se argomento0;bit0/1/8/9:set solo1;bit3/4:set nonzero. FFC3130bit0:set solo1;mascheraFFC300C da argomento,con set solo per primo argomento1.',
                  '- FFB9F2C..9FC0 è una finestra di38uscite halfword da helper303A40,con copia srotolata su destinazioni fisse. Le38celle non sono ammesse come registri indipendenti.',
                  '- Provenienza helper→recordlocale→loadstack→MMIO verificata per quattro input;matematica NON verificata indipendentemente,modello DSP provvisorio. Nessun nome periferico o significato numerico fisico assegnato.',
                  '- SR303ADE suAUX65/AUX_MACMODE con operando0 osservato in quattro run:quattro nuovi siti run/PC,un unico nuovoPC;22indici distinti invariati. Operando setter,non stato fisico misurato.', '']
    if metadata.get('ff7_residual_controls_new_scalars'):
        lines += ['', '## FF7: controlli scalari residui e valori restituiti', '',
                  '- [CPU](evidence/ff7_residual_controls.json), [audit indipendente](evidence/ff7_residual_controls_audit.json):26entry/8scenari/16run,1328chiamate con replay,1216accessi e8tracepair identiche;21indirizzi nuovi e2arricchiti.',
                  '- FF7000Cgetter bit5 restituisce0/1;FF70008getter restituisce0/32,e setter scrive costante20hex senza leggere. Non è prova di acknowledgment oW1C.',
                  '- FF760FC:bit0set/clear ebit1set senza dipendere dall’argomento;entry2E11A4 sostituisce bits2..7 da arg&FC,preservando low2/high8.',
                  '- FF741D4/D8 ricevono low16 di due argomenti distinti;cinque coppie FF76100..124 ricevono low16 poi high16 dello stesso argomento. Nessuna atomicità o funzione fisica dedotta.',
                  '- FF74000 eFF76098 arricchiti,senza duplicare voci;finestre,sovrapposizioni e146siti AUX conservati invariati.', '']
    if metadata.get('ffc7000_fields_new_scalars'):
        lines += ['', '## FFC7000: campi mascherati e argomenti divisi', '',
                  '- [CPU](evidence/ffc7000_fields.json), [audit indipendente](evidence/ffc7000_fields_audit.json):11entry/8scenari/16run,176chiamate con replay,376accessi e8tracepair identiche;24indirizzi nuovi.',
                  '- FFC7000/04:low13=(argomento-1)&1FFF,preservandohigh3. Lo zero produce1FFF nel campo,senza dimostrare valori di reset o un dominio hardware valido.',
                  '- Coppie da argomento32 usano low16 ehigh12;tre setter duali scrivono low16/high12 di r0 e low16/high13 di r1. I bit esterni ai campi12/13 sono conservati dalla halfword letta.',
                  '- Alcuni percorsi leggono prima di sostituire tutti i16bit:il vecchio valore non contribuisce al risultato. Ogni accesso resta16bit;nessuna atomicità32bit o funzione periferica dedotta.', '']
    if metadata.get('ffc7000_controls_new_scalars'):
        lines += ['', '## FFC7000: polarità delle maschere e aggiornamenti dei byte', '',
                  '- [CPU](evidence/ffc7000_controls.json), [audit](evidence/ffc7000_controls_audit.json):13entry/8scenari/16run,464chiamate con replay,504accessi e8tracepair identiche;13indirizzi nuovi.',
                  '- FFC7060:cancella la maschera solo perflag1,altrimenti imposta;FFC7084:imposta solo perflag1,altrimenti cancella. FFC7064bit0/7068bit1setsolo1;7068bit0setincondizionato.',
                  '- FFC7080:getterlow5 e setterfull16;FFC706C/7074/7084 getterfull16. Il mascheramento del getter non prova la larghezza hardware.',
                  '- FFC7088/8C e7090/94:prima RMWlow8,poi rilettura e RMW high8;7098low8 e709Chigh8 sono destinazioni differenti. Nessuna scrittura atomica del valore composto.',
                  '- [Correzione oracolo](evidence/ffc7000_controls_oracle_correction.json):primo tentativoFAIL conservato;EXTB estende conzeri,nonconsegno. [Definizione GNU](evidence/ffc7000_extb_definition.txt) e20casi conbit7alto confermano conservazione deglihigh8 nella prima scrittura;firmware/GNU invariati.', '']
    if metadata.get('ffc7000_buffer_new_windows'):
        lines += ['', '## FFC7000: writer da struttura RAM e due finestre sparse', '',
                  '- [CPU](evidence/ffc7000_buffer_writer.json), [audit CFG/dataflow](evidence/ffc7000_buffer_writer_audit.json):8scenari/16run,608accessi e8tracepair identiche;4equivalenze metamorfiche.',
                  '- Due finestre FFC7124..7178(22celle) eFFC7180..71BC(16celle):32campi low9 conhigh7preservati,6campi raw16. Nessuna nuova voce scalare e nessuna cella aggiunta per717C non toccato.',
                  '- Input126byte:38halfword usate aoffset38/40,50..112,118..124;25halfword ignorate inquesto writer. Bit alti dei low9,campi non letti e secondoargomento variati senza cambiare le scritture.',
                  '- Ordine originale:71B8/BC prima degli altri campi;copie raw16 includono letture del vecchio valore che non contribuisce al risultato. Nessuna funzione periferica o struttura completa Nikon dedotta.',
                  '- Conservazione delle geometrie di finestra verificata anche su tutti gli atlanti storici validati;catalogo1024voci e coperturaAUX invariati.', '']
    if metadata.get('ffc7000_bound_loops_new_windows'):
        lines += ['', '## FFC7000: loop con destinazioni fissate dai chiamanti', '',
                  '- [CPU](evidence/ffc7000_loop_writers.json), [audit](evidence/ffc7000_loop_writers_audit.json):28scenari/56run,680accessi e28tracepair identiche;13finestre/125celle nuove e2indirizzi singoli.',
                  '- Bytepacker308ED4:tabella originale354E50,9byte in5celle;ultima cella conserva high8. Quattro wrapper originali fissano8finestre da13halfword al helper308F48;wrapper3090D0 lega targetindiretto309090 e4finestre low9 da4celle.',
                  '- FFC74B4/B8:4RMW per accumulatore;maschereF e7 a passo4bit. La seconda destinazione conserva bits3/7/11/15. Nessuna atomicità del valore composto o funzione fisica dedotta.',
                  '- Audit112SR su8PC;28record rappresentativi di7run aggiungono14siti run/PC:totale160siti/22indici. Operandi setter,non stati AUX fisici misurati.',
                  '- I domini di altri chiamanti dei helper parametrizzati restano aperti;nessuna ammissione da indirizzi arbitrari di prova.', '']
    if metadata.get('ffc7000_table_tail_new_windows'):
        lines += ['', '## FFC7000: parametri originali5/7/8bit e salto di una cella', '',
                  '- [CPU](evidence/ffc7000_table_tail.json), [audit](evidence/ffc7000_table_tail_audit.json):24scenari/48run,1684accessi,24tracepair identiche;5indirizzi singoli e13finestre/127celle nuove.',
                  '- Tabella originale354E50:lane5bit via309188→3090FC,7bit via309430→3093B4,8bit via3094E8→30945C. Bit non selezionati ehighlane dell’ultima cella dispari conservati. Helper3092DC usa10+6input e lascia75CC non toccato;nessuna assenza fisica dedotta.',
                  '- Raw33daFFC7530;scalariFFC751C/20 da3byte,7524/28store16,752C low8poi bit15settato perargomento1nonzero. Ogni fase RMW conservata.',
                  '- Audit104SR su12PC nuovi;26recordrappresentativi5run aggiungono12siti:totale172run-PC/22indici. Operandi setter,non stato fisico. Domini di altri chiamanti restano aperti.', '']
    if metadata.get('branch_reconciliation'):
        summary=metadata['mmio_window_overlap_summary']
        lines += ['', '## Riconciliazione dei rami dell’atlante', '',
                  '- [Audit storico](coverage_lineage_audit.json):nessuna chiave di registro degli atlanti validati viene persa;129 indirizzi recuperati dal ramo FFB/FFC,37 del ramo FF7 iniziale conservati.',
                  '- Finestre unificate per base/conteggio/stride/larghezza;nomi alternativi e contratti originali restano documentati.',
                  f"- {summary['window_count']} finestre: {summary['summed_cell_offsets']} appartenenze di cella, {summary['unique_cell_addresses']} indirizzi distinti; {summary['duplicate_cell_occurrences']} ripetizioni tra finestre. Un indirizzo è anche parametro scalare: nessuna nuova ammissione dai duplicati.", '']
    if metadata.get('ffc7000_scalar_tail_new_scalars'):
        lines += ['', '## Coda scalare FFC7000 e RMW ripetuti', '',
                  '- [CPU](evidence/ffc7000_scalar_tail.json), [audit](evidence/ffc7000_scalar_tail_audit.json):16entry,9scenari/18run,675accessi halfword(342R/333W),9coppie di tracce identiche;16nuovi scalari e2esistenti arricchiti.',
                  '- FFC7718 aggiorna low7 poi bits8..14 preservando bits7/15;FFC7724 aggiorna low3 poi bits8..10 preservandoF8F8. Ogni campo ha una lettura e scrittura separate.',
                  '- FFC771C/7720:low8 poi high8 da due buffer;FFC7204/7208/720C:low4 da tre byte. FFC7228/721C:low2;722C/7238/7220:LSB,con altri bit conservati.',
                  '- Setter selezionati su7224/7230/7218/7200bit0 e7064bit1:set solo seargomento1,altrimenti clear. Getter309838 restituisce7080bit0.',
                  '- 63carichi input indipendentemente confrontati e1equivalenza:invertire upper16degli argomenti dei writer di campo,con flag invariati,conserva tutti gli eventi MMIO. Finestre,overlap eAUX precedenti invariati;nessuna semantica fisica dedotta.', '']
    if metadata.get('fe9_selector_new_scalars'):
        lines += ['', '## Dispatcher FE9 e helper a destinazione parametrica', '',
                  '- [CPU](evidence/fe9_dispatch_and_mask_helpers.json), [audit](evidence/fe9_dispatch_and_mask_helpers_audit.json):23 entry,12 scenari/24 run,4184 eventi halfword e12 coppie di tracce identiche;206 istruzioni ricontrollate sui byte originali.',
                  '- Cinque nuovi indirizzi fissi:FFC7070 read16;FE9013C/140 eFE9813C/140. Solo136 eventi(88R/48W) giustificano queste ammissioni.',
                  '- Dispatcher309A2C aggiorna low10,309C44 low11. Selettori0/2 aggiornano i campi dei due indirizzi,1 legge il primo full16,3 cancella il secondo con la maschera completa. Altri selettori unsigned restituiscono55AA senza MMIO.',
                  '- Venti helper parametrizzati/puri:4048 eventi su indirizzi scelti nel laboratorio,esclusi dalle ammissioni e dagli arricchimenti. First-set-bit cerca solo low16 e restituisce15 se vuoto:il flag helper con maschera zero può modificare bit15;domini Nikon non provati.',
                  '- [Censimento](evidence/fe9_caller_census.json):37 candidati BL nei16 payload,36 istruzioni qualificate e1 candidato dentro immediato a30AA10;nessun puntatore LE/ME trovato. Raggiungibilità globale e domini delle tabelle dei chiamanti restano aperti.', '']
    if metadata.get('fe9_indexed_new_scalars'):
        lines += ['', '## Chiamanti indicizzati FE9 e tabelle del secondo payload', '',
                  '- [CPU](evidence/fe9_indexed_callers.json), [audit](evidence/fe9_indexed_callers_audit.json), [riscontri degli indici](evidence/fe9_indexed_witnesses.json):9 wrapper originali,12 scenari/24 run,1080 eventi e12 tracepair identiche;398 istruzioni e1008 carichi da parole originali verificati.',
                  '- 68 sequenze locali con indice costante in75 candidati BL qualificano le selezioni provate:70 indirizzi,66 nuovi e4 arricchiti,1032 eventi(456R/576W). Raggiungibilità globale e dominio completo degli indici restano aperti.',
                  '- 48 eventi con indice0 sintetico nei wrapper2EE924/974 esclusi da ammissioni earricchimenti:FE90200/FE90400/FE98200/FE98400. Nessun limite di tabella dedotto dalla distanza fra puntatori.',
                  '- Payload0 e1 originali mappati invariati;maschere edestinazioni dei due rami possono differire. Split store low16 ehigh16 a+4 catalogati separatamente.',
                  '- Wrapper2EE9C4modo1 applicaAND con tabellaB anche nel ramoA;indice11 usa7FF dopo il readfull16,verificati2casi con bit10 conservato. Il risultato non coincide sempre con un campo low10.',
                  '- 6 equivalenze:varia solo canale1→2/FFFFFFFF,con valori,seed,indici e modi invariati. Nessun significato fisico dei canali osemantica hardware dedotti.', '']
    lines += ['','## AUX con risultato nella CPU emulata', '',
              '| AUX | Nome documentale/toolchain | Record LR/SR | PC distinti |',
              '|---|---|---:|---:|']
    for number, events in sorted(by_aux.items()):
        r=by_key[('aux',number)]
        lines.append(f"| {hex(number)} | {r['name']} | {len(events)} | {len({e['pc'] for e in events})} |")
    for space, title in [('core','Posizioni core'),('aux','Catalogo AUX'),('soc_mmio','Indirizzi MMIO e candidati')]:
        lines += ['', '## '+title, '', '| Numero/indirizzo | Nome/gruppo | Accesso | Stato delle prove |', '|---|---|---|---|']
        for r in sorted((r for r in records if r['space']==space), key=lambda r:r['number']):
            lines.append(f"| {r['number_hex']} | {r['name']} | {r.get('access','?')} | {r['classification']} |")
    lines += ['', '## Requisiti ancora non dimostrati', ''] + ['- '+g for g in gaps]
    lines += ['', 'Nessun accesso hardware, flash, reset USB, comando NAND/vendor o scrittura SD. GNU, firmware originali e copie laboratorio conservati in sola lettura. **NON_INSTALLARE** invariato.', '']
    (out/'REGISTER_MAP.md').write_text('\n'.join(lines))
    print(json.dumps(dict(counts=counts, firmware_aux_indices=len(by_aux), status=result['status'])))


if __name__ == '__main__':
    main()
