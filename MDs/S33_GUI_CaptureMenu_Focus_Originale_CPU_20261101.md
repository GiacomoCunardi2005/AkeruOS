# CaptureMenu: selezione originale del controllo attivo — 2026-11-01

## Risultato

Nel banco GNU ARC700 V1.1, l'apertura di CaptureMenu con argomento 5 recupera il controllo `0x4801` usando il servizio originale `0x145654` e passa attraverso `0x145764` → `0x1456EC`. Il codice originale scrive il puntatore `0x980268` nel campo controllo attivo del manager `0x366EAC`. Il banco verifica che il puntatore sia presente dopo il rilascio e dopo la successiva pressione, senza imporlo manualmente.

L'esperimento estende il [banco precedente](S33_GUI_CaptureMenu_Flag_Pressione_Successiva_CPU_20261101.md): snapshot sintetico → normalizzazione e coda originali → dispatcher → AutoScene → manager → CaptureMenu → aggiornamento record `0x7CB1B4` → successiva pressione logica. Il servizio originale `0x1457D4` legge l'ID del controllo attivo per l'aggiornamento dei record. Le finestre di codice e i dati usati sono confrontati con il dump V1.1.

Con `0xCAD30=0x46` e `0xCA310=0` sintetici, flag iniziali con bit 1 impostato dal banco e selezione riuscita, i flag della lista diventano `08,00,02,02`. I successivi eventi logici `0x2180` e `0x2700` raggiungono rispettivamente gli handler originali `0x631A38` e `0x631B14`: entrambi leggono flag 2 e non emettono una nuova richiesta di apertura. Con la guardia del manager attiva l'apertura iniziale è bloccata e non viene inviata la seconda pressione.

## Riproduzione

- `python3 Python_Trace_Scripts/s33_verify_snapshot_capture_focus_original_cpu.py`: 4 casi PASS, `Risultati/GUI_S33/snapshot_capture_focus_original_cpu_20261101T100729529577Z/`.
- Stesso comando con `--ui-mode-23`: 4 PASS, `Risultati/GUI_S33/snapshot_capture_focus_original_cpu_20261101T100732611926Z/`.
- Regressioni: `s33_verify_snapshot_capture_followup_key_cpu.py` 4 PASS, `snapshot_capture_followup_key_cpu_20261101T100723220523Z/`; `s33_verify_gui_capture_init_slot_cpu.py` 6 PASS, `capture_init_slot_cpu_20261101T100723Z/`.

La fixture indipendente `0x1286BC` vale rispettivamente 0 e `0x23` nei due gruppi. Il primo evento e rilascio sono estratti e consegnati dal banco; la seconda pressione è iniettata come tasto logico e il suo rilascio non è generato. MMIO, lifecycle AutoScene, servizi di modalità, visibilità, sincronizzazione, stato iniziale e scheduler restano in parte sintetici. Non si dimostrano tasti fisici, rendering, valori reali, persistenza o comportamento hardware. Simulatore DSP sperimentale; **NON_INSTALLARE**.
