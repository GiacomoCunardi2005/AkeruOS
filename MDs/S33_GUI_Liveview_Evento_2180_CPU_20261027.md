# S33 V1.1 — evento 0x2180 nella live view

Il 27 ottobre 2026 ho eseguito offline il wrapper originale `CaptureLiveview` `0x6524F4`, il dispatcher `0x169F60` e il callback `0x655F34`, usando l'evento **0x2180 immesso direttamente nel wrapper**. Nella tabella originale `0x7833EC` la coppia a `0x78349C` associa l'evento al callback; il descrittore dell'oggetto 7 riporta il nome interno `ShootingMode`. Codice, tabella, riferimento e descrittore sono confrontati con `MainCode.dmp` V1.1.

In **9 casi GNU ARC700 PASS**, con contesto, modalità, stato, filtro e servizi sintetici:

| Caso | Risultato osservato |
| --- | --- |
| Modalità `0x0A` o `0x46`, guardie inattive | Una richiesta `0x1453E4(7,0)`. |
| Modalità `0x38`, stato 7 o 8 | Nessuna richiesta. |
| Modalità `0x38`, stato 0; oppure `0x39`, stato 7 | Una richiesta `(7,0)`. |
| Guardia `0x657928` attiva | Nessuna richiesta. |
| Filtro sintetico contenente `0x2180` | Nessuna richiesta; un filtro con `0x4004` lascia passare il caso provato. |

Tutte le prove preservano lo stack; il run dichiara 3402 istruzioni e nessun fault. Undici servizi sono fixture; quello a `0x1453E4` registra gli argomenti e **non apre realmente una schermata**. Il filtro è inizializzato dal test. I valori restituiti dai servizi restano fissi per scenario, quindi le letture ripetute non provano il comportamento con cambiamenti concorrenti.

L'evento corrisponde al candidato slot 2 nella tabella di classe `0x15`, ma **non identifica il terzo pulsante fisico** né dimostra che il suo evento raggiunga la live view. Coda, scheduler, stato runtime, transizione effettiva, ritorno, grafica e fotocamera non sono eseguiti. La prova non dimostra l'apertura dei nuovi sottomenu richiesti. Firmware e hardware non sono stati modificati; **NON_INSTALLARE**.

- [Script riproducibile](../Python_Trace_Scripts/s33_verify_gui_liveview_slot2_wrapper.py)
- [Risultato, hash e limiti](../Risultati/GUI_S33/liveview_slot2_wrapper_20261027T214340Z/verified_evidence.json), [casi](../Risultati/GUI_S33/liveview_slot2_wrapper_20261027T214340Z/cases.json), [finestre GNU](../Risultati/GUI_S33/liveview_slot2_wrapper_20261027T214340Z/gnu_verified.txt), [fixture](../Risultati/GUI_S33/liveview_slot2_wrapper_20261027T214340Z/fixture_patches.json).
- [Tabella dei quattro slot e limiti](S33_GUI_Quattro_Tasti_e_Controlli_20261027.md); [analoga prova dell'evento 0x700](S33_GUI_Wrapper_Filtro_Menu_20261027.md).
