# S33 V1.1 — argomenti 4 e 5 nel CaptureMenu

**Data:** 2026-11-01. Quattro casi GNU ARC700 eseguono il wrapper originale di CaptureMenu `0x7CAFE8`, il dispatcher `0x169F60`, i callback `0x7CB020`/`0x7CB03C` e il selettore `0x7CB118`. Gli eventi `0x4401` e `0x4405` sono consegnati direttamente dal banco; i servizi di controllo, visibilità, aggiornamento record e rendering sono fixture.

| Argomento fornito a 4401 | Selezione richiesta a 4405 | Chiamate di visibilità registrate | Puntatore salvato |
| ---: | --- | --- | --- |
| 4 | `0x4800` | `4800 → 1`, `4801 → 0` | controllo sintetico `0x2200000` |
| 5 | `0x4801` | `4800 → 0`, `4801 → 1` | controllo sintetico `0x2200100` |
| 0 o `0xFFFFFFFF` | nessuna delle due in questo ramo | nessuna | sentinella invariata |

Il codice originale salva l'argomento in `0x899860`; per 4 o 5 salva poi il risultato della fixture di recupero in `0x89985C`. Registra anche una chiamata al servizio sostituito `0xD139C` con `(11,3)` per 4 e `(12,1)` per 5 (ulteriori argomenti zero nel percorso provato). Il significato fisico o grafico di quel servizio non è stabilito. I valori diversi da 4 e 5 sono controlli delimitati, non prove del comportamento dell'intero menu.

Questa esecuzione rafforza la [precedente analisi statica](S33_GUI_CaptureMenu_Argomento_Ingresso_20261027.md): nelle condizioni del banco, **4 e 5 selezionano risorse diverse**, non sono semplicemente due nomi per la stessa inizializzazione. Combinata con la [prova AutoScene](S33_GUI_Autoscene_Due_Tasti_ID2_CPU_20261101.md), motiva la conservazione della distinzione nel futuro raccordo. Le due prove restano separate: qui non viene eseguita la chiamata del manager che porta gli argomenti dall'handler AutoScene al callback, né si escludono redirect, filtri o modifiche runtime.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_capture_menu_entry_choices_cpu.py`; [quattro casi PASS](../Risultati/GUI_S33/capture_entry_choices_cpu_20261101T095335221067Z/cases.json), trace, fixture, snapshot e hash nella stessa cartella. Regressioni PASS: controllo statico `capture_menu_entry_arg_20261101T095344Z/` e nove casi AutoScene `autoscene_key2180_reenter_cpu_20261101T095344Z/`. Primo tentativo `...095329550891Z` conservato FAIL per un'asserzione ridondante che confrontava l'ID della seconda risorsa con il valore di visibilità; l'asserzione corretta controlla entrambi separatamente.

La selezione registrata non prova la pagina disegnata, il controllo attivo effettivo, il tasto fisico, l'ordine dello scheduler o l'hardware. Firmware originale, GNU, fotocamera e SD invariati; **NON_INSTALLARE**.

Aggiornamento 2026-11-01: una [prova integrata](S33_GUI_Autoscene_CaptureMenu_Argomenti_CPU_20261101.md) esegue AutoScene → manager → callback CaptureMenu originale nella stessa sessione, confermando il trasferimento di 4/5 con guardie e servizi sintetici.
