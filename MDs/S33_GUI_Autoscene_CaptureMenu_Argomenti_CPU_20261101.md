# S33 V1.1 — AutoScene, manager e CaptureMenu nella stessa prova

**Data:** 2026-11-01. Quattro casi GNU ARC700, con codice Nikon originale e servizi sintetici. La voce ID 2 della tabella oggetti rimane quella originale, `0x9802AC` (CaptureMenu): è verificata prima dell'esecuzione nella copia di laboratorio.

Il banco inizializza AutoSceneLiveView come descrittore corrente e consegna un evento direttamente al dispatcher originale `0x169E1C`. Per gli eventi `0x700` e `0x2180`, un wrapper di laboratorio inoltra al callback AutoScene originale `0x6593A0`; gli altri eventi AutoScene, incluso il lifecycle, sono simulati. Con modalità e guardie permissive, il percorso originale `0x65C46C` → `0x65C5F8` → `0x1453E4` → `0x145180` apre il CaptureMenu originale. Il manager invia `0x4401` e `0x4405` al callback originale `0x7CAFE8`, che raggiunge `0x7CB020` e `0x7CB118`.

| Evento | Guardia manager | Descrittore finale | Argomento registrato | Risorsa richiesta / visibilità |
| --- | ---: | --- | ---: | --- |
| `0x700` | 0 | CaptureMenu `0x9802AC` | 4 | `4800` / `4800=1`, `4801=0` |
| `0x2180` | 0 | CaptureMenu `0x9802AC` | 5 | `4801` / `4800=0`, `4801=1` |
| `0x700` o `0x2180` | 1 | AutoScene `0x783AE8` | sentinella invariata | nessuna chiamata di selezione |

Il dispatcher restituisce 1 anche nei due casi bloccati. La catena completa elimina, per queste condizioni del banco, il precedente salto tra prove separate: l'argomento selezionato dall'handler arriva effettivamente ai callback CaptureMenu originali. Le chiamate di selezione, visibilità e recupero controllo sono però registrate da fixture; i puntatori restituiti sono sintetici. Il ciclo di risorse `0x1455E4`, aggiornamento record `0x7CB1B4`, lock, modalità `0x46`, guardie e vari servizi sono anch'essi sostituiti. Non si dimostra quale pagina venga disegnata o se i controlli reali siano costruiti.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_autoscene_capture_entry_cpu.py`; [quattro casi PASS](../Risultati/GUI_S33/autoscene_capture_entry_cpu_20261101T095538337632Z/cases.json), trace, fixture, snapshot e hash nella stessa cartella. Le finestre e le tabelle rilevanti sono confrontate con il dump V1.1. Regressioni PASS: selezione diretta `capture_entry_choices_cpu_20261101T095542602309Z/` e percorso verso descrittore sintetico `autoscene_key2180_reenter_cpu_20261101T095542Z/`.

Il risultato non identifica i tasti fisici né verifica scheduler, altre modalità, hook runtime, rendering, scatto o persistenza. Non modifica il firmware originale, GNU, fotocamera o SD; **NON_INSTALLARE**.
