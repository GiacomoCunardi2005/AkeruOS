# S33 V1.1 — snapshot candidato fino a CaptureMenu originale

**Data:** 2026-11-01. Quattro casi GNU ARC700 collegano lettore snapshot `0x2D62D8`, callback `0x1406D0`, normalizzatore `0x16E6E0`, generatore tasti, coda Nikon, dispatcher e percorso AutoScene → CaptureMenu originale. ID 2 rimane associato al descrittore originale `0x9802AC`.

| Bit snapshot simulato | Tasto logico prodotto | Evento estratto | Guardia manager aperta |
| ---: | ---: | --- | --- |
| 7 | 14 | `0x700` | argomento 4, richiesta risorsa `0x4800` |
| 8 | 67 | `0x2180` | argomento 5, richiesta risorsa `0x4801` |

Con guardia manager forzata, entrambi gli eventi lasciano AutoScene corrente e non raggiungono la selezione della risorsa. Il banco controlla anche lo snapshot di rilascio e i record `0x701`/`0x2181`: li estrae dalla coda, **senza consegnarli al dispatcher**. Per la pressione il banco estrae il record e chiama esplicitamente il dispatcher; non esegue lo scheduler.

Le due halfword a `0xFE70224` e `0xFE70228` sono memoria simulata; per ogni caso si varia un solo bit e il banco chiama esplicitamente il callback con il risultato del lettore. I dati della tabella di normalizzazione, il contesto del gestore e i gate sono predisposti dal banco. Modalità `0x46`, lifecycle AutoScene, ciclo delle risorse, controlli, visibilità, lock e servizi sono fixture. Il controllo attivo è nullo. I bit sono **candidati software**, non identificano interruttori fisici, ordine o polarità sulla macchina; pressioni simultanee e scheduler non sono verificati. Le risorse registrate non provano rendering o scatto.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_snapshot_autoscene_capture_cpu.py`; [quattro casi PASS](../Risultati/GUI_S33/snapshot_autoscene_capture_cpu_20261101T095709821949Z/cases.json), trace, fixture, snapshot del verificatore e hash nella stessa directory. È passato anche il banco con tasti logici direttamente iniettati, `key_autoscene_capture_cpu_20261101T095713655253Z/`, e la regressione snapshot flash `flash_model_snapshot_cpu_20261101T095713660908Z/`. I byte delle finestre originali, tabelle e ID 2 sono confrontati con il dump V1.1.

Nessuna modifica al firmware originale, GNU, fotocamera o SD. **NON_INSTALLARE.**
