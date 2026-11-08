# S33 V1.1 — consegna del rilascio dopo AutoScene → CaptureMenu

**Data:** 2026-11-01. Quattro casi GNU ARC700 estendono il [banco snapshot](S33_GUI_Snapshot_Autoscene_CaptureMenu_CPU_20261101.md): il banco estrae e consegna esplicitamente al dispatcher originale sia la pressione sia il rilascio generati dal codice Nikon. I bit 7 e 8 e i registri di ingresso sono simulati, uno per volta.

| Bit / eventi | Guardia manager | Destinatario osservato del rilascio | Campi controllati |
| --- | ---: | --- | --- |
| 7 / `700`, `701` | 0 | callback CaptureMenu originale | argomento 4, risorsa `4800`, puntatore sintetico e conteggio visibilità invariati |
| 8 / `2180`, `2181` | 0 | callback CaptureMenu originale | argomento 5, risorsa `4801`, puntatore sintetico e conteggio visibilità invariati |
| 7 o 8 | 1 | callback AutoScene originale | descrittore AutoScene e sentinelle del CaptureMenu invariati |

Con guardia aperta, la pressione ha già cambiato il descrittore corrente prima del rilascio; con guardia chiusa resta corrente AutoScene. La trace verifica quale wrapper originale riceve ciascun rilascio, oltre ai record della coda e ai campi indicati. Il dispatcher restituisce 1 in tutti e quattro i casi; questo non dimostra che il rilascio sia privo di ogni effetto non osservato.

Il wrapper AutoScene di laboratorio inoltra ora al callback originale anche `0x701`/`0x2181`; gli eventi di lifecycle AutoScene restano simulati. Modalità `0x46`, stato, controllo attivo nullo, lock, risorse e servizi di selezione/visibilità sono fixture; il banco decide ordine e consegna degli eventi. Non è verificato che il dispositivo consegni il rilascio con questo timing, né sono identificati pulsanti fisici, rendering, concorrenza o scatto. L'ID 2 resta originale nella copia usata.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_snapshot_release_autoscene_capture_cpu.py`; [quattro casi PASS](../Risultati/GUI_S33/snapshot_release_autoscene_capture_cpu_20261101T095818961938Z/cases.json), trace, fixture, snapshot e hash nella stessa cartella. Regressioni PASS: `snapshot_autoscene_capture_cpu_20261101T095823575546Z/` e `flash_model_snapshot_cpu_20261101T095823577850Z/`. Nessuna operazione su fotocamera o SD; **NON_INSTALLARE**.
