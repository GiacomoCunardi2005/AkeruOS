# S33 V1.1 — lifecycle delle risorse CaptureMenu nel banco integrato

**Data:** 2026-11-01. Quattro casi GNU ARC700 estendono il [percorso snapshot → CaptureMenu](S33_GUI_Snapshot_Rilascio_CaptureMenu_CPU_20261101.md). Il banco non sostituisce più il servizio originale `0x1455E4`: esegue l'enumerazione e i callback originali `0x16A93C` e `0x16A944`. Il lookup delle classi `0x145020` e il callback di classe risultante sono fixture, che registrano gli eventi e restituiscono zero.

Nei due casi in cui il manager apre CaptureMenu originale `0x9802AC`, il banco verifica che le tre risorse originali siano collegate a quel descrittore tramite la word `+8` e che il dispatcher le consegni, nell'ordine, al callback di classe simulato con evento `0x4401`:

| Risorsa | ID | Classe originale | Parent osservato nella copia laboratorio |
| --- | --- | --- | --- |
| `0x9801C0` | `0x4800` | `0x15` | `0x9802AC` |
| `0x980268` | `0x4801` | `0x15` | `0x9802AC` |
| `0x3ABA38` | `0x4A12` | `1` | `0x9802AC` |

Entrambe le liste ricevono `0x4401` in questa fase. Il callback CaptureMenu richiede poi `0x4800` per argomento 4 o `0x4801` per argomento 5; selezione e visibilità restano servizi simulati. Nei due casi con guardia del manager attiva, il banco osserva zero eventi CaptureMenu nel registratore e nessuno dei tre parent preparati a zero viene aggiornato.

Il banco forza a zero i tre parent prima di ciascun caso: non sono letture di RAM reale. La terza risorsa compare anche fra quelle originali AutoScene, quindi la modifica della sua copia durante una prova non dimostra proprietà o durata esclusive. Le pressioni e i rilasci sono generati da snapshot MMIO simulati ed estratti e consegnati esplicitamente dal banco. Modalità, controllo attivo nullo, lifecycle AutoScene, lookup e classi, servizi di visualizzazione e altri gate sono fixture. Non vengono costruiti i controlli reali e non sono verificati rendering, tasti fisici, concorrenza o scatto.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_snapshot_capture_resources_cpu.py`; [quattro casi PASS](../Risultati/GUI_S33/snapshot_capture_resources_cpu_20261101T095947597564Z/cases.json), trace, fixture, snapshot e hash nella stessa directory. Regressioni PASS: `snapshot_release_autoscene_capture_cpu_20261101T095950915441Z/` e due inizializzazioni diagnostiche `debug_window_resource_events_cpu_20261101T095950Z/`. Descrittori, risorse e finestre di codice usate sono confrontati col dump V1.1. Firmware originale, GNU, fotocamera e SD invariati; **NON_INSTALLARE**.
