# S33 V1.1 — inoltro dell'evento ai controlli diagnostici

Il 28 ottobre 2026 ho esteso la [prova delle risorse](S33_GUI_Debug_Risorse_Parent_CPU_20261028.md), eseguendo anche il callback originale `0x16A944`: il servizio originale `0x1455E4` lo richiama per ciascuna risorsa, e questo inoltra `0x4401` attraverso il dispatcher originale `0x169D78`. Il recupero dell'handler di classe `0x145020` e l'handler restituito sono fixture; registrano gli argomenti e restituiscono zero.

Nei **due casi GNU ARC700 PASS**, con descrittori e array originali V1.1 e contesto sintetico, il dispatcher raggiunge la fixture di classe per tutte le risorse nell'ordine originale. Ogni chiamata registrata porta l'evento `0x4401`:

| Schermata | Numero risorse | Classi iniziali nell'ordine |
| --- | ---: | --- |
| Tempo | 6 | 7, 2, 2, 2, 1, 1 |
| ISO | 2 | 7, 9 |

Il banco verifica anche i collegamenti al descrittore nella word `+8`, i flag finali, la richiesta di selezione ISO e la richiesta del testo iniziale tempo. Gli indirizzi delle risorse sono confrontati con il dump e riportati nei casi. L'handler di classe simulato **non costruisce i controlli**: la prova non stabilisce che le classi originali accettino l'evento o che il display mostri una schermata. Ottenimento dei controlli, selezione, testo e disegno restano fixture; nessuna RAM fisica libera è individuata.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_debug_window_resource_events_cpu.py), [casi](../Risultati/GUI_S33/debug_window_resource_events_cpu_20261028T091822Z/cases.json), [fixture](../Risultati/GUI_S33/debug_window_resource_events_cpu_20261028T091822Z/fixture_patches.json), [traccia](../Risultati/GUI_S33/debug_window_resource_events_cpu_20261028T091822Z/cases.trace), [risultato e hash](../Risultati/GUI_S33/debug_window_resource_events_cpu_20261028T091822Z/verified_evidence.json). Nessuna prova di tasti fisici, ritorno, scatto o fotocamera; firmware e SD invariati. **NON_INSTALLARE**.
