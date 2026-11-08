# S33 V1.1 — collegamento delle risorse diagnostiche in CPU

Il 28 ottobre 2026 ho esteso la [prova di apertura](S33_GUI_Debug_Apertura_4401_4405_CPU_20261028.md), eseguendo il servizio originale `0x1455E4` e il callback originale `0x16A93C`. Nel banco GNU ARC700, `0x4401` percorre l'array di risorse indicato dal descrittore e il callback scrive il puntatore al descrittore nella word `+8` di ciascuna risorsa. Il servizio viene poi richiamato per inoltrare `0x4401` alle stesse risorse tramite un callback **simulato**.

| Schermata | Risorse originali percorse | Word `+8` dopo il callback originale |
| --- | ---: | --- |
| Tempo | 6 | descrittore tempo `0x989CD8` |
| ISO | 2 | descrittore ISO `0x989FCC` |

Entrambi i casi **PASS** verificano l'ordine degli indirizzi inoltrati alla fixture, le word `+8` risultanti in tutte le risorse e i risultati già osservati per i callback diagnostici. Contesto del gestore, controlli e indice ISO sono sintetici; selezione ISO, scrittura testo, inoltro degli eventi ai controlli e disegno sono fixture. Le word delle risorse sono modificate solo nelle copie di laboratorio, non nel firmware originale.

L'esecuzione dimostra il collegamento software nelle condizioni del banco, non allocazione o validità della RAM fisica, caricamento completo dei controlli, rendering, consegna reale dei tasti, ritorno al nuovo menu o effetto sullo scatto. Il callback di inoltro reale `0x16A944` non è eseguito. Nessuna operazione su fotocamera o SD; **NON_INSTALLARE**.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_debug_window_resources_cpu.py), [due casi](../Risultati/GUI_S33/debug_window_resources_cpu_20261028T091641Z/cases.json), [fixture](../Risultati/GUI_S33/debug_window_resources_cpu_20261028T091641Z/fixture_patches.json), [traccia](../Risultati/GUI_S33/debug_window_resources_cpu_20261028T091641Z/cases.trace), [risultato e hash](../Risultati/GUI_S33/debug_window_resources_cpu_20261028T091641Z/verified_evidence.json).
