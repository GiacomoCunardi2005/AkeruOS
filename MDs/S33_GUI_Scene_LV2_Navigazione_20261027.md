# S33 — navigazione di SCENE MODE LV2

Il 27 ottobre 2026 ho verificato la schermata interna `SCENE MODE LV2` del firmware V1.1. La tabella eventi a `0x981F4C` associa `0x0480` all'handler `0x7CA554` e `0x0500` a `0x7CA634`. I comandi diagnostici precedentemente studiati associano questi eventi rispettivamente a Left e Right; ciò non identifica i pulsanti fisici né dimostra il recapito dell'evento alla schermata.

In 12 scenari GNU ARC700 ho chiamato direttamente gli handler con modalità sintetica `0x1F` nel byte `0x899832`. Le routine originali leggono e aggiornano la halfword `0x3657C2` mediante getter `0xCFC44` e setter `0xCFC50`. Per ciascuno dei cinque valori iniziali 0–4:

| Evento | Trasformazione osservata |
| --- | --- |
| `0x0480` / Left | 0→1→2→3→4→0 |
| `0x0500` / Right | 0→4→3→2→1→0 |

Ogni scenario verifica anche la chiamata a un servizio di selezione con il nuovo indice e quella a un servizio di posizione con parametro `138 + 90 × (4 − indice)`. Sono valori interni passati alle fixture, non posizioni misurate sul display. Due ulteriori casi con byte modalità zero e valore iniziale 2 lasciano il valore invariato e non invocano tali servizi. Sono comportamenti dei casi esaminati; il ramo distinto per modalità `0x7B` non è stato eseguito.

Il banco usa handler, getter e setter originali, confrontati col dump, e cinque servizi sostituiti: risorsa, posizione, selezione, aggiornamento e notifica. Le fixture registrano gli argomenti e non disegnano; l'evento viene inserito chiamando direttamente l'handler, senza dispatcher, coda o tasto fisico. Il significato fotografico dei cinque valori, il layout visibile e lo stato reale della fotocamera non sono provati.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_scene_navigation_cpu.py), [12 casi](../Risultati/GUI_S33/scene_nav_cpu_20261027T174840Z/cases.json), [sostituzioni](../Risultati/GUI_S33/scene_nav_cpu_20261027T174840Z/fixture_patches.json), [finestre GNU](../Risultati/GUI_S33/scene_nav_cpu_20261027T174840Z/gnu_windows.txt) e [traccia](../Risultati/GUI_S33/scene_nav_cpu_20261027T174840Z/cases.trace). Il primo tentativo `scene_nav_cpu_20261027T174836Z` è conservato come FAIL: l'aspettativa iniziale della formula di posizione era errata; il codice e la formula corretta producono il risultato PASS sopra. Nessuna scrittura firmware o operazione hardware.
