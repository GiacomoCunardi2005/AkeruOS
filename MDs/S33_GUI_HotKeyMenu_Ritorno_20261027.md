# S33 — ritorno dal menu rapido

Il 27 ottobre 2026 ho eseguito in GNU ARC700 il wrapper originale `LiveViewHotKeyMenu` (`0x6646C0`), il dispatcher `0x169F60` e tre handler V1.1 della tabella originale `0x784714`. La prova inietta l'evento nel wrapper e sostituisce soltanto il servizio di apertura `0x1453E4` con un registratore.

| Evento iniettato | Richiesta registrata se non filtrato |
| --- | --- |
| `0x0080` | `0x1453E4(0x87, 0)` — descrittore `AutoSceneLiveView` |
| `0x0180` | `0x1453E4(0x87, 0)` — descrittore `AutoSceneLiveView` |
| `0x0580` | `0x1453E4(0x02, 4)` — descrittore `CaptureMenu` |

I comandi diagnostici collegano separatamente `0x0580` a KeyOK; non identificano il pulsante fisico. Il valore 4 è il secondo argomento della richiesta, non una prova che il menu sia effettivamente aperto. Tre ulteriori scenari con il rispettivo evento inserito nel filtro sintetico producono zero richieste. In totale **6 scenari PASS**, stack preservato.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_hotkey_navigation_cpu.py), [casi](../Risultati/GUI_S33/hotkey_navigation_cpu_20261027T175145Z/cases.json), [sostituzione del servizio](../Risultati/GUI_S33/hotkey_navigation_cpu_20261027T175145Z/fixture_patch.json), [disassemblato](../Risultati/GUI_S33/hotkey_navigation_cpu_20261027T175145Z/gnu_windows.txt) e [traccia](../Risultati/GUI_S33/hotkey_navigation_cpu_20261027T175145Z/cases.trace). Codice, descrittore e tabelle sono confrontati con `MainCode.dmp`. Il filtro è inizializzato dal banco: non è noto il suo contenuto runtime. Non sono eseguiti WindowMgr, transizione reale, coda, display o ingresso fisico; nessuna modifica firmware o operazione hardware.
