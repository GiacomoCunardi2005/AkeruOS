# Menu RAW: flag condiviso e selettore — 28 ottobre 2026

Due sequenze GNU ARC700 inviano eventi al wrapper originale `IQDEBUG MENU` `0x7CF024` con la tabella eventi V1.1. Le voci `SaveCCDRawOnTake` (`0x5003`) e `Take12BitCCDRawImage` (`0x500C`) **invertono lo stesso flag** `0x36C26E`; soltanto la seconda aggiorna anche il selettore `0x366F90` a 3 quando accende e 0 quando spegne.

| Partenza | Evento | Flag, selettore dopo l'evento |
|---|---|---|
| `(0, 0)` | `0x5003` | `(1, 0)` |
| `(0, 0)` | `0x500C` | `(1, 3)` |
| `(1, 3)` | `0x5003` | `(0, 3)` |
| `(0, 3)` | `0x5003` | `(1, 3)` |
| `(1, 3)` | `0x500C` | `(0, 0)` |

Le due sequenze complete contengono sei eventi ciascuna e verificano flag, selettore e stack dopo ogni passo. Le combinazioni `(1,0)` e `(0,3)` sono osservate con input e stato sintetici: **un singolo toggle non assicura la coppia desiderata** e spegnere un flag tramite l'altra voce non ripristina automaticamente il selettore. Una futura scelta colore/mono dovrà definire uno stato esplicito e il comportamento di ritorno, senza supporre che i due toggle siano indipendenti.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_raw_menu_toggles_cpu.py), [sequenze e trace](../Risultati/GUI_S33/raw_menu_toggle_cpu_20261028T093419Z/). Wrapper, dispatcher, callback e setter sono originali; lookup e aggiornamento UI sono fixture, eventi e RAM sono sintetici. Le finestre e le coppie evento/callback sono confrontate con il dump V1.1. La [precedente analisi statica del ramo RAW](S33_HiddenMenu_RAW_Massimo_20261027.md) collega la coppia flag/selettore alla lunghezza richiesta, non alla riuscita di una cattura o scrittura.

Questa prova non implementa Mono RAW Luminance, non verifica CFA, formato o buffer di un frame reale e non autorizza scritture sulla fotocamera. **NON_INSTALLARE**.
