# S33 V1.1 — scelte flash e valori, 31 ottobre 2026

La tabella `0x784640` del menu rapido contiene quattro record originali, passo 28. Il testo, risolto condizionalmente tramite i blocchi di lingua verificati sul file, e il campo `+16` sono:

| Record | Testo italiano | Campo +16 | Evento testato |
|---|---|---:|---:|
| `0x784640` | Flash | 0 | intestazione |
| `0x78465C` | Flash auto | 4 | `0x0700` |
| `0x784678` | No flash | 1 | `0x2180` |
| `0x784694` | Flash sempre attivo | 8 | `0x2700` |

Questa associazione di evento è verificata nel banco descritto sotto, con contesto sintetico specifico; non identifica i pulsanti fisici. Il collegamento delle stringhe è condizionale al percorso originale di caricamento e ai blocchi italiano/inglese, non dimostra la lingua o la schermata realmente visualizzata.

## Prova CPU

Il [verificatore](../Python_Trace_Scripts/s33_verify_gui_flash_choices_cpu.py) esegue wrapper `0x6646C0`, dispatcher, handler `0x664890/0x664904/0x664970`, getter `0x631DB8/0x631DD0/0x631DE8`, selezione `0x632694 → 0x631D60`, setter `0xCDE44` e getter `0xCDC80` originali. I record sono quelli del dump V1.1, verificati byte per byte; il contesto del menu e la consegna degli eventi sono sintetici. I getter di riga sono impiegati con `+47 = 4`, `+52 = 4` per evitare il ramo paginato, che richiede ulteriori condizioni.

Nove casi PASS: le tre scelte per ciascuna delle modalità fornite dal banco `0x2C`, `0x46` e `0x08`. Per `0x2C`, il setter scrive 4/1/8 nel byte `0xC8EC0E`, il getter lo rilegge e la funzione successiva, sostituita con un registratore, riceve 4/1/8. Per `0x46`, il byte corrispondente è `0xC8EC0D`, e la stessa rilettura avviene quando la fixture della guardia `0xCE8F0` restituisce 1. Nell'esempio `0x08`, il setter non modifica i due byte osservati e il getter fornisce 26: il valore passato alla fixture successiva non coincide con il valore di menu. Questo non dimostra il supporto o l'uso effettivo del menu flash in tale modalità.

In tutti i casi la fixture di apertura riceve oggetto `0x87`, argomento 0, e lo stack è preservato. Pseudo-C Ghidra del setter e getter è stato confrontato con istruzioni e CPU; non è codice sorgente certificato. [Evidenze](../Risultati/GUI_S33/flash_choices_cpu_20261031T160102042981Z/), con scelta, casi, patch fixture, finestre GNU e traccia. Due run esplorativi precedenti sono registrati FAIL per un limite di finestra del disassemblatore dopo le verifiche CPU, non usati come PASS.

Modalità, guardia, contesto, filtro, servizi applicativi, notifiche e apertura sono fixture; `0xDE3A4` non viene eseguita. Non sono dimostrati persistenza, trasmissione all'elettronica, impulso flash, UI fisica o compatibilità in ogni modo. Questo individua un possibile raccordo software, non autorizza a scrivere i byte in camera. Candidati **NON_INSTALLARE**.
