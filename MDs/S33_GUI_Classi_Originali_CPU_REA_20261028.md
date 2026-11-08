# Classi originali delle schermate diagnostiche — 28 ottobre 2026

Due inizializzazioni CPU GNU ARC700 passano usando il lookup originale `0x145020`, la tabella classi V1.1 `0x77F728` (22 voci), i quattro wrapper originali e i rispettivi callback `0x4401`. La registrazione della tabella nel manager è impostata dal banco: non è stata eseguita la registrazione di avvio reale.

| Classe | Wrapper | Callback `0x4401` | Chiamate nella prova |
|---|---|---|---:|
| 7 | `0x6338E0` | `0x633914` | 2 |
| 2 | `0x6327FC` | `0x632830` | 3 |
| 1 | `0x6333FC` | `0x633430` | 2 |
| 9 | `0x6406D8` | `0x64070C` | 1 |

I sei oggetti TIME hanno classi `[7,2,2,2,1,1]`; i due ISO `[7,9]`. I callback 1 e 7 fanno ritorno senza operazioni visibili nel corpo eseguito; il callback 2 raggiunge `0x633170`, che per il bit `0x40` del flag letto non impostato esce dal ramo iniziale tutte e tre le volte. Il callback 9 raggiunge `0x6338A8` e `0x641284`. Non si generalizza ad altri flag o contesti.

Il banco verifica i byte dei percorsi e della tabella contro `DUMPS/MainCode.dmp`, conta le entrate nei callback nella trace e controlla risultati del manager e stack. [Script](../Python_Trace_Scripts/s33_verify_gui_debug_class_all_original_cpu.py), [evidenze CPU](../Risultati/GUI_S33/debug_class_original_handlers_cpu_20261028T092238Z/). L'esecuzione precedente senza blocco 3 è fallita per lettura non mappata ed è conservata in `debug_original_class_dispatch_cpu_20261028T092153Z`; il blocco è mappato nel test finale.

La copia locale MCP REA ARC ha letto 64 byte per ciascuno dei quattro wrapper e per `0x633170` e `0x64070C`, verificandoli contro il payload: [evidenza REA](../Risultati/GUI_S33/rea_gui_class_bytes_20261028T092255Z/evidence.json), [script](../Python_Trace_Scripts/s33_verify_rea_gui_class_bytes.py). È una verifica statica di byte, non prova di esecuzione né validazione di decompilazione o corpi funzione. Il provider ARC è sperimentale e Ghidra presenta limiti documentati in [Studio REA](S33_GUI_Studio_REA_20261027.md).

Manager e contesti iniziali sono sintetici; recupero controllo/risorsa, selezione ISO, testo e disegno sono fixture elencate in `fixture_patches.json`. Non sono dimostrati costruzione e visualizzazione reali, tasti fisici, modifica effettiva delle impostazioni, sensore o persistenza. Nessuna operazione sulla fotocamera: **NON_INSTALLARE**.
