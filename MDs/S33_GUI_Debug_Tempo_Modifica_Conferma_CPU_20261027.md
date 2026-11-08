# S33 V1.1 — modifica e conferma del tempo nella stessa prova CPU

Il 27 ottobre 2026 ho eseguito in GNU ARC700 una sequenza continua per ciascuno di cinque scenari sintetici: uno o due richiami diretti agli handler originali su/giù di `DebugModeExpTime`, quindi il callback originale di conferma `0x7D2394` e i setter originali. La tabella eventi e le finestre sono confrontate con il dump V1.1. Il test avvicina le due [prove precedenti](S33_GUI_Debug_Tempo_Tasti_CPU_20261027.md), senza però eseguire un'intera sessione della GUI.

| Word iniziale | Eventi iniettati direttamente | Word dopo modifica | Due campi dopo conferma |
| ---: | --- | ---: | ---: |
| 0 | su, giù | 119 | 119.000 / 119.000 |
| 120 | su, su | 122 | 122.000 / 122.000 |
| 3999 | su | 0 | 0 / 0 |
| 1 | giù | 0 | 0 / 0 |
| 2 | giù, su | 2 | 2.000 / 2.000 |

In ciascun caso i due campi `0x365788` e `0x37FBF4` partono dal valore sentinella `0x12345678` e **restano invariati dopo la sola modifica**; la conferma scrive in entrambi la word modificata moltiplicata per 1000. Il test verifica anche il numero di richieste timer e una richiesta di apertura `0x1453E4(0x36,0)`. Il servizio di apertura registra soltanto gli argomenti.

Sei servizi di formato, risorsa, testo, refresh, timer e apertura sono fixture; contesto, input e chiamate sono sintetici. Non si osservano eventi fisici, ripetizione timer, disegno, significato delle unità, AE o scatto. In particolare la prova termina immediatamente dopo la conferma: altre routine possono modificare un campo successivamente, come mostrato separatamente nelle [prove sulle sovrascritture](S33_GUI_Tempo_Sovrascritture_e_Snapshot_20261027.md). Nessuna alterazione hardware o SD; candidati **NON_INSTALLARE**.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_debug_time_session_cpu.py), [cinque casi](../Risultati/GUI_S33/debug_time_session_cpu_20261027T214606Z/cases.json), [fixture](../Risultati/GUI_S33/debug_time_session_cpu_20261027T214606Z/fixture_patches.json), [finestre GNU](../Risultati/GUI_S33/debug_time_session_cpu_20261027T214606Z/gnu_windows.txt), [risultato e hash](../Risultati/GUI_S33/debug_time_session_cpu_20261027T214606Z/verified_evidence.json).
