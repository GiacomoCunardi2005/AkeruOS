# S33 V1.1 — dispatcher diagnostico, pannello iride e setter nella stessa prova

Il 29 ottobre 2026 quattro sequenze GNU ARC700 eseguono nella stessa chiamata il dispatcher diagnostico originale `0x2C4FAC`, la tabella originale `0x406CF0` (`0x50 → 0x2C5074`), il pannello iride originale `0x2C5074` e il setter `0x18B85C`. Il banco invoca direttamente il dispatcher con selettore 0x50: non c'è ancora un collegamento dal menu esposizione o dal WindowManager.

| Stato software iniziale | Tasto logico simulato | Richiesta del pannello | Esito simulato della richiesta | Stato software finale | Ritorno dispatcher |
|---:|---:|---:|---|---:|---:|
| 9 | 9 | 1, testo Big | accettata | 1 | 1 |
| 1 | 10 | 9, testo Small | accettata | 9 | 1 |
| 9 | 9 | 1, testo Big | rifiutata | 9 | 1 |
| 1 | 10 | 9, testo Small | rifiutata | 1 | 1 |

Ogni caso verifica anche argomenti della richiesta `(handle 0x1234, stato, 1, 15000)`, sequenza delle letture dei tasti, numero di chiamate alle fixture e stack. La traccia conferma che la richiesta di testo precede la chiamata al setter nei quattro casi. Il ritorno del dispatcher **è 1 sia nell'accettazione sia nel rifiuto**: indica che il selettore corrispondente è stato trovato e chiamato, non la riuscita della regolazione. Anche lo stato finale qui è una cella software, non una misura ottica.

PASS: 4 casi, 2.249 istruzioni nel modello; [script](../Python_Trace_Scripts/s33_verify_iris_dispatch_panel_key_cpu.py), [casi](../Risultati/GUI_S33/iris_dispatch_panel_key_cpu_20261028T232335Z/cases.json), [manifest e traccia](../Risultati/GUI_S33/iris_dispatch_panel_key_cpu_20261028T232335Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/iris_dispatch_panel_key_cpu_20261028T232335Z/fixture_patches.json). I byte del dispatcher, della tabella e del pannello sono confrontati con il dump V1.1; il getter tasti restituisce una sequenza sintetica, le routine di inizializzazione, testo, attuazione e sincronizzazione sono sostituite da fixture. Il selettore e l'ordine sono imposti, senza scheduler o dispositivi fisici. La prova unisce i precedenti banchi separati del [dispatcher](S33_GUI_Iride_Dispatch_Diagnostico_CPU_20261028.md) e del [pannello](S33_GUI_Iride_Pannello_Esito_CPU_20261028.md); non prova l'apertura dal nuovo menu.

Il valore `0x50` nel dispatcher diagnostico **non è** l'ID della schermata iride nel WindowManager: in quest'ultimo la stessa cifra identifica `CardUnusable`. [Distinzione verificata](S33_GUI_Iride_Selettore_vs_Oggetto_20261028.md). Servono ancora un ponte GUI esplicito, una gestione di uscita e concorrenza, una conferma affidabile dello stato e la correlazione degli indici 1/9 con l'effetto ottico; il manuale descrive filtro ND e due passi in grandangolo, ma qui non vengono associati numeri f/ agli indici. Non sono stati verificati tasti fisici, display, movimento o scatto. Nessuna modifica a firmware, fotocamera o SD; **NON_INSTALLARE**.
