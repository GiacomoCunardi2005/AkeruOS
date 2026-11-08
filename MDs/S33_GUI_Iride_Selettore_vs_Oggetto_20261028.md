# Iride — selettore diagnostico e ID schermata sono distinti, 28 ottobre 2026

Il valore `0x50` ha due significati diversi nel firmware V1.1:

| Contesto | Risoluzione statica |
|---|---|
| Tabella del dispatcher diagnostico `0x2C4FAC` | `0x406CF0`: `0x50 → 0x2C5074`, ingresso del pannello iride |
| Tabella oggetti WindowMgr `0x3F5900` | indice `0x50 → 0x99C924`, descrittore con ID `0x50` e nome `CardUnusable` |

Non si può quindi mettere semplicemente `0x50` nella destinazione della lista esposizione aspettandosi il pannello iride. Nella nuova [prova GNU](../Risultati/GUI_S33/iris_selector_namespace_cpu_20261028T144749Z/verified_evidence.json), il terzo record della lista sintetica contiene `0x50`: l'handler originale dell'evento `0x2180` inoltra `0x50` alla **fixture** del servizio di apertura WindowMgr. Non apre davvero la schermata e non chiama il dispatcher diagnostico. Quattro slot sono verificati in totale; [banco](../Python_Trace_Scripts/s33_verify_gui_iris_selector_namespace_cpu.py).

Un ulteriore limite emerge dalla [precedente traccia diagnostica](../Risultati/GUI_S33/iris_diagnostic_dispatch_cpu_20261028T144635Z/cases.trace): la fixture dell'ingresso iride restituisce `0`, ma subito dopo `0x2C5036` imposta `r0=1`. In quel caso il valore 1 del dispatcher segnala che la voce è stata trovata e chiamata, non che il pannello o l'iride abbiano avuto successo.

[Audit riproducibile](../Python_Trace_Scripts/s33_audit_gui_iris_selector_namespace.py) PASS: verifica le due tabelle, il descrittore e il nome confrontandoli col dump V1.1, controlla gli hash delle tracce e il risultato della richiesta al servizio simulato. La scansione del listato lineare disponibile non ha individuato chiamate dirette a `0x2C4FAC`; non esclude chiamate indirette, riferimenti calcolati o errori di confine. Serve un ponte esplicito e verificato fra WindowMgr e gestione diagnostica, con ciclo di vita e ritorno definiti. Nessun tasto fisico, display, attuatore o scatto è stato verificato; **NON_INSTALLARE**.
