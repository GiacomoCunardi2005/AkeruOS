# Snapshot → menu → setter iride: CPU emulata V1.1

Data 2026-11-04. Il banco esegue lettore snapshot su MMIO simulato, callback, normalizzatore, scanner e coda originali; estrae e consegna esplicitamente pressione/rilascio al dispatcher. Un descrittore/callback sintetico inoltra al modello C già predisposto sulla pagina esposizione. Per l'azione `OPEN_APERTURE` il banco preleva la richiesta e chiama direttamente il setter originale `0x18B85C` con lo stato **scelto dal banco**. La scelta 1/9 non è ancora un sottomenu realizzato. Le finestre originali, incluso il pool del parametro `0x3A98`, sono verificate byte per byte dopo il link.

**14/14 PASS**: sette condizioni × due ordini delle callback. La classe logica 67 (`0x2180/2181`) produce la richiesta iride:

| Stato iniziale → richiesto | Esito servizi fixture | Stato software finale |
|---|---|---:|
| 9 → 1 | accettazione | 1 |
| 9 → 1 | acquisizione rifiutata | 9 |
| 9 → 1 | guardia rifiutata | 9 |
| 9 → 1 | richiesta rifiutata | 9 |
| 9 → 9 | già uguale, nessuna richiesta | 9 |
| 1 → 9 | accettazione | 9 |

Il caso di controllo usa classe logica 14: produce la richiesta ISO e non invoca il setter iride. Per i casi che raggiungono la richiesta, sono verificati argomenti `(0x1234, stato richiesto, 1, 0x3A98)` e chiamate di acquisizione, guardia, rilascio e cleanup secondo i rispettivi rami. Il servizio di richiesta è uno **stub**, quindi il suo valore di ritorno rappresenta soltanto l'esito predisposto. Il risultato di stato software non conferma movimento o posizione ottica.

Questa prova estende il [setter isolato](S33_GUI_Iride_Esiti_Setter_Prova_CPU_20261027.md) e il [ponte snapshot → menu](S33_GUI_Snapshot_Modello_Quattro_Tasti_CPU_20261104.md); non esegue il pannello diagnostico né dimostra che una scelta nel menu possa chiamare direttamente il setter nel runtime reale. Snapshot, callback registrato, finestra, scelta, stato, sincronizzazione e servizi sono fixture o stub; monitor input, scheduler, rendering, tasti fisici, concorrenza AE, posizione del filtro, calibrazioni e scatto non sono verificati. In particolare, non associare gli stati 1 e 9 a valori f/ senza riscontro fisico. Nessuna scrittura su dispositivo, SD o firmware. **NON_INSTALLARE**.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_snapshot_menu_iris_setter_cpu.py`; [evidenze 14/14](../Risultati/GUI_S33/key_snapshot_menu_iris_cpu_20261104T160201249226Z/verified_evidence.json). Regressioni snapshot → menu [16/16](../Risultati/GUI_S33/key_snapshot_menu_bridge_cpu_20261104T160214545303Z/verified_evidence.json) e sequenza tempo [4/4](../Risultati/GUI_S33/key_scanner_menu_time_cpu_20261104T160214542916Z/verified_evidence.json).
