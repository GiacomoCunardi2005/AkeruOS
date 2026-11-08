# Modello esposizione e pannello diagnostico iride

Il 29 ottobre 2026 ho collegato nel [banco CPU](../Python_Trace_Scripts/s33_verify_gui_model_iris_panel_cpu.py) la richiesta diaframma del modello C al percorso diagnostico originale già studiato. Il banco passa l'evento sintetico `0x2180` al modello predisposto in schermata esposizione; solo se riceve `AKERU_OPEN_APERTURE` chiama direttamente il dispatcher diagnostico `0x2C4FAC` con selettore `0x50`. Il dispatcher esegue il pannello originale `0x2C5074` e il setter `0x18B85C`.

| Stato iniziale | Tasto diagnostico simulato | Stato richiesto | Esito fixture | Stato software finale |
|---:|---:|---:|---|---:|
| 9 | 9 | 1 | accettato | 1 |
| 1 | 10 | 9 | accettato | 9 |
| 9 | 9 | 1 | rifiutato | 9 |
| 1 | 10 | 9 | rifiutato | 1 |

Un quinto caso passa al modello l'evento ISO `0x700` e verifica che il banco non chiami il dispatcher iride. [Cinque casi PASS](../Risultati/GUI_S33/model_iris_panel_cpu_20261029T052710Z/verified_evidence.json), 2.460 istruzioni: verificati azione, argomenti della richiesta, stato software, testo richiesto e stack. Il dispatcher ritorna 1 sia con accettazione sia con rifiuto: quel ritorno non conferma l'esito della regolazione. [Casi](../Risultati/GUI_S33/model_iris_panel_cpu_20261029T052710Z/cases.json), [fixture](../Risultati/GUI_S33/model_iris_panel_cpu_20261029T052710Z/fixture_patches.json) e traccia nel manifest.

Il collegamento è eseguito dal banco, non dal firmware o dal WindowManager; `0x50` è un selettore diagnostico, non un ID finestra. Input del pannello, esito dell'attuatore e altri servizi sono simulati. Il testo è richiesto prima dell'esito, quindi non dimostra lo stato effettivo. Non sono stabiliti corrispondenza degli stati 1/9 con numeri f/, movimento ottico, uscita dal pannello, concorrenza con AE, pulsanti fisici o scatto. Firmware originale e fotocamera non modificati; **NON_INSTALLARE**.
