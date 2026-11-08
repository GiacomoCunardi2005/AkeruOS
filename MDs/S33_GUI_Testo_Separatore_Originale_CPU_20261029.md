# GUI — separazione e ripristino con routine originale

Il 29 ottobre 2026 ho sostituito il separatore simulato della [prova precedente](S33_GUI_Testo_Scrittura_Temporanea_CPU_20261029.md) con la routine originale `0x186B14`, chiamata dal backend originale `0x186C40` su `ISO X`. Il banco imposta il flag `0x40`, usa una larghezza richiesta di 30 o 80 e sostituisce le metriche con valori sintetici: larghezza 10 per ogni carattere, classificazione a byte singolo e servizi metrici a zero. Il callback resta un registratore sintetico.

| Larghezza richiesta | Ritorno callback | Comportamento verificato |
|---:|---:|---|
| 80 | 1 | Nessuna separazione: il callback vede `ISO X`. |
| 30 | 0 | La routine sceglie lo spazio: il callback vede `ISO\0`; al ritorno il byte spazio è ripristinato. |
| 30 | 1 | Il callback vede prima `ISO\0`, poi `X`; lo spazio è ripristinato. |

**Tre casi PASS**; quattro chiamate alla routine originale di separazione complessive, store temporanei e ripristino verificati in traccia, stringa finale e stack conservati. [Verificatore](../Python_Trace_Scripts/s33_verify_gui_text_original_split_cpu.py), [casi](../Risultati/GUI_S33/text_original_split_cpu_20261029T225622Z/cases.json), [manifest e traccia](../Risultati/GUI_S33/text_original_split_cpu_20261029T225622Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/text_original_split_cpu_20261029T225622Z/fixture_patches.json).

Questo risultato collega la scelta dello spazio alla scrittura temporanea nel ramo e nelle metriche simulate, ma non stabilisce le larghezze del font Nikon, il wrapping del menu reale o il comportamento per tutte le codifiche. Callback, metriche e contesto sono fixture; non sono verificati concorrenza, memoria fisica, font, display o fotocamera. Firmware originale invariato; **NON_INSTALLARE**.
