# GUI — scrittura temporanea della stringa nel backend testo

Il 29 ottobre 2026 ho eseguito in GNU ARC700 la routine originale `0x186C40` su una stringa sintetica scrivibile `ISO X`. Il banco imposta il contesto e sostituisce `0x186B14` con una fixture che restituisce il puntatore allo spazio oppure zero; anche il callback è una fixture che registra i byte osservati e restituisce un valore deciso dal banco.

| Separatore restituito dalla fixture | Ritorno callback | Osservazione |
|---|---:|---|
| Nessuno | 1 | Una chiamata vede `ISO X`; la stringa resta invariata. |
| Spazio dopo `ISO` | 0 | Una chiamata vede `ISO\0`; dopo il ritorno lo spazio viene ripristinato. |
| Spazio dopo `ISO` | 1 | La prima chiamata vede `ISO\0`; lo spazio è ripristinato e la seconda chiamata riceve `X`. |

**Tre casi PASS**: contenuto della stringa dopo la routine identico all'iniziale, stack conservato; la traccia esegue i due store di azzeramento e ripristino nei due casi con separatore. [Verificatore](../Python_Trace_Scripts/s33_verify_gui_text_temporary_write_cpu.py), [casi](../Risultati/GUI_S33/text_temporary_write_cpu_20261029T225548Z/cases.json), [manifest e traccia](../Risultati/GUI_S33/text_temporary_write_cpu_20261029T225548Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/text_temporary_write_cpu_20261029T225548Z/fixture_patches.json).

La scelta del punto di separazione e il callback sono simulati: la prova non esegue `0x186B14` originale, font o display. Non copre interruzioni, callback che non torna o letture concorrenti durante la modifica; non prova se o quando questo ramo venga usato nel menu reale. Rimane necessario identificare memoria scrivibile e lifetime delle etichette. Nessun firmware o dispositivo modificato; **NON_INSTALLARE**.
