# S33 — lettore JPEG GUI in CPU emulata

Il 27 ottobre 2026 ho eseguito sette scenari GNU ARC700 con le routine originali V1.1 `0x159550` (configurazione), `0x7C9E38` (indice GUI) e `0x159558` (lettore). Il chiamante sintetico configura ogni caso, poi invoca la routine GUI. L'indice proviene dalla tabella originale `0x981734`; codice e tabella sono confrontati con `MainCode.dmp`.

| Scenario sintetico | Risultato osservato |
|---|---|
| Base zero, indice 1 | Lunghezza 2688, ritorno 0, nessuna chiamata backend; stato lettore 1. |
| Base `0x35C918`, indice 1 | Backend chiamato con offset `0x35C918`, lunghezza 2688; ritorno GUI 1. |
| Base `0x35C918`, indice 14 | Backend chiamato con offset `0x3670D1`, lunghezza 2715; ritorno GUI 1. |
| Base `0xD03000`, indice 14 | Backend chiamato con offset `0xD0D7B9`, lunghezza 2715; ritorno GUI 1. |
| Backend restituisce 9 | Ritorno GUI 0, stato lettore 9 e rilascio richiesto. |
| Lock restituisce 7 | Ritorno GUI 0; nessuna chiamata a lettore/backend o rilascio. La lunghezza era già stata scritta; lo stato precedente 9 rimane nel contesto. |
| Indice 0, lunghezza zero | Ritorno GUI 0, stato lettore 1, nessuna chiamata backend. |

Nei casi con backend, questo riceve selettore 6 e la destinazione sintetica attesa. La base osservata nel contesto al termine coincide con quella impostata: il rilascio **fixture** non la modifica. Questo non dimostra che il servizio reale conservi la base, né quale percorso la imposti nella fotocamera. Il backend fixture registra gli argomenti e restituisce il valore scelto: non copia né decodifica JPEG. Il successo è dunque soltanto quello del percorso sintetico.

Le chiamate a `0x302634`, acquisizione, rilascio e backend sono quattro sostituzioni esplicite nella sola immagine di laboratorio; le routine oggetto della verifica restano originali. Percorso sorgente nullo, indici, basi ed esiti sono impostati dal banco. Nessun filesystem, sincronizzazione reale, scheduling, display o hardware è stato eseguito. Non viene eseguita la funzione `0x2BEAFC`: `0xD03000` è un valore già individuato staticamente in quel percorso.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_jpeg_reader_cpu.py), [casi e risultati](../Risultati/GUI_S33/jpeg_reader_cpu_20261027T171339Z/cases.json), [sostituzioni fixture](../Risultati/GUI_S33/jpeg_reader_cpu_20261027T171339Z/fixture_patches.json), [trace](../Risultati/GUI_S33/jpeg_reader_cpu_20261027T171339Z/cases.trace). Analisi della [base nei file](S33_GUI_Base_JPEG_e_Lettore_20261027.md) e del [contesto condiviso](S33_GUI_Contesto_Condiviso_Lettore_20261027.md).
