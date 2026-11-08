# S33 — percorso dell'evento Menu nella schermata di ripresa

Studio offline del firmware Nikon S33 V1.1, 27 ottobre 2026. Questa prova estende [lo studio precedente](S33_GUI_Ripresa_Tasti_e_Risorse_20261027.md): include il wrapper della schermata, oltre al dispatcher e all'handler già studiati.

## Percorso e risultati

Con evento `0x700` e tasto logico 14 immessi direttamente nel wrapper originale `0x6524f4`, il codice può passare al dispatcher originale `0x169f60`, che usa la tabella `0x7833ec` e chiama l'handler originale `0x65426c`. Nei casi provati le modalità `0x0a` e `0x46` producono una richiesta verso l'oggetto 2, identificato come `CaptureMenu`; la modalità `0x2c` produce una richiesta verso l'oggetto `0x9b`, identificato come `ImageMode`.

Prima della richiesta intervengono controlli: nei casi sintetici testati, tasto logico 1, 7 o 9 attivo, guardia `0xd0270` uguale a 1, oppure byte del contesto a offset 143 o 144 uguale a 1 bloccano la richiesta. In modalità `0x46`, il valore 1 del byte `0x681f09` blocca la richiesta, mentre il valore 2 la lascia passare; in modalità `0x0a`, il valore 1 non la blocca nel caso provato. Il significato funzionale di questo byte non è ancora stabilito.

Il wrapper passa anche un filtro a `0x681e80` al dispatcher. Nella prova, impostare sinteticamente l'elemento del filtro a `0x700` blocca l'evento; impostarlo a `0x4004` lo lascia passare. Questo non dimostra quale contenuto il filtro abbia durante l'uso reale.

## Verifica e limiti

Il test GNU ARC700 ha superato 14 scenari, con 4136 istruzioni complessive e stack preservato. Il wrapper, il dispatcher, l'handler e la tabella eventi sono originali; contesto, valori di stato e filtro sono preparati dal test. Undici servizi esterni sono fixture, tra cui il servizio `0x1453e4` che registra la richiesta anziché aprire una finestra reale. Le finestre di codice eseguite sono confrontate con `DUMPS/MainCode.dmp` e gli input sono verificati tramite hash.

La prova non esegue il tasto fisico, la coda eventi, lo scheduler, il WindowMgr o il rendering: registra una **richiesta** di apertura, non dimostra che il menu sia effettivamente visualizzato sulla fotocamera. Non identifica quale pulsante fisico corrisponda al tasto logico 14. Non è stato modificato o installato firmware.

- Script: [s33_verify_gui_liveview_wrapper.py](../Python_Trace_Scripts/s33_verify_gui_liveview_wrapper.py)
- Risultati e scenari: [verified_evidence.json](../Risultati/GUI_S33/liveview_wrapper_20261027T113310Z/verified_evidence.json)
- Comandi diagnostici dei tasti: [S33_GUI_Tasti_Comandi_Eventi_20261027.md](S33_GUI_Tasti_Comandi_Eventi_20261027.md)
