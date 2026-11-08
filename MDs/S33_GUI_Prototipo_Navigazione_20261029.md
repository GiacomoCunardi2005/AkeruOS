# Prototipo isolato di navigazione per la GUI S33

Il 29 ottobre 2026 è stato aggiunto un piccolo modello C della navigazione richiesta, in [`AkeruOS/ui/menu.c`](../AkeruOS/ui/menu.c) e [`menu.h`](../AkeruOS/ui/menu.h). È un componente offline, non collegato al firmware o ai tasti fisici. I numeri qui sotto sono **posizioni logiche proposte**, non un mapping misurato dei pulsanti sulla S33.

| Schermata modello | Posizione 1 | Posizione 2 | Posizione 3 | Posizione 4 |
|---|---|---|---|---|
| Principale | Apri esposizione | Apri colore/mono | Nessuna azione: da decidere | Richiedi impostazioni |
| Esposizione | Indietro | Richiedi ISO | Richiedi f/ | Richiedi tempo |
| Colore/mono | Indietro | Richiedi colore standard | Richiedi Mono RAW Luminance | Nessuna azione |

Un tasto fornisce un'azione al chiamante; le richieste ISO, f/, tempo, colore, mono e impostazioni **non applicano valori**, non dichiarano successo e non cambiano la schermata modello. Aprire, gestire la conferma, riportare gli errori e fare il ritorno dal controllo esterno sono responsabilità del futuro collegamento. Il modello non inventa range di esposizione, una modalità mono esistente o una destinazione per il terzo tasto. Non deduce pressioni/rilasci dagli eventi originali: occorre un adattatore verificato.

[`menu_test.c`](../AkeruOS/tests/menu_test.c) verifica tutte le 12 combinazioni schermata/posizione, le transizioni e i percorsi di ritorno, le richieste senza cambio di schermata, tasto fuori intervallo, stato invalido e puntatore nullo. `make -C AkeruOS menu-model-verify` compila ed esegue lo stesso test su host con UBSan e su GNU ARC700 isolato: **PASS, 573 istruzioni nel modello**, nessun simbolo irrisolto. [Verificatore](../Python_Trace_Scripts/s33_verify_akeru_menu.py) e [manifest](../Risultati/GUI_S33/akeru_menu_model_20261028T233107Z/verified_evidence.json).

Mancano il rendering, la mappa fisica dei quattro tasti, il lifecycle WindowManager, il contesto dei ritorni, i backend realmente applicabili di ISO/tempo/f/, la pipeline mono su fotocamera e l'accesso alle impostazioni originali. Il modello è un punto di partenza per collegare e testare questi componenti, non una GUI completa o un firmware avviabile. Nessun accesso a camera/SD, **NON_INSTALLARE**.

## Adattatore eventi logici — 29 ottobre 2026

**Aggiornamento:** l'evento logico `0x480` ora richiede il ritorno alla live view dalla principale o ritorna alla principale dai sottomenu; `0x481` è consumato senza azione. La destinazione effettiva non è collegata. [Prova e limiti](S33_GUI_Modello_Ritorno_Evento_20261029.md).

Il modello espone ora `akeru_menu_event`: in base alle prove della classe 0x15 mappa gli eventi **iniettati** `0x580`, `0x700`, `0x2180`, `0x2700` alle posizioni 1–4 rispettivamente. Le controparti di stato zero `0x581`, `0x701`, `0x2181`, `0x2701` sono consumate senza azioni o cambio schermata; la loro polarità fisica non è provata. Gli eventi estranei non sono consumati. Anche la posizione principale 3 è consumata senza azione, così un chiamante che rispetti il risultato non la inoltra al menu padre: ciò evita nel modello la ricaduta sintetica già documentata, non dimostra l'integrazione nel dispatcher originale. Puntatori o schermata invalidi danno errore senza cambiare lo stato.

Il test ora controlla tutte le 12 coppie schermata/evento, le 12 controparti di stato zero, il terzo slot, l'evento estraneo e input invalidi. Host UBSan e GNU ARC700 PASS: [manifest aggiornato](../Risultati/GUI_S33/akeru_menu_model_20261028T233204Z/verified_evidence.json); gli ID sono forniti direttamente dal test, non dalla coda originale. Il chiamante deve usare il risultato `1` consumato, `0` estraneo, `-1` invalido. Nessuna associazione con i pulsanti fisici o esecuzione della nuova GUI sulla camera è dimostrata.
