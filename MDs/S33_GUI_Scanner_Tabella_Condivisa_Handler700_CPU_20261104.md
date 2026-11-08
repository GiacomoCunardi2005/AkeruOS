# Tasti, tabella condivisa e handler 0x700 — CPU emulata

Data: 2026-11-04; firmware campione 1.1. [Tabella condivisa: 33/33 PASS](../Risultati/GUI_S33/key_scanner_shared_cpu_20261104T105421812784Z/verified_evidence.json); [handler 0x700: 6/6 PASS](../Risultati/GUI_S33/key_scanner_handler700_cpu_20261104T105515534172Z/verified_evidence.json); [regressione tabella 33/33 PASS](../Risultati/GUI_S33/key_scanner_shared_cpu_20261104T105522672906Z/verified_evidence.json). Stato **NON_INSTALLARE**.

## Catena e condizioni

Il banco estende la [prova CaptureMenu](S33_GUI_Scanner_CaptureMenu_Tabella_CPU_20261104.md): esegue il default originale 0x20E814, che richiama il lookup originale 0x169F60 con tabella condivisa originale 0x3E8BB4. Byte e pool inclusa la tabella sono confrontati con i payload verificati anche dopo il link. Il percorso parte da scanner, generatore, fan-out, due callback, post/coda, estrazione e dispatcher originali; il banco estrae e invia esplicitamente i record dopo la sequenza pressione/rilascio.

Finestra corrente 0x9802AC o zero e controllo attivo 0 sono imposti; snapshot, RAM, latch, ordine delle callback, guardie, lock e segnale sono fixture. La lista esclusioni parte vuota. Handler finali 0x20EAF4, 0x20E940 e 0x20F414 sono intercettati nel primo banco; contatori distinti e log verificano nodo, evento e argomento. La scelta di un handler non ne dimostra gli effetti.

## Selezione degli handler

32 casi coprono quattro classi, due ordini delle callback, fixture `0xC9BF8` 0/1 e finestra corrente presente/nulla. Con finestra presente ed esclusioni vuote, tra gli eventi prodotti:

| Evento | Handler selezionato nella tabella condivisa |
|---|---|
| Pressione 0x700 | 0x20EAF4 |
| Pressione 0x2180 | 0x20E940 |
| Notifica 0x4006 | 0x20F414 |
| 0x580/581, 0x701, 0x2181, 0x2700/2701 | Nessun handler: terminatore della tabella con puntatore zero |

Questo vale solo se l'evento raggiunge la tabella: con `0xC9BF8=1` le classi 11/14 sono assorbite a monte, mentre 67/78 producono anche le notifiche grazie alla fixture `0xCB618=1`. Con finestra nulla non viene selezionato alcun handler. Il 33° caso impone 0x700 nella lista esclusioni e verifica che la sua pressione non raggiunga l'handler. Il comportamento di altre finestre o liste esclusioni non è stabilito.

## Handler 0x700 originale

Il secondo banco esegue anche 0x20EAF4 originale, dalle due sequenze scanner/coda con i due ordini, `0xC9BF8=0` e finestra corrente imposta. Getter 0xCAD5C e 0xCD9C8 sono stub; la richiesta 0x1453E4 è intercettata. Con tre valori di 0xCAD5C e `0xCD9C8=0x3F` si ottengono sei casi PASS:

| 0xCAD5C fixture | Richiesta osservata allo stub 0x1453E4 |
|---:|---|
| 0 | Nessuna |
| 1 | `(2, 0)` |
| 2 | `(0x3F, 0)`, con 0x3F restituito dalla fixture 0xCD9C8 |

Il risultato conferma il ramo dell'handler nelle condizioni imposte; non dimostra che 0x3F sia il valore reale in camera, che il manager accetti la richiesta, o che un menu venga aperto. Il rilascio 0x701 non seleziona un handler nella tabella condivisa in questi casi.

## Limiti e seguito

Nessun GPIO fisico, rendering o valore ISO/diaframma/tempo/monocromatico è verificato qui. Da integrare il servizio 0x1453E4 originale e la finestra eventualmente richiesta, oppure l'handler 0x2180 con le sue guardie e controllo attivo, senza assumere che i percorsi siano contemporaneamente abilitati. Concorrenza e lifecycle reali restano aperti.
