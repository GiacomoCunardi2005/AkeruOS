# Dallo scanner alla tabella eventi CaptureMenu — CPU emulata

Data: 2026-11-04, firmware 1.1. [Verificatore](../Python_Trace_Scripts/s33_verify_key_scanner_table_cpu.py), [evidenze 34/34 PASS](../Risultati/GUI_S33/key_scanner_table_cpu_20261104T105222272628Z/verified_evidence.json), [regressione dispatcher 32/32 PASS](../Risultati/GUI_S33/key_scanner_dispatch_cpu_20261104T105231725781Z/verified_evidence.json). Stato **NON_INSTALLARE**.

## Catena eseguita

Il banco estende [scanner → coda → dispatcher](S33_GUI_Scanner_Coda_Dispatch_CPU_20261104.md) con il gestore originale 0x16A6E4, il risolutore callback 0x14505C, 0x16A028, il descrittore originale CaptureMenu 0x9802AC, la sua callback originale 0x7CAFE8 e il lookup originale 0x169F60 sulla tabella originale 0x982384. Codice, descrittore, tabella e pool provengono dai payload verificati e sono confrontati anche nell'ELF finale. La cella finestra corrente è imposta a 0x9802AC oppure zero; la cella del controllo attivo 0x366EAC è zero, così 0x16A6E4 prosegue verso la callback della finestra. Non si dimostra come questi stati siano raggiunti nella fotocamera.

Come nei banchi precedenti: snapshot, RAM, latch, ordine callback, guardie e sincronizzazione sono fixture; il banco estrae e invia esplicitamente i record dopo pressione e rilascio. Post e anello sono originali; segnale/lock sono stub. Gli **handler finali** della tabella CaptureMenu sono intercettati: lo stub di default a 0x20E814 registra nodo/evento/argomento; il controllo di corrispondenza intercetta 0x7CB0D8. Il default reale 0x20E814 e la successiva tabella condivisa non sono eseguiti.

La lista esclusioni 0x899858 è RAM sintetica azzerata, salvo il controllo esplicito qui sotto. Non si assume che tale lista sia vuota a runtime.

## Risultati

Nei 32 casi, quattro classi × due ordini × fixture `0xC9BF8` 0/1 × finestra impostata/nulla:

- Finestra 0x9802AC e `0xC9BF8=0`: pressione e rilascio di ciascuna classe raggiungono lo stub del **default 0x20E814**, con nodo, evento e argomento attesi.
- Finestra 0x9802AC e `0xC9BF8=1`: classi 11/14 non producono record; per 67/78 arrivano al default i quattro record `0x4006/classe`, pressione/1, `0x4006/classe`, rilascio/0, con `0xCB618=1`.
- Finestra nulla: nessun handler viene chiamato, anche se i record sono stati estratti.

La tabella CaptureMenu ha voci specifiche per 0x4401, 0x4405, 0x4406, 0x180 e 0x480, seguite dalla voce terminatrice con default 0x20E814: non contiene voci specifiche per le quattro coppie 0x580/581, 0x700/701, 0x2180/2181, 0x2700/2701 né per 0x4006. Questo **non** significa che gli eventi siano ignorati: il default reale prosegue verso un'altra tabella.

Controlli supplementari: evento 0x180 iniettato direttamente al dispatcher seleziona lo stub della voce specifica 0x7CB0D8 e non il default; impostando artificialmente 0x700 nella lista esclusioni, la pressione 0x700 non raggiunge il default mentre il rilascio 0x701 sì. Totale 34 casi.

## Limiti e prossima prova

Non sono stati eseguiti il default 0x20E814, il suo lookup nella tabella condivisa 0x3E8BB4, i controlli di classe, il rendering o l'apertura di sottomenu. Il test non prova GPIO, tasti fisici o variazione delle impostazioni. Il prossimo passo è eseguire il default e la tabella condivisa fino all'handler effettivamente selezionato, con controlli attivi e stato della finestra esplicitati.
