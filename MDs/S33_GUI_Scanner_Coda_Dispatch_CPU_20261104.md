# Scanner, coda e dispatcher fino al gestore di consegna — CPU emulata

Data 2026-11-04; firmware campione 1.1. [Verificatore](../Python_Trace_Scripts/s33_verify_key_scanner_dispatch_cpu.py), [evidenze 32/32 PASS](../Risultati/GUI_S33/key_scanner_dispatch_cpu_20261104T104837112090Z/verified_evidence.json). Regressioni dopo l'estensione: [coda 16/16](../Risultati/GUI_S33/key_scanner_queue_cpu_20261104T104826377358Z/verified_evidence.json), [scanner 16/16](../Risultati/GUI_S33/key_scanner_callbacks_cpu_20261104T104826372700Z/verified_evidence.json). **NON_INSTALLARE**.

## Percorso e condizioni

La prova estende il [banco scanner/coda](S33_GUI_Scanner_Coda_Due_Callback_CPU_20261104.md): scanner, generatore, due callback, post, inserimento ed estrazione in coda sono originali, come anche dispatcher 0x169E1C, risolutore finestra corrente 0x1453F4 e 0x169D78. Le finestre di codice e i pool caricati sono confrontati con i payload verificati dopo il link. Il punto 0x16A6E4 è uno **stub di consegna**, che registra destinazione, evento e argomento; non esegue il comportamento della finestra.

Snapshot, RAM, ordine delle callback, guardie, lock e segnale rimangono fixture come nel banco coda; in particolare `0xCB618=1`, i latch sono azzerati e la coda parte vuota. Il banco imposta la cella della finestra corrente 0x366EA4 a 0x9802AC oppure zero. 0x9802AC è un valore di destinazione imposto, non si legge né si attiva il descrittore in questo test. Il banco estrae tutti i record e **poi chiama esplicitamente il dispatcher per ciascun record**: non gira il ciclo WindowManager, né si dimostra che la finestra corrente resti invariata fra eventi reali.

## Osservazioni

Quattro classi × due ordini × fixture `0xC9BF8` 0/1 × finestra corrente presente/nulla = 32 casi. Con destinazione 0x9802AC, lo stub a 0x16A6E4 riceve ogni record estratto nell'ordine e con evento e argomento verificati:

| Fixture `0xC9BF8` | Classe | Chiamate allo stub di consegna |
|---|---|---|
| 0 | 11, 14, 67, 78 | Due: pressione e rilascio, argomento 0 |
| 1 | 11, 14 | Zero: nessun record in coda |
| 1 | 67, 78 | Quattro: 0x4006/classe, pressione/1, 0x4006/classe, rilascio/0 |

Con cella finestra zero, nessuna di queste chiamate raggiunge lo stub, anche quando la coda contiene record. Il banco controlla separatamente contenuto e indici di inserimento/estrazione. I risultati valgono solo per le fixture, inclusi `0xCB618=1` e l'ordine imposto; non stabiliscono l'ordine sulla fotocamera.

## Limiti e passo successivo

La catena arriva fino all'**ingresso del gestore di consegna**, non al callback della finestra o a un menu visibile. Da integrare 0x16A6E4 e il callback reale della finestra con dati originali e condizioni esplicite, oltre al ciclo WindowManager e al collegamento con i valori di impostazione. Non è stata verificata la corrispondenza dei bit con i pulsanti fisici e nessuna impostazione è stata cambiata su hardware.
