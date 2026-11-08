# Scanner tasti e due callback originali — CPU emulata

Data: 2026-11-04. Firmware campione 1.1; stato **NON_INSTALLARE**. Il banco [s33_verify_key_scanner_callbacks_cpu.py](../Python_Trace_Scripts/s33_verify_key_scanner_callbacks_cpu.py) produce [16/16 casi PASS](../Risultati/GUI_S33/key_scanner_callbacks_cpu_20261104T104338644241Z/verified_evidence.json). La regressione del [banco fan-out](../Risultati/GUI_S33/key_fanout_callbacks_cpu_20261104T104348628414Z/verified_evidence.json) passa 38/38 dopo il riuso del suo esecutore.

## Percorso e condizioni

In ogni caso vengono eseguiti byte originali del firmware, verificati rispetto ai payload dopo il link: inizializzazione della macchina tasti e tabella descrittori 0x392F04, scanner 0x16F86C, generatore 0x16F72C, fan-out 0x16F6B0, callback 0x16E588 e 0x323A00, getter modo, query tasto e millicode. Il banco imposta uno snapshot di ingresso a un bit, poi zero: lo scanner genera pressione e rilascio in una singola sequenza. Gli snapshot sono sintetici e non provengono da GPIO o fotocamera.

Sono imposti i due possibili ordini delle callback, modo 0x2C, latch e trigger zero, flag globale anello e bit della classe a 1, `0x16BC90=0`, `0xD0CA4=0`, `0xCB618=1`. `0xC9BF8` è una fixture variata fra 0 e 1. Stub per sincronizzazione, timer, servizi callback, controllo 0x17C150, post e anello; in particolare l'anello **non viene eseguito**. Il banco verifica gli argomenti delle chiamate, non il loro recapito. La tabella RAM delle callback e i record stato sono sintetici; nessuna prova dell'ordine reale o di concorrenza.

## Osservazioni

Quattro classi × due ordini × due valori di `0xC9BF8`: ogni sequenza verifica anche il ritorno a zero dello stato del record e dello snapshot dopo rilascio. Per ogni pressione lo stub di controllo 0x17C150 riceve la coppia attesa di codici.

| Bit sintetico | Classe | Pressione / rilascio | `0xC9BF8=0` | `0xC9BF8=1` |
|---:|---:|---|---|---|
| 12 | 11 | 0x580 / 0x581 | Due chiamate allo stub anello | Nessun post o chiamata anello |
| 7 | 14 | 0x700 / 0x701 | Due chiamate allo stub anello | Nessun post o chiamata anello |
| 8 | 67 | 0x2180 / 0x2181 | Due chiamate allo stub anello | Per ciascun evento, post 0x4006/classe e post evento/stato |
| 13 | 78 | 0x2700 / 0x2701 | Due chiamate allo stub anello | Per ciascun evento, post 0x4006/classe e post evento/stato |

Nel primo ramo gli argomenti delle chiamate all'anello sono `(0, evento, 0, 1)`. Nel secondo i post sono `(0, 0x4006, classe)` e `(0, evento, stato)` con stato 1 alla pressione e 0 al rilascio. Le conclusioni valgono per le fixture sopra; in particolare il secondo post dipende da `0xCB618=1`. Non generalizzare ai latch attivi o ad altre condizioni.

## Limiti e prosecuzione

Questa prova unisce scanner e callback, colmando il tratto lasciato separato dai banchi precedenti. Non dimostra che un particolare pulsante fisico corrisponda al bit, né che i post siano stati inseriti o consumati dalla coda, che una GUI sia stata visualizzata o che le impostazioni siano cambiate. Restano da integrare l'anello e il dispatcher originali con le rispettive condizioni e seguire le impostazioni fino ai consumatori reali.
