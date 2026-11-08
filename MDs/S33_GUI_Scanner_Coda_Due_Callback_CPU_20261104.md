# Scanner, callback e coda eventi originali — CPU emulata

Data: 2026-11-04; firmware campione 1.1. [Verificatore](../Python_Trace_Scripts/s33_verify_key_scanner_queue_cpu.py), [evidenze 16/16 PASS](../Risultati/GUI_S33/key_scanner_queue_cpu_20261104T104618500197Z/verified_evidence.json). Regressioni: [scanner/callback 16/16](../Risultati/GUI_S33/key_scanner_callbacks_cpu_20261104T104626085813Z/verified_evidence.json) e [fan-out 38/38](../Risultati/GUI_S33/key_fanout_callbacks_cpu_20261104T104626085233Z/verified_evidence.json). **NON_INSTALLARE**.

## Ambito

Un unico banco GNU ARC700 esegue su byte originali verificati contro i payload: inizializzazione e scanner 0x16F86C, generatore 0x16F72C, fan-out 0x16F6B0, callback 0x16E588 e 0x323A00, post 0x169EB4, inserimento anello 0x17BC7C, estrazione 0x17BD4C e millicode. Il banco estrae esplicitamente tutti i record attesi **dopo** aver generato pressione e rilascio; non esegue il ciclo del WindowManager. I byte sono ricontrollati nell'ELF risultante.

Input, RAM, ordine delle callback e condizioni runtime sono sintetici: bit dello snapshot, modo 0x2C, latch e trigger zero, `0x16BC90=0`, `0xD0CA4=0`, `0xCB618=1`, gate anello/bit classe abilitati; `0xC9BF8` varia tra 0 e 1. Stub per servizi delle callback, timer, 0x17C150, lock/sezioni critiche e segnale: il lock restituisce 1, i contesti di coda e hook partono azzerati. Non prova la sincronizzazione, il risveglio del task o la conservazione dopo riavvio.

## Risultati

Quattro classi × due ordini delle callback × due valori fixture `0xC9BF8`; per ciascuna sequenza il banco verifica anche l'array di codici richiesto a 0x17C150, lo stato tasto tornato a zero e le chiamate allo stub di segnalazione. Per ogni record atteso controlla valori e ordine sia nell'anello sia nel buffer scritto dall'estrattore; indici lettura e scrittura avanzano fino allo stesso valore.

| Fixture 0xC9BF8 | Classe | Record inseriti ed estratti, nell'ordine `(destinazione, evento, argomento)` |
|---|---|---|
| 0 | 11, 14, 67, 78 | `(0, pressione, 0)`, `(0, rilascio, 0)` |
| 1 | 11, 14 | Nessun record; nessuna segnalazione |
| 1 | 67, 78 | `(0, 0x4006, classe)`, `(0, pressione, 1)`, `(0, 0x4006, classe)`, `(0, rilascio, 0)` |

I codici pressione/rilascio sono rispettivamente 0x580/0x581, 0x700/0x701, 0x2180/0x2181, 0x2700/0x2701. Lo stub del segnale viene chiamato una volta per inserimento: due, zero o quattro secondo la riga. Il ramo con post evento dipende dalla fixture `0xCB618=1`. La prova non copre coda piena, interleaving, tempi reali o altre callback e guardie.

## Limiti e prossimo collegamento

La coda parte vuota, l'estrazione è esplicita e il dispatcher non viene chiamato: questi risultati non provano che una finestra riceva gli eventi o che un menu appaia. I bit non sono ancora associati a pulsanti fisici; nessun valore ISO, diaframma, tempo o monocromatico è stato cambiato in questa prova. Prossimo passo: eseguire il ciclo estrazione → dispatcher su una finestra originale, preservando le condizioni del banco e verificando sia i casi con record sia l'assenza di consegna dei casi assorbiti.
