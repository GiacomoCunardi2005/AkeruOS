# S33 — richiesta, esecuzione e risultato del servizio JPEG

Analisi statica del 17 ottobre 2026, continuazione del protocollo Recorder Still.

È stato ricostruito un confine concreto da conservare nella futura applicazione essenziale: **parametri condivisi → avvio del lavoro → attesa → lettura separata del risultato**. Il task JPEG esegue callback diverse; il nome del task non basta a identificare una codifica fotografica. Non abbiamo ancora una funzione completa “scatta e salva” utilizzabile dal nuovo firmware.

## Registrazione del produttore Recorder Still

A `0x12f746` il codice carica il puntatore `0x130a94` dal letterale `0x12f934`; a `0x12f748` lo scrive in `0x4425b0 + 0x28 = 0x4425d8`. Questo identifica il punto che registra la callback analizzata in precedenza. La ricerca della rappresentazione uint32 little-endian nei 16 blocchi ha trovato una sola occorrenza, a `0x12f934` nel blocco 00.

Il chiamante indiretto che legge questa registrazione, o una sua copia, resta da identificare. Il conteggio delle occorrenze non esclude puntatori calcolati o copiati. La callback passa un indice di buffer al worker: non è stata collegata al pulsante fisico.

## Servizio JPEG: una callback condivisa

| Elemento | Osservazione |
|---|---|
| Task | `0x15a764`, associato a `ImgMgrJPEGTask` nella tabella già verificata |
| Cella callback | `0x367384` |
| Oggetto evento | `0x70000a` |
| Segnale di richiesta | `0x10000` |
| Segnale di fine esecuzione | `0x20000` |
| Invio | `0x15a7a8` |
| Attesa di fine esecuzione | `0x15a798` |

La funzione di invio rifiuta il puntatore nullo con il valore `0x700001`. Altrimenti richiama l'attesa di fine esecuzione precedente e, se questa restituisce zero, salva la callback, cancella `0x20000` e imposta `0x10000`.

Il worker attende `0x10000`, cancella entrambi i bit con maschera `0x30000`, chiama indirettamente la callback non nulla e imposta `0x20000`. **Non usa il valore di ritorno della callback per decidere se impostare quel bit.** Fine esecuzione e successo sono quindi due condizioni distinte.

Questo helper usa una singola cella, non una coda di richieste visibile nel codice esaminato. Non abbiamo dimostrato che l'invio sia sicuro tra chiamanti concorrenti: il controllo di disponibilità e la scrittura della cella non bastano a provarlo. Per la futura applicazione la scelta prudente è un solo proprietario del servizio, conservando la sincronizzazione originale.

## Parametri ed esito: un percorso verificato

| Funzione | Trasferimento osservato attraverso la routine di copia `0x128c20` |
|---|---|
| `0x13b758` | Copia 176 byte dal chiamante a `0x44288c` |
| `0x13b774` | Copia 176 byte da `0x44288c` al chiamante |
| `0x13b790` / `0x13b7ac` | Coppia analoga per `0x44293c` |
| `0x13b7c8` / `0x13b7e4` | Scrittura/lettura di un risultato di 32 byte in `0x4429ec` |
| `0x13b800` | Scrittura della variante di risultato in `0x442a0c` |

Nel ramo a `0x1e29d4–0x1e2a3e` il codice sceglie il canale dei parametri, invia la callback `0x22ab64`, attende tramite `0x15a798` e legge il risultato tramite `0x13b7e4`. Se non ha già rilevato un errore, legge una parola all'offset **28** dei 32 byte restituiti.

La callback `0x22ab64` deposita una parola nello stesso offset 28 prima di pubblicare il risultato. Il suo significato completo e i possibili valori non sono ancora decodificati. Questo collegamento prova lo scambio separato dell'esito, non che il percorso sia il normale salvataggio di una fotografia.

Un'altra callback, `0x26c8a4`, usa la stessa coppia parametri/risultato e richiama servizi nel blocco 02, fra cui `0x60d938`. Quest'ultimo seleziona `0x6111c0` oppure `0x61290c` in base a uno stato globale. Le finestre analizzate mostrano ulteriori attese su eventi e gestione di buffer; non è stata ricostruita tutta questa callback.

Il percorso `0x24156c → 0x2410a4`, anch'esso eseguito dal task JPEG, esamina un buffer e confronta coppie di byte `FF D8`, `FF C4`, `FF DB`, `FF DD`, `FF C0`, `FF E0`. È una pista di lettura/elaborazione di dati JPEG già presenti, da non confondere automaticamente con l'acquisizione dal sensore.

## Impatto sul firmware essenziale

La nuova interfaccia può essere piccola, ma deve rispettare proprietà e durata dei buffer, attese del worker e lettura dell'esito. Saltare una di queste fasi per anticipare lo scatto successivo potrebbe riutilizzare dati ancora in lavorazione. Non ci sono ancora misure che attribuiscano il ritardo di scatto alla grafica o dimostrino un guadagno rimuovendola.

La [continuazione sul salvataggio](S33_Salvataggio_e_Chiusura.md) ricostruisce un percorso fra lavoro di elaborazione, JPEG e scrittura/chiusura del file. Restano da collegare la richiesta fotografica del pulsante, l'inizializzazione del bit di disponibilità JPEG e l'ABI completa prima di chiamare questi indirizzi da codice nuovo.

## Riproducibilità e limiti

[Script](../outputs/trace_s33_jpeg.py), [mappa](../outputs/s33_jpeg_map.json), [finestre disassemblate](../outputs/s33_jpeg_disassembly.txt), [evidenza REA del primo passaggio](../outputs/s33_rea_jpeg_evidence.json). Script e output sono stati successivamente estesi al salvataggio; il bundle citato conserva la verifica iniziale di 18 finestre.

Il processo REA `ev_78cd7d676c70ca76382bcd7a2e5b643b66a38adf717c0678d61f8a2e213afb39` è terminato con codice 0, senza troncamenti. Lo script verifica lunghezza e SHA-256 di 16 blocchi rispetto al manifest esistente, 12 letterali e l'uguaglianza byte per byte degli ELF di analisi dei blocchi 00 e 02. Questi controlli verificano i campioni e la riproducibilità, non l'esecuzione sulla fotocamera o la classificazione di ogni istruzione.

Nessun collegamento alla fotocamera, scrittura del firmware, test di autonomia o misura dei tempi. Non è stata verificata una procedura di recupero: una modifica installata ora potrebbe impedire l'avvio.
