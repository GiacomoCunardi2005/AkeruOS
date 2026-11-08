# S33 — sorgenti numeriche statiche dell'interpolatore

Analisi statica V1.1, 19 ottobre 2026. Prosegue l'[origine dei puntatori worker](S33_Origine_Puntatori_Worker_e_Aree_Riservate.md). Nessuna esecuzione hardware.

## Risultato

Nel percorso **selettore 0 del dispatcher `0x253570`**, seguito fino a `0x252B34`, la sorgente può essere uno fra **otto indirizzi fissi nel blocco firmware 05** oppure un puntatore precedentemente conservato nel record condiviso.

Le otto aree referenziate sono state estratte dai payload verificati. Ognuna contiene **9.100 coppie little-endian di halfword**, con una disposizione osservata di **130 colonne × 70 righe**: la seconda componente cresce lungo ogni riga e riparte esattamente dopo 130 coppie.

Questo attribuisce una sorgente concreta e statica al ricampionamento già ricostruito. Non stabilisce ancora il significato Nikon delle componenti, né che tutte le modalità usino queste tabelle. Stima funzionale invariata: circa 10%.

## 1. Dal getter al ramo del dispatcher

Il getter `0x25283C`, installato nella configurazione del secondo percorso, chiama `0x253570`. Per i valori halfword 1920/2016 prepara selettore 0 e secondo argomento 1; anche il default del getter usa selettore 0, con secondo argomento 0.

Il dispatcher conserva il selettore in r14 e, nel caso 0, chiama **`0x252B34`** a `0x253592`, passando il secondo argomento in r0. Poi raggiunge un epilogo comune senza un nuovo confronto del risultato.

Gli altri selettori chiamano routine diverse e rimangono fuori dall'attribuzione delle sorgenti di questo rapporto. Non si assume che 130×70 sia una risoluzione del sensore o dell'immagine finale.

## 2. Record condiviso, selezione e valore precedente

La routine `0x252B34` usa il record **`0x8996E0`**, risolto dal pool `0x252B1C`.

Un primo ramo verifica il byte **record+0x0E**. Se vale 1, carica direttamente **`0x89BB20`** e raggiunge l'uscita. Nel resto del corpo, chiamate e confronti costruiscono soglie a partire da valori di stato. Le identità funzionali di questi lettori e delle soglie restano aperte.

Il codice contiene due famiglie di selezione:

| Famiglia | Puntatori assegnati | Cella che conserva la scelta |
|---|---|---|
| A | `0x8C8210`, `0x8D1040`, `0x8D9E70`, `0x8E2CA0` | record+`0x24` = `0x899704` |
| B | `0x89BB20`, `0x8A4950`, `0x8AD780`, `0x8B65B0` | record+`0x28` = `0x899708` |

Ogni ramo di assegnazione carica il valore in r0 e lo conserva nella cella della famiglia prima dell'uscita. I tratti **`0x252CF6`** e **`0x252D52`**, quando non viene selezionata una nuova assegnazione, leggono invece la cella precedente.

Di conseguenza non è corretto rappresentare la funzione come una scelta sempre nuova e indipendente dalla storia: **alcuni rami possono riutilizzare il puntatore precedente**. Nei dati iniziali verificati le due celle sono zero; questo non dimostra quale sia il loro valore dopo la preparazione runtime. Le guardie successive del task distinguono alcuni casi nulli, ma non sostituiscono l'audit dell'ordine delle chiamate.

## 3. Aree estratte dal blocco 05

| Indirizzo | Famiglia | File estratto |
|---|---|---|
| `0x89BB20` | B e ramo diretto | [BIN](../Ghidra_Results/ghidra_reports/source_numeric_grids/grid_0089bb20.bin) |
| `0x8A4950` | B | [BIN](../Ghidra_Results/ghidra_reports/source_numeric_grids/grid_008a4950.bin) |
| `0x8AD780` | B | [BIN](../Ghidra_Results/ghidra_reports/source_numeric_grids/grid_008ad780.bin) |
| `0x8B65B0` | B | [BIN](../Ghidra_Results/ghidra_reports/source_numeric_grids/grid_008b65b0.bin) |
| `0x8C8210` | A | [BIN](../Ghidra_Results/ghidra_reports/source_numeric_grids/grid_008c8210.bin) |
| `0x8D1040` | A | [BIN](../Ghidra_Results/ghidra_reports/source_numeric_grids/grid_008d1040.bin) |
| `0x8D9E70` | A | [BIN](../Ghidra_Results/ghidra_reports/source_numeric_grids/grid_008d9e70.bin) |
| `0x8E2CA0` | A | [BIN](../Ghidra_Results/ghidra_reports/source_numeric_grids/grid_008e2ca0.bin) |

Ogni file contiene **36.400 byte = 130×70×2×2**. Gli inizi appartengono a una disposizione con passo `0x8E30`; fra `0x8B65B0` e `0x8C8210` c'è anche lo spazio a `0x8BF3E0`, che non è uno degli otto puntatori assegnati nel ramo analizzato. Non viene incluso come nona sorgente selezionata senza seguirne i riferimenti.

La validazione di ciascuna area controlla che i soli decrementi consecutivi della seconda componente siano alle posizioni 130, 260, …, 8970: **69 ripartenze esatte**, coerenti con 70 righe. Il JSON conserva offset nel blocco, SHA-256 del file estratto, intervalli delle componenti e prime coppie.

Esempi iniziali:

- `0x89BB20`: `(383,678)`, `(380,916)`, `(376,1154)`, `(372,1393)`;
- `0x8C8210`: `(12,6)`, `(20,275)`, `(27,542)`, `(32,808)`.

Sono valori numerici statici. La regolarità della griglia, da sola, non prova un formato colore, una calibrazione ottica o un algoritmo specifico della fotocamera.

## 4. Collegamento all'interpolatore e conseguenze per il buffer

Il ritorno del getter raggiunge intermedio+0, descrittore+`0x10`, payload+`0x10`, poi la cella **`0x369604`**. Nei percorsi già verificati, questa cella alimenta r4 dell'interpolatore.

Il corpo `0x1FD4E4` legge due halfword per posizione della sorgente e combina quattro vicini; le scritture del risultato avvengono nella griglia r3, non attraverso il puntatore sorgente r4 nel corpo verificato.

Quindi, per il ramo che restituisce queste aree, la sorgente del ricampionamento può essere **una tabella numerica residente nell'immagine del firmware**, mentre il buffer di lavoro viene sovrascritto con le coppie elaborate. Non si attribuisce universalmente al campo payload+`0x10` il significato di immagine acquisita dal sensore.

La corrispondenza fra stride effettivo dei chiamanti e disposizione osservata 130×70 deve ancora essere chiusa per ogni modalità. Non basta conoscere il layout del file per provare che ogni impronta di quattro vicini sia valida.

## Evidenze e continuazione

[Script estrazione/verifica](../Python_Trace_Scripts/s33_trace_source_numeric_grids.py), [JSON](../Ghidra_Results/ghidra_reports/source_numeric_grids/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/source_numeric_grids/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_source_numeric_grids.py`.

Verificati **16 SHA-256, roundtrip ELF del blocco 00, 5 finestre, 3 collegamenti diretti, 28 istruzioni chiave e 11 pool**. Estratte otto aree dal blocco 05 con hash individuali e controllo della struttura 130×70. L'estrazione non esegue il firmware.

Prossimo: identità e dominio dei lettori di stato usati nelle soglie, stride reale dei chiamanti, e selezione delle tabelle negli altri rami del dispatcher. Capienza delle regioni di lavoro, lettore dell'esito, consumatore finale della destinazione e sincronizzazione restano aperti.


## Continuazione: soglie e stati di selezione

Il [rapporto sulle soglie](S33_Soglie_e_Stati_Selezione_Tabelle.md) risolve lettori, curva e pesi delle tre soglie, e verifica i predicati contro il tratto decodificato. Unità fisiche, scrittori degli stati, geometria runtime e durata buffer restano aperti.
