# S33 — condizioni di attivazione della registrazione diagnostica

Analisi statica del 18 ottobre 2026, firmware V1.1. Nessun accesso USB, esecuzione del firmware o modifica del dispositivo. Continuazione della [ricognizione mattutina](S33_Ripresa_20261018.md).

## Risultato

Il byte `0x366B9F`, che nel ramo USB controlla la registrazione degli handler diagnostici e ottici, ha due chiamanti verificati che richiedono valore **1**:

1. La routine di inizializzazione `0x0C5EC0`, quando gli stati dei **tasti logici 9 e 11 sono entrambi non nulli**.
2. Un ramo dell'handler `0x4405` dell'oggetto originale **Calibration**, indice `0x5C` nella tabella oggetti registrata.

È stato inoltre verificato un wrapper nel blocco 04 che passa alla routine di scrittura il byte basso dell'argomento. La presenza del wrapper non dimostra un terzo percorso di attivazione con valore 1: i suoi chiamanti restano sconosciuti.

Questo attribuisce condizioni e un contesto applicativo al controllo. Non identifica ancora i pulsanti fisici, una sequenza utilizzabile sulla V1.0, o un comando di lettura RAM. **Avanzamento verso il firmware essenziale: circa 10%, invariato.**

## 1. Routine di scrittura, copia normalizzata e lettura

La routine `0x138FB0` conserva il suo argomento in `r13`, carica `0x366B9F` dal letterale `0x138FDC` e scrive il byte a `0x138FC0`. Successivamente passa in `r0` zero se l'argomento era zero, altrimenti 1, e chiama `0x13993C`.

Quest'ultima non è più una funzione dal significato completamente aperto: a `0x139944` carica il letterale `0x139954 = 0x366BB1` e a `0x139946` vi scrive il byte ricevuto. Nel percorso esaminato esiste quindi una seconda copia normalizzata del valore. Non sono ancora attribuiti i suoi consumatori né dimostrata l'esclusività degli scrittori.

Il getter `0x1398E8` legge invece direttamente il byte `0x366B9F`, usando il letterale `0x1398F0`. Non restituisce la copia `0x366BB1`.

Nel ramo USB già verificato, `0x139348` legge `0x366B7C+35`, che coincide con `0x366B9F`; se vale esattamente 1 il codice chiama `0x1DBD98` e `0x222348` a `0x139354` e `0x13935C`. Gli altri controlli precedenti dell'inizializzazione rimangono necessari.

## 2. Condizione sui tasti durante l'inizializzazione

La finestra con ingresso verificato `0x0C5EC0` carica `0x16F920` dal letterale `0x0C5F64`. La routine puntata esegue:

```text
0x16F920: carica base 0x446808 dal letterale 0x16FA34
0x16F922: calcola base + indice*4
0x16F924: ritorna con delay slot
0x16F926: legge il byte di stato all'indirizzo calcolato
```

È la stessa tabella di stato dei tasti già collegata a `0x16F72C` nell'[analisi MMIO](S33_S2_MMIO_e_Coda_Eventi.md). Il ritorno misura un valore software, non una pressione fisica osservata.

| Sito | Operazione |
|---|---|
| `0x0C5F02..0x0C5F08` | Chiama il getter con indice 9; se ritorna zero salta a `0x0C5F1E` |
| `0x0C5F0A..0x0C5F10` | Chiama il getter con indice 11; se ritorna zero salta allo stesso punto |
| `0x0C5F12` | Prepara `r0=1` |
| `0x0C5F14` | Chiama `0x138FB0` |
| `0x0C5F18..0x0C5F1A` | Passa anche 2 alla routine `0x138F7C`, il cui effetto ulteriore non è attribuito qui |

Il chiamante `0x0C6272`, nella routine con ingresso `0x0C6234`, invoca `0x0C5EC0`. Questa associazione è stata controllata con una seconda finestra radicata all'ingresso, non dedotta dalla sola decodifica lineare.

**Inferenza:** la condizione è compatibile con un controllo combinato di due tasti durante una fase di inizializzazione. Non è ancora una procedura pratica di accesso a una modalità di servizio: polarità, etichette dei pulsanti, momento del campionamento e raggiungibilità completa all'avvio rimangono da verificare. Non è dimostrato che il mancato soddisfacimento della condizione azzeri un valore precedentemente impostato: il ramo esaminato salta la scrittura.

## 3. Attribuzione del secondo chiamante a Calibration

L'attribuzione proviene dai dati originali e dal lookup già ricostruito:

| Elemento | Evidenza nei byte |
|---|---|
| Descrittore | `0x40AB08` |
| Callback a descrittore+12 | `0x40AB14 → 0x2D0660` |
| Nome a descrittore+20 | `0x40AB1C → 0x40AE7C → "Calibration"` |
| Voce nell'array oggetti | `0x3F5A70 → 0x40AB08`, indice `0x5C` rispetto alla base `0x3F5900` |
| Tabella del lookup | Letterale `0x2D0694 → 0x40AB3C` |
| Prima associazione verificata | `0x40AB3C: 0x4405`, `0x40AB40: 0x2D0698` |

La callback `0x2D0660` prepara i due puntatori di tabella/contesto e chiama il lookup `0x169F60` a `0x2D067E`. La tabella oggetti di 197 voci e la sua registrazione originale sono già documentate nel rapporto MMIO: l'attribuzione dell'indice `0x5C` è condizionale alla stessa registrazione.

L'handler con ingresso `0x2D0698` usa il contesto `0x36CA00`, caricato dal letterale `0x2D0A54`. Nel tratto finale esaminato:

```text
0x2D08DE: legge byte [contesto+0]
0x2D08E0..0x2D08E2: se nonzero, salta a 0x2D0996
0x2D08E4..0x2D08E6: chiama prima 0x163D90 con argomento 1
0x2D08EA: prepara r0=1
0x2D08EC: chiama 0x138FB0
```

Il percorso precedente contiene altri rami e operazioni: contesto+0 uguale a zero è una condizione locale necessaria per questo tratto, non una descrizione sufficiente di tutto l'handler. Non è ancora ricostruito come l'utente o l'avvio selezionino Calibration.

`0x4405` qui è una voce della tabella di Calibration: non va interpretato automaticamente come il comando di cattura dell'oggetto Recorder/CaptureImage. I destinatari e i rispettivi handler sono distinti.

## 4. Wrapper del blocco 04 e limiti della ricerca

La funzione `0x80D3A8` converte l'argomento con `extb_s r0,r0` a `0x80D3B6`, poi chiama `0x138FB0` a `0x80D3B8`. Il suo ingresso e l'intero tratto fino all'epilogo sono stati disassemblati separatamente. Può inoltrare il byte basso di un argomento; non è stato verificato chi la richiami.

La scansione lineare dei blocchi non sovrapposti 00–10 ha trovato **24 candidati di branch** verso sei routine selezionate, compresi tre siti verso `0x138FB0`. I tre siti sono stati verificati in finestre radicate. I candidati verso il getter comprendono contesti PTP e altri servizi, ma non sono tutti attribuiti semanticamente in questa fase.

Un candidato nel blocco 09, `0xCA4A32 → 0x0C5EC0`, è circondato da una sequenza densa di mezze parole che la decodifica lineare trasforma in branch incoerenti. Non viene promosso a chiamante eseguibile: occorre prima riconoscere il formato della regione e trovare un ingresso raggiungibile. Questo illustra perché il semplice elenco di xref del decoder non basta.

Le occorrenze grezze non allineate del valore `0x138FB0` sono conservate nel JSON e non vengono trattate come puntatori. Non è dimostrata l'assenza di chiamate indirette, scritture tramite alias o costanti costruite. I blocchi overlay 11–15 sono stati verificati e ricercati per valori grezzi, non disassemblati per attribuire il flusso.

## Riproduzione

Eseguire dalla directory del progetto:

```bash
python3 s33_trace_diagnostics_mode.py
```

Lo [script](../Python_Trace_Scripts/s33_trace_diagnostics_mode.py) verifica dimensione e SHA-256 dei 16 blocchi, controlla letterali, istruzioni selezionate, descrittore, stringa, tabella e slot oggetto. Ricrea gli ELF 00/04 con roundtrip identico e conserva **10 finestre GNU ARC700** nel [disassemblaggio](../Ghidra_Results/ghidra_reports/diagnostics_mode/gnu_verified.txt). Il [JSON](../Ghidra_Results/ghidra_reports/diagnostics_mode/verified_evidence.json) registra hash, collegamenti, risultati della scansione e limiti. I risultati descrivono il codice statico, non un esperimento sul dispositivo.

## Prossimo confine utile per AkeruOS

L'attivazione diagnostica è ora parzialmente attribuita; la priorità per la nuova applicazione torna al raccordo fra evento S2, byte liveview+59 e stato `0x0A` di CaptureImage, insieme al contratto di esito della scrittura/chiusura. La possibile modalità di servizio rimane una pista di supporto e non sostituisce i requisiti di avvio, riuso del motore fotografico e recupero del firmware essenziale.
