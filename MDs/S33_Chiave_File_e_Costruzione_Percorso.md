# S33 — chiave file e costruzione del percorso

Analisi statica V1.1 del 18 ottobre 2026. Continuazione dell'[apertura file e dei volumi](S33_Apertura_File_e_Volumi.md). Nessun accesso al dispositivo.

## Risultato

La chiave usata dal convertitore **`0x210C5C`** è suddivisa da **`0x210C08`** in cinque campi che coprono tutti i 32 bit. Sono collegati il numero usato dal formato numerico del nome, un indice di record directory, la selezione dell'estensione e i rami di percorso.

Il percorso completo **non si ricava dalla sola chiave**. Il codice legge separatamente lo stato del volume corrente, un registro di directory e il prefisso del nome file. Non è corretto trasformare la parte alta della chiave direttamente in `A:` o `B:`, né considerare l'indice directory uguale al numero stampato nel suo nome.

È disponibile un decodificatore locale dei campi. Non valida una chiave, non consulta la fotocamera e non dimostra equivalenza con gli handle oggetto PTP. R2 resta parziale, circa 10% funzionale invariato.

## 1. Disposizione verificata dei bit

La routine `0x210C08` riceve la chiave in `r0` e un'uscita in `r1`. Con uscita nulla restituisce zero; altrimenti scrive:

| Bit della chiave | Larghezza | Destinazione nell'uscita | Impiego ricostruito |
|---|---:|---|---|
| 0–13 | 14 | Mezza parola +0 | Numero del file nel ramo che usa `%04d` |
| 14–15 | 2 | Byte +2 | Variante di costruzione/ricerca del nome |
| 16–25 | 10 | Parola +4 | Indice del record directory |
| 26–27 | 2 | Byte +12 | Indice estensione |
| 28–31 | 4 | Byte +13 | Selettore dei rami di percorso, qui denominato namespace |

Le maschere non si sovrappongono e coprono `0xFFFFFFFF`. In particolare la routine non scrive il campo +8: il convertitore lo popola successivamente tramite il servizio directory. Leggere +8 come un altro campo direttamente codificato nella chiave sarebbe errato.

Il numero dei file nel percorso numerico è controllato rispetto a 1–9999 nei rami descritti sotto, mentre il campo dispone di 14 bit. La semplice estrazione di un valore non lo rende valido per qualunque chiamata.

### Estensioni

Il letterale **`0x210F50 = 0x3E8E94`** punta nel campione a quattro stringhe da quattro byte:

| Indice | Stringa |
|---:|---|
| 0 | `JPG` |
| 1 | `AVI` |
| 2 | `WAV` |
| 3 | `MPO` |

`0x210E8E` seleziona base + `4*indice`. È un collegamento dalle istruzioni alla tabella, non una classificazione basata sulla sola presenza di quelle stringhe nel firmware.

## 2. Il percorso dipende dallo stato corrente

All'ingresso, **`0x210C88 → 0x12B0DC`** copia una stringa di base per il percorso. Quest'ultima routine:

1. legge l'indice corrente tramite **`0x12B290`**, dal byte **`0x366889`**;
2. se l'indice vale `0xFF`, prende l'uscita di errore;
3. altrimenti copia la stringa all'indirizzo **`0x44234C + 56*indice`**.

Nel payload iniziale il byte corrente vale **255**. Non è una misura del valore dopo l'avvio sulla macchina. La tabella a `0x44234C` richiede preparazione a runtime: il contenuto della stringa selezionata non viene dedotto dal solo indirizzo. In particolare non si assume che sia soltanto `B:` anziché un percorso di base più lungo.

Questa dipendenza è distinta dalla tabella dei volumi `0x376018` con passo `0x150`, già documentata. I due passi non vanno confusi.

## 3. Indice directory, nome e prefisso del file

Il convertitore chiama **`0x215724`** con modalità differenti. Nel percorso convenzionale:

- usa l'indice codificato a uscita+4 per ottenere un record;
- ricava dal record altri dati, fra cui il valore successivamente confrontato con **100–999**;
- richiede anche un nome directory dal registro;
- controlla che l'indice sia nonzero e non superi il conteggio restituito dal registro.

Pertanto l'indice codificato non è direttamente il numero directory. Le informazioni necessarie risiedono nel registro accessibile tramite un puntatore del contesto **`0x3E8EF0`**. Il suo contenuto effettivo dopo inizializzazione resta da attribuire.

Per il nome file, **`0x2127FC`** legge il contesto **`0x4BCFD8`**. Nel ramo ordinario copia cinque byte a partire da contesto+7; in un ramo speciale costruisce un prefisso numerico a partire da un altro formato. Non è stato dimostrato che il prefisso attivo sia sempre `DSCN`.

La variante +2 uguale a 2 usa un nome già ottenuto da un servizio, mentre il ramo numerico usa il formato verificato a **`0x3E8EBA`**:

```text
%s%s\%s%04d.%s
```

Gli argomenti corrispondono alla stringa di base già preparata, al nome directory, al prefisso del file, al numero e all'estensione. Questo è un modello del ramo, non un percorso pronto ottenuto per una foto reale. Eventuali separatori già contenuti nella stringa di base devono essere conservati.

## 4. Rami di percorso e controlli

Quando le guardie del ramo principale lo consentono, il selettore alto sceglie anche percorsi con le stringhe iniziali **`SYSTEM`**, **`MISC`** e **`DCIM`**:

- valore 3: ramo che aggiunge `SYSTEM`;
- valore 2: ramo che aggiunge `MISC`;
- valore 6: ramo che aggiunge `DCIM`.

Per altri valori esistono comportamenti ulteriori, incluso un ramo speciale per 7. Questo non costituisce un'enumerazione semantica completa di tutti i namespace. Alcuni rami saltano i controlli o i formati del percorso numerico convenzionale.

All'ingresso del convertitore, chiave zero, chiave `0xFFFFFFFF` o uscita nulla conducono all'uscita di errore. Nei rami convenzionali vengono inoltre verificati indice e dati directory, numero file e un selettore rispetto alla configurazione corrente. Il terzo argomento può selezionare un comportamento diverso: non è stato definito qui un validatore universale.

Sono presenti anche un protocollo cache tramite `0x2156A8`, un confronto con una chiave conservata in un altro contesto e servizi di ricerca dei nomi. Il percorso può quindi dipendere da stato precedente, non soltanto dalla sequenza di maschere.

## 5. Decodificatore locale

[Decodificatore](../Python_Trace_Scripts/s33_decode_file_key.py):

```bash
python3 Python_Trace_Scripts/s33_decode_file_key.py 0x12345678
```

L'esempio è **sintetico**, non un handle acquisito dalla Nikon. Produce numero 5752, variante 1, indice directory 564, estensione `JPG`, namespace 1. Non dimostra che la chiave superi i controlli o che esista un file corrispondente.

Il comando rifiuta valori negativi, oltre 32 bit e input non numerici. Il caso di esempio e questi rifiuti sono stati verificati attraverso la CLI. Non genera richieste PTP o un nome di file inventato.

## 6. Inizializzazione delle basi e ordine degli indici

La continuazione collega **`0x210428 → 0x12B358`** alla tabella delle stringhe a `0x44234C`. Nel ramo con due voci, passa le stringhe del campione:

| Indice della tabella percorso | Stringa assegnata | Corrispondente record nella tabella inferiore dei volumi |
|---:|---|---|
| 0 | `A:` da `0x369750` | Record 1, `DEVNAND:` |
| 1 | `B:` da `0x36974D` | Record 0, `DEVSD:` |

**I due domini di indice hanno ordine inverso.** Un indice corrente 1 della tabella percorso non deve essere usato direttamente come indice 1 nella tabella dei volumi `0x376018`. L'associazione attraverso le stringhe e i servizi originali va conservata. La tabella non esclude altre riscritture o configurazioni.

`0x12B358` copia la stringa in `0x44234C + 56*indice`. La routine di inizializzazione comune `0x21055C`, al proprio termine, richiede **indice corrente `0xFF`** tramite `0x12B29C`: inizializzare le stringhe non seleziona automaticamente una base valida per il convertitore.

È inoltre seguito un chiamante a **`0x2198D8 → 0x212654`**, che applica il prefisso, poi a **`0x2198E0 → 0x12B084`**, che tenta la selezione della base. Le condizioni complete che portano quel chiamante nel percorso fotografico restano da attribuire.

## 7. Default NIKON/DSCN e prefisso modificabile

Nel tratto **`0x134EBE..0x134EC6`** il codice ottiene `NIKON` dal getter `0xC7768` e passa `DSCN` come secondo argomento a `0x21055C`, nel delay slot della chiamata. Le stringhe sono verificate nei payload. Il servizio richiede lunghezze 5 e 4 e le copia rispettivamente a **`0x366B10`** e **`0x366B18`**, nel ramo che supera i controlli. Questo dimostra una sorgente di nomi iniziali, non che ogni foto usi sempre quei nomi.

Il prefisso attivamente letto dal convertitore resta nel contesto `0x4BCFD8`. Sono ora seguiti i suoi setter:

- **`0x212654`** riceve una configurazione passata nei registri e ricostruita sullo stack. Aggiorna i byte del contesto +0 e +6; se il primo byte è diverso da 3 copia quattro caratteri dall'argomento a contesto+7, poi scrive zero a +11. Nel ramo uguale a 3 genera invece quattro cifre con il formato `%02d%02d` e le copia nello stesso campo.
- **`0x212700`** può aggiornare contesto+7 da quattro caratteri ricevuti. Nel ramo modalità 2 genera un prefisso numerico a partire dal parametro controllato fra 100 e 999; nel ramo modalità 3 evita l'aggiornamento locale.
- **`0x2127FC`** rimane il getter del prefisso per la costruzione del percorso, con le eccezioni già documentate.

Non è ancora chiuso il raccordo fra il default `DSCN` a `0x366B18` e il valore attivo di contesto+7 durante una particolare acquisizione. Il codice permette prefissi variabili; un decodificatore non deve sostituire i dati mancanti con `DSCN` come se fossero osservati.

Verifica aggiuntiva: [script setup](../Python_Trace_Scripts/s33_trace_path_setup.py), [JSON](../Ghidra_Results/ghidra_reports/path_setup/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/path_setup/gnu_verified.txt). **16 hash, roundtrip del blocco 00, 12 finestre e 11 collegamenti**. Sono state conservate le istruzioni dei delay slot e i due ordini di indice.

## Evidenze e prossimo passo

[Script di verifica](../Python_Trace_Scripts/s33_trace_file_key_path.py), [JSON](../Ghidra_Results/ghidra_reports/file_key_path/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/file_key_path/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_file_key_path.py`.

Verificati **16 hash, roundtrip ELF del blocco 00, nove finestre, nove collegamenti**, tabelle stringhe e maschere. L'identità aritmetica della partizione dei bit e la CLI non sono un'emulazione del firmware.

**Prossimo passo R2:** completare il registro directory e il raccordo dal default `DSCN` al prefisso attivo durante l’acquisizione, conservando la distinzione fra indice percorso e indice volume. Collegare la selezione corrente e la chiave fotografica al chiamante di setup. Completare poi la sincronizzazione inferiore a `0x2A1054` e la propagazione degli esiti. Scatto normale, recupero completo, persistenza SD ed esecuzione AkeruOS rimangono da verificare; il campione statico è V1.1, i log hardware V1.0.
