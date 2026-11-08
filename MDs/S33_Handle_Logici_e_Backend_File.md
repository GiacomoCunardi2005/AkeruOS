# S33 — handle logici, puntatori file e selezione del backend

Analisi statica V1.1 del 18 ottobre 2026. Continuazione delle [callback filesystem](S33_Callback_Filesystem_e_Controlli_Close.md). Nessuna esecuzione sul dispositivo.

## Risultato

Il valore consegnato al wrapper di chiusura viene usato come **chiave di una tabella**, distinta dal puntatore file sottostante. La tabella ha 30 record da 12 byte a `0x4BD110`. Il wrapper risolve la chiave, rimuove l'associazione e solo dopo chiama il close sul puntatore recuperato. Non ricrea l'associazione nel proprio corpo se la chiusura fallisce.

La scelta fra i backend già individuati è ora concreta: **`0x1F35FC` restituisce 1 se la parola del contesto privato a +`0x70` vale 7**, altrimenti zero. Il valore corrente di quel campo sul file fotografico rimane da determinare; non viene attribuito un nome di formato al numero 7.

Il risultato chiarisce interfacce e limiti di recupero, ma non prova ancora il backend attivo della SD o la persistenza della fotografia. R2 parziale; stima funzionale circa 10%, invariata.

## 1. Tre livelli di identificazione

Nel percorso documentato occorre distinguere:

| Livello | Impiego osservato |
|---|---|
| Valore nel descrittore fotografico +`0x48` | Conservato separatamente per la chiusura differita; il wrapper `0x21828C` lo usa come chiave di ricerca |
| Puntatore file recuperato | Record di associazione +8; passato attraverso una cella locale a `0x12D604` |
| Dispositivo e contesti privati | La prima parola del file punta al dispositivo; dispositivo+`0x24` identifica il contesto del backend, file+4 un contesto specifico del file |

Il campo del descrittore non deve essere dereferenziato come puntatore file soltanto perché viene chiamato informalmente «handle». Il significato globale della chiave e tutti i suoi produttori restano da completare.

Una sorgente di produzione è ora collegata: nel ramo di `0x1B8F24` che raggiunge `0x1B90B4`, il codice costruisce **descrittore+`9*8 = 0x48` in `r3`**, prima di chiamare **`0x1872A0`**. Quest'ultima conserva l'indirizzo di uscita e lo inoltra in `r4` a **`0xBFFF4`**, a `0x18736E`. La catena completa sotto quel servizio non è ancora ricostruita. L'errore restituito viene conservato e può portare all'epilogo che salta la pubblicazione del buffer, come negli altri errori di acquisizione.

## 2. Tabella di associazione

Il letterale **`0x218414 = 0x4BD110`** è usato da inizializzazione, registrazione, ricerca e rimozione.

| Campo del record | Contenuto verificato |
|---|---|
| +0 | Flag; bit 0 usato come occupazione |
| +4 | Chiave logica confrontata con il primo argomento |
| +8 | Puntatore file sottostante |

La geometria è **30 × 12 = 360 byte**, intervallo `[0x4BD110,0x4BD278)`. `0x2183C8` copia 30 volte un template da 12 byte all'indirizzo `0x3500A8`; il template verificato contiene **`0, 0xFFFFFFFF, 0`**. Questo descrive l'inizializzazione statica, non una fotografia della tabella a runtime.

**Registrazione `0x218458`:** cerca un record con bit 0 libero, scrive la chiave a +4 e il puntatore a +8, poi imposta bit 0 tramite `0x336F3C(…,1)`. Se non trova spazio restituisce il valore iniziale dal letterale `0x2184A4`. Il limite 30 riguarda queste associazioni, non i buffer fotografici o i record ImgMgr.

**Ricerca `0x2184A8`:** azzera prima la cella di uscita, poi cerca contemporaneamente chiave uguale e bit 0 attivo. Se trova il record vi copia il puntatore da +8 e restituisce zero. Se non lo trova conserva il valore iniziale **`0xF20010`**. Questi numeri sono riportati senza inventare un nome simbolico.

**Rimozione `0x218500`:** quando trova la stessa chiave attiva, scrive `0xFFFFFFFF` a +4, zero a +8 e cancella bit 0 con `0x336F3C(…,0)`. Il caso non trovato conserva il valore iniziale **`0xF20040`**.

L'helper `0x336F3C` passa posizione zero e larghezza di un bit alla routine `0x336718`, che preserva gli altri bit della parola. Non è stato dimostrato che quell'operazione sia atomica rispetto ad altri task. La sincronizzazione del wrapper originale rimane necessaria.

## 3. L'associazione scompare prima del risultato del close

Il corpo **`0x21828C`** esegue, nel ramo in cui i controlli precedenti riescono:

```text
0x2182C0 → 0x2184A8(chiave, &puntatore_file_locale)
0x2182C4/C6: se ricerca fallita, evita il close
0x2182CE → 0x218500(chiave)
0x2182D4 → 0x12D604(&puntatore_file_locale)
0x2182D8: conserva il risultato del close
```

Il ritorno della rimozione non viene confrontato prima della chiamata successiva. Il risultato del close lo sostituisce. Nel corpo locale non c'è un rollback della tabella se `0x12D604` restituisce errore.

Questa rimozione precede anche gli eventuali errori dei controlli che `0x12D604` esegue **prima** della callback driver. Pertanto un errore del close può coincidere con chiave già disassociata e file non ancora passato alla callback finale. È un ordine statico da conservare nella gestione degli esiti, non una perdita globale dimostrata: altri proprietari e percorsi di ripristino restano da verificare.

La cancellazione dell'associazione è inoltre distinta dall'azzeramento dell'handle di basso livello dentro `0x12D604`, e dall'eventuale persistenza del valore originale in `0x368DE4`.

## 4. Contesto privato e predicato dei backend

Nel ramo close con file+4 non nullo, `0x1F48A4` passa **dispositivo+`0x24`** a `0x1F35FC`. Il predicato completo legge contesto+`0x70`, confronta con 7 e restituisce 1/0, includendo il delay slot del ritorno.

| Predicato | Callback close selezionata | Callback write selezionata |
|---|---|---|
| Campo +`0x70` uguale a 7 | `0x1F9258` | `0x1F94D4` |
| Campo +`0x70` diverso da 7 | `0x21AD30` | `0x21A4B8` |

Con file+4 nullo, il close raggiunge invece `0x1F46C4`, percorso distinto. La tabella non descrive quindi tutti i casi di un handle arbitrario.

Il codice **`0x1F3608`**, se `0x1F64E8` restituisce 1, scrive esplicitamente 7 nel campo a `0x1F364E`. La routine che decide quel ramo e i suoi stati globali sono ancora parziali. Non si deduce il backend effettivo dal solo nome assegnato al file o dalla presenza di quella scrittura.

Il servizio **`0x2A1344`** conferma la distinzione fra contesti: recupera file+4 attraverso un'uscita e dispositivo+`0x24` attraverso un'altra, poi esegue i controlli del contesto e la sincronizzazione originale.

## 5. Un tratto del close nel backend diverso da 7

Nel corpo **`0x21AD30`**, dopo la risoluzione dei contesti, sono presenti aggiornamenti di campi data/ora con base anno 1980. Nel tratto finale, sotto ulteriori guardie, può raggiungere:

1. **`0x21AE36 → 0x2AC438`**, un servizio che usa campi del record file, può copiare 32 byte e chiama `0x2A1054`;
2. **`0x21AE80 → 0x2AC564`**, che scollega un record, modifica un suo marcatore e chiama `0x2F7AF0`;
3. rilascio della sincronizzazione e ritorno del risultato conservato.

Questa sequenza non identifica ancora una barriera di persistenza SD. Vanno seguiti gli effetti di `0x2A1054`, la selezione del volume e il risultato dei servizi inferiori prima di tradurla in «tutti i dati sono sul supporto». Gli altri rami e il backend uguale a 7 restano distinti.

## Evidenze e prossimo passo

[Script](../Python_Trace_Scripts/s33_trace_file_handle_backend.py), [JSON](../Ghidra_Results/ghidra_reports/file_handle_backend/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/file_handle_backend/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_file_handle_backend.py`.

Verificati **16 hash, roundtrip ELF del blocco 00, 17 finestre mirate, 16 collegamenti e 14 istruzioni selezionate**. La lettura del template è verificata nei payload. La tabella di destinazione in RAM non è stata letta sul dispositivo.

**Prossimo passo R2:** completare la creazione/apertura fino alla registrazione `0x218458`, distinguendo chiave e puntatore reale; attribuire il valore del selettore backend sul volume fotografico e seguire `0x2A1054` e i servizi di scrittura inferiori. Il recupero delle risorse fotografiche e la persistenza degli esiti fra worker e chiusura restano aperti. Nessuna equivalenza V1.1/V1.0 o esecuzione AkeruOS è dimostrata.

## Continuazione: apertura collegata alla registrazione

Il [rapporto apertura e volumi](S33_Apertura_File_e_Volumi.md) collega ora il wrapper `0x217EFC` ai servizi inferiori e alla registrazione `0x218458`, con ritorno di registrazione non propagato. Distinti 60 slot file per volume dalle 30 associazioni logiche. La tabella statica associa B: a DEVSD:/PMSD: e A: a DEVNAND:/PMNAND:, con prefissi passati all’installatore della famiglia. Restano percorso fotografico, stato runtime e sincronizzazione del supporto.

## Continuazione: aggiornamento differito dei metadati

Il [rapporto metadati e scrittura inferiore](S33_Metadati_Differiti_e_Scrittura_Inferiore.md) segue `0x2A1054`: un ramo imposta il flag +`0x1AC` e restituisce zero senza trasferimento. Il consumatore `0x2A10F4` lo cancella solo su ritorno zero del trasferimento. Collegato l’handle inferiore a contesto+`0x1A4` alla callback dispositivo+`0x18`, distinta dalla famiglia filesystem superiore. Destinatario e persistenza restano aperti.
