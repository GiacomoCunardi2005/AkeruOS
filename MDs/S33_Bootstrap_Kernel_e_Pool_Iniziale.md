# S33 — bootstrap del kernel, template e pool iniziale

Analisi statica del 18 ottobre 2026, firmware Nikon S33 V1.1. Nessuna esecuzione, lettura della RAM reale o modifica del dispositivo. La fotocamera nei log è V1.0. Continuazione di [avvio e task](S33_Avvio_Runtime_e_Creazione_Task.md) e [contesto iniziale](S33_Task_Stack_Contesto_e_GP.md). **Avanzamento complessivo orientativo: circa 10%, invariato.**

## Risultato

Il percorso di bootstrap esaminato usa la configurazione originale a `0x42375C`, pubblica il contesto kernel attraverso `0x369348` e assegna al campo dei template la tabella **`0x372388`** già individuata. Il ciclo di avvio crea i record con attributo bit 0; nei 53 template originali questo seleziona soltanto **RTOSINIT**, ingresso `0x167A20`.

Dalla configurazione e dal codice si ricavano inoltre il contesto kernel a **`0x1800`** e un'area iniziale del pool **`[0x1CC0, 0xAD800)`**. Quest'area contiene metadati e allocazioni del runtime: non è una regione libera da destinare al nuovo codice.

## 1. Collegamento dal runtime C al kernel

La routine `0xAD890`, dopo i propri controlli, chiama **`0x333D7C`** a `0xAD8B6`. Il wrapper chiama **`0x1F0C3C`** e nel delay slot carica il puntatore a configurazione dal letterale `0x333D88`.

Questo stabilisce un collegamento concreto al bootstrap kernel. Non attribuisce `0xAD890` come vettore di reset, né risolve ancora il trasferimento TBIB → TBM. I primi byte del blocco 00 non possono essere assunti come punto di patch soltanto perché si trovano all'inizio del file.

La configurazione occupa 48 byte:

| Offset | Valore | Uso sostenuto dal percorso |
|---|---|---|
| +`0x00` | `1` | Campo copiato nel contesto; semantica completa non attribuita qui |
| +`0x04` | `0x1800` | Base richiesta per il contesto, allineata a 64 |
| +`0x08` | `0xAD800` | Limite superiore per il pool iniziale, allineato a 64 |
| +`0x0C` | `0x400` | Dimensione usata nel tratto che prepara lo stack di sistema/interrupt |
| +`0x10` | `0x372388` | Puntatore ai template dei task |
| +`0x14` | `2` | Discriminante consultato nell'inizializzazione dello stato; nome completo ancora aperto |
| +`0x18`, +`0x1C` | `0`, `0` | Campi originali non attribuiti qui |
| +`0x20` | `0x42378C` | Puntatore a dati originali, che iniziano con `ttya:` |
| +`0x24` | `6` | Campo originale non attribuito qui |
| +`0x28`, +`0x2C` | `0`, `0` | Campi originali non attribuiti qui |

I valori sono byte del campione, non risultati letti dal dispositivo acceso.

## 2. Pubblicazione del contesto e assegnazione dei template

Nel ramo di prima inizializzazione, `0x1F0C9C..0x1F0CA0` allinea il valore configurato +4, ottenendo **`K=0x1800`**. A **`0x1F0CA4`** lo scrive a base `0x369334` +`0x14`, cioè **`0x369348`**. È la stessa cella che i servizi task, allocatore e scheduler leggono ripetutamente.

Il codice azzera **`0x498` byte** del contesto, quindi copia i 48 byte della configurazione a **`K+0x100`**. Alcuni campi vengono successivamente normalizzati o sovrascritti: la copia iniziale non implica che l'intera struttura resti immutata.

Nella routine `0x29F1BC`:

```text
0x29F20C: legge K + 68*4 = K+0x110
                        = posizione del campo copiato configurazione+0x10
0x29F220: scrive quel valore a K+0xC8
```

Quindi, in questo bootstrap, **`[K+0xC8] = 0x372388`**, e la cella si trova a **`0x18C8`**. Il caricamento `.as` è scalato: 68 è un indice di parole, non un offset di 68 byte.

Il creatore `0x2C9AE0` cerca i template attraverso questo campo kernel. Il wrapper `0x158E78` usa invece direttamente il letterale `0x372388`. Il bootstrap qui ricostruito risolve dunque il precedente dubbio sulla loro corrispondenza: i due puntatori coincidono per questa configurazione, senza dimostrare ogni possibile modifica successiva o altra versione del firmware.

## 3. Pool iniziale e spazio già assegnato al runtime

`0x29F33C` richiama `0x2F6C80` con inizio **`K+0x498`**, limite superiore dal campo inizializzato e descrittore del pool a **`K+0x64`**.

Con i valori originali:

```text
K                         = 0x1800
fine contesto azzerato    = K+0x498 = 0x1C98
inizio pool allineato     = align_up(0x1C98,64) = 0x1CC0
limite superiore         = align_down(0xAD800,64) = 0xAD800
ampiezza iniziale         = 0xABB40 = 703.296 byte
```

Il costruttore controlla che vi sia spazio oltre le strutture minime, scrive i limiti nel descrittore, prepara un primo blocco e un elemento finale da 64 byte e collega il pool alle strutture del kernel.

Successivamente il bootstrap richiede memoria per stack di sistema, strutture dello scheduler e task. I servizi di creazione già ricostruiti usano l'allocatore del runtime. L'ampiezza del pool non equivale quindi alla sua memoria disponibile dopo l'avvio, e neppure alla sua capacità netta immediatamente dopo la creazione.

Non sono dimostrati dimensione della RAM fisica, altri pool, alias, permessi o contiguità fisica. L'intervallo superiore `0xAD800` coincide con la base del blocco 00 nella mappa candidata: questo è un confine di configurazione osservato, non la prova della mappa hardware completa.

## 4. Avvio automatico e ingresso nello scheduler

Dopo l'inizializzazione delle strutture, il codice costruisce un task interno usando un template del contesto kernel e il ramo personalizzato di `0x29F3A8`. La sua identità e tutte le sue dipendenze non sono state attribuite in questa verifica.

Poi, a `0x1F0D9E`, legge la tabella da `K+0xC8` e scorre i record da 32 byte fino al terminatore:

1. legge gli attributi a record+`0x14`;
2. se il bit 0 è zero, avanza al record successivo;
3. se il bit è uno, passa template e parametro record+`0x18` a **`0x29F3A8`**, con discriminante personalizzato zero;
4. richiama **`0x29F4E4`**, che inserisce il descrittore nelle liste di schedulazione e ne imposta lo stato a 2.

Il controllo integrale della tabella trova un solo record selezionato: **RTOSINIT**, ID 1, ingresso **`0x167A20`**, descrittore **`0x372A08`**. Il ruolo del bit 0 come selezione di avvio automatico è ora sostenuto dal codice che lo consuma, oltre che dalla somiglianza delle strutture con MQX.

A **`0x1F0DD0`**, il bootstrap chiama **`0xB2D0C`**. Questo imposta un bit dello stato del kernel e raggiunge la selezione delle liste; nel percorso esaminato si carica lo stack salvato del task e si arriva al ripristino CPU già verificato nel rapporto precedente.

Il collegamento statico completo di questo tratto è quindi:

```text
configurazione → contesto K → tabella 0x372388
  → record RTOSINIT con attributo bit 0
  → costruzione descrittore e frame
  → inserimento nelle liste
  → selezione scheduler → ripristino CPU
  → ingresso 0x167A20 → preparazione applicativa già tracciata
```

Il flusso dipende dal completamento dell'inizializzazione e dalla configurazione originale. Non è una traccia runtime del primo task effettivamente eseguito. Errori del bootstrap, task interno e tutti i rami di interrupt/scheduling non sono stati esaminati esaustivamente.

## Conseguenze e prossimo passo

Per AkeruOS esiste ora un collegamento fra bootstrap, template, allocatore e costruzione del task. Un candidato di integrazione deve usare il runtime inizializzato e rispettare i suoi servizi, invece di occupare arbitrariamente gli spazi non coperti dai payload.

Il [collegamento statico TBIB→ingresso TBM](S33_Passaggio_TBIB_TBM_e_Ingresso_CPU.md) è ora risolto tramite record16/tipo2, cella di trasferimento e prefisso CPU prima di `0xAD890`. Prossimo: completare chiusura del kernel TBIB e residenza durante la transizione. Restano da fissare punto d'inserimento, memoria realmente assegnabile, linker, attesa cooperante, compatibilità ABI, pacchetto e recupero.

## Evidenze riproducibili

Eseguire `python3 s33_trace_kernel_bootstrap.py`. Lo [script](../Python_Trace_Scripts/s33_trace_kernel_bootstrap.py) verifica hash e dimensioni dei **16 blocchi**, tutti i **53 template**, configurazione di 48 byte, letterali, istruzioni selezionate e destinazioni delle chiamate. Controlla roundtrip ELF identico del blocco 00 e produce **10 finestre GNU ARC700** nel [disassemblaggio](../Ghidra_Results/ghidra_reports/kernel_bootstrap/gnu_verified.txt) e nel [JSON](../Ghidra_Results/ghidra_reports/kernel_bootstrap/verified_evidence.json), con hash dello script. Esecuzione completata con codice 0.

## Continuazione del19 ottobre — ingresso TBM collegato

Il [rapporto sul passaggio TBIB→TBM](S33_Passaggio_TBIB_TBM_e_Ingresso_CPU.md) attribuisce il record16/tipo2 all’ingresso `0xBB540`, collega la cella di trasferimento e verifica stack, gp e chiamata a `0xAD890`, oltre all’area azzerata. Il precedente punto aperto sul collegamento statico è quindi ristretto: restano la sequenza completa di chiusura TBIB, la residenza, l’inserimento AkeruOS e il recupero, senza esecuzione hardware dimostrata.
