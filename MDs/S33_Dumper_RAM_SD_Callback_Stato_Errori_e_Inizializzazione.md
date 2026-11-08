# S33 — callback di stato SD, errori e inizializzazione originale

23 ottobre 2026, R0/R1/R4. Continuazione di [scadenza e risveglio](S33_Dumper_RAM_SD_Scadenza_Risveglio_e_Progress_Originali.md). Sono ora eseguiti anche registrazione, abilitazione, dispatcher e callback di errore del controller nella stessa catena del lettore asincrono. Non sono più sostituiti da ritorni simulati nel nuovo profilo.

**Risultato:** gli errori campionati dal registro originale raggiungono il task accodato, fanno ritornare il WAIT e vengono tradotti dal chiamante in E01520/E01620, con rilascio dell'oggetto e ripristino della maschera. Eseguito inoltre l'inizializzatore superiore dell'evento SD: dai flag statici2 deriva auto-clear0, senza predisporre manualmente il gate attivo. Restano separati il cambio contesto CPU, il trasferimento fisico e il binding del dumper.

## Prove riproducibili

[28 casi CPU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Status/20261023T141610Z/verified_evidence.json), [traccia](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Status/20261023T141610Z/trace.txt), [GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Status/20261023T141610Z/gnu_verified.txt): **10 casi API e18 lettore, tutti ritornati**;13 finestre GNU,27 istruzioni chiave, pool e record verificati. Hash dei16 payload e snapshot dei sorgenti conservati insieme a comando e log.

```sh
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_status.py
```

[Runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_read_status.py), [probe](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDReadStatus.java). Riutilizzati gli helper ProbeDumpSDMutex/ProbeStatusRead; nessun probe precedente modificato.

Regressioni rieseguite:

- `python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_async_wake.py`: [8 scenari PASS](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Async_Wake/20261023T141447Z/verified_evidence.json),7 ritorni e1 osservazione interrotta;136 timeout e136 letture di avanzamento originali,13600 invocazioni del tick. Corretto il precedente totale editoriale137: la somma delle righe è1+1+30+41+63=136.
- `make -C AkeruOS ram-dump-verify`: [28 casi host PASS e20 file malformati respinti](../Risultati/Runtime_Kernel/RAM_Dumper/20261023T141447Z_569c2ace/verified_evidence.json), compreso streaming128MiB sintetici e controllo oggetto ARC. Questa prova rimane distinta dal firmware Nikon.

## Inizializzazione dell'evento SD

Ogni scenario del lettore chiama realmente **158C30(E00005)**. Il corpo scorre la tabella372A48 fino al record **373228**, controlla il magic45564E4C, ricava il bit0 dei flag+8, azzera32 byte inferiori tramite AD90C e chiama23C674. Quindi esegue la traduzione17B770 e pubblica il bit31 del gate superiore.

Con il record statico originale `{magic45564E4C,idE00005,flags2}`, il risultato asserito è:

- flag superiore80000002;
- modo inferiore a record+28 uguale0;
- marker6C65766E a record+20 e registrazione globale dell'oggetto inferiore;
- livello critico finale0.

Questo supera la precedente preparazione manuale del gate nel profilo SD. Dimostra il comportamento dell'inizializzatore con quel record originale, **non l'esecuzione dell'intero boot né l'assenza di riconfigurazioni successive**. I quattro negativi auto-clear sostituiscono esplicitamente flags2 con3 prima dell'inizializzazione: sono un profilo alternativo dichiarato.

## Registrazione e servizio condiviso040E

Il pool266834 contiene **36B338**, non un oggetto dati receive. La halfword iniziale è1000, seguita da cinque slot callback:

| ID esatto | Slot |
|---|---|
| 1001 | 36B33C |
| 1002 | 36B340 |
| 1004 | 36B344 |
| 1008 | 36B348 |
| 1010 | 36B34C |

**266768(id,fn)** scrive soltanto lo slot dell'ID esatto. I test1000/1003/2 ritornano comunque0 senza modificare slot: il ritorno0 non certifica una registrazione per un ID arbitrario. Nel lettore gli ID sono1002/1004, con callback25AD3C/25AD78.

**26671C(id)**, al primo enable con halfword1000, chiama realmente16D898(040E,2667FC) e16D7E8(040E,FF). La tabella424A00 ha pendingFEF0050, enableFEF0080 e16 record; il record **424A1C** è `{040E,bit13,bit13,fn}`. Viene verificata la scrittura del puntatore a424A20 e l'abilitazione del bit2000. Poi lo stato36B338 diventa1002 o1004; con entrambi i client diventa1006.

Il test attiva il pending2000 e chiama il walker originale **2640E0**, che legge la tabella e raggiunge **2667FC**. Quest'ultimo visita gli slot non nulli e invoca la callback salvata. Non viene chiamata direttamente la callback SD al posto del walker.

## Errori reali, attesa e rilascio

Per ciascuno dei selettori0/800 vengono provati i campioni0/1/2/3 a **0FF01804−selettore**, due combinazioni errore+completion, due profili auto-clear e un fallimento di inizializzazione del router.

| Campione | Pubblicazione da25AD3C /25AD78 | Ritorno25A83C, modo0 |
|---|---|---|
| 0 | nessun errore; successiva callback dati40 /40000 | 0 |
| 1 | 80 /80000 | E01520 |
| 2 | 100 /100000 | E01620 |
| 3 | solo80 /80000: bit0 ha priorità | E01520 |

E01520 è anche il codice del limite dei30 controlli senza progresso: il solo valore restituito non distingue sempre la causa.

L'innesto avviene a **B2D50**, dopo l'accodamento originale nella lista evento e nella lista temporizzata: task52D, un waiter e una deadline. Il SET originale rimuove entrambi i nodi, rende il task pronto e azzera task+30. Solo dopo questi controlli il test restituisce dal confine astratto del cambio contesto; WAIT/query/CLEAR e i rami del lettore proseguono realmente.

La callback di errore esegue25A0D0 e si deregistra via2667B0. Il lettore rilascia poi l'oggetto281158, cancella il bit d'errore, ripristinaFFFF nel registro maschera e richiama2667B0: **due deregistrazioni**, entrambe originali. Handle e id dell'oggetto sono azzerati. Nei casi di errore seguito da completion, l'errore prevale e il bit completion resta pendente41/40001 con il bit estraneo1; sarà il CLEAR della successiva operazione a rimuoverlo.

L'helper25A0D0 riscrive il campione con i bit riconosciuti inclusi. Il test controlla il writeback, senza trasformarlo in una prova elettrica W1C.

## Due uscite che il binding dovrà rispettare

**Auto-clear forzato:** flags3 produce modo1. Il SET consuma il bit d'errore prima della query successiva; il WAIT ritorna0 e la query trova soltanto il bit estraneo1. Il lettore percorre la chiusura con ritorno0 anche se la notifica era di errore. I quattro casi0/800×bit0/bit1 lo riproducono. Non è una diagnosi della macchina: il percorso d'inizializzazione statico SD provato seleziona modo0. Un adapter non deve riconfigurarlo arbitrariamente.

**Router non inizializzato:** con gate framework367884=0, il primo enable originale ritorna200604 ma pubblica comunque1002/1004 nello stato36B338.25A83C termina prima di28080C senza release/deregister/ripristino della maschera: handle/id, slot callback eDFEF restano associati. Nei due casi API separati, un successivo enable1004 ritorna0 perché lo stato non è più1000 e salta il primo setup. Non è un leak fisico dimostrato; conferma che un fallimento d'inizializzazione non può essere trattato come assenza di effetti.

Dopo le normali deregistrazioni resta il marker1000. Il ramo che disabiliterebbe040E confronta lo stato con0, perciò nel profilo iniziale1000 il bit enable2000 resta impostato. Gli slot dei client vengono però azzerati: una successiva invocazione del walker non produce callback né SET. Non si deducono frequenzaIRQ o effetti elettrici da questo stato.

## Confini e prosecuzione verso il dump

Restano predisposti kernel/ready con un solo task, identità CPU e gate framework. Rimangono fixture il query/post della risorsa1594E4/1594A4, hook267BAC e prodotti3342A8/336364. Il salvataggio/ripristino del frameCPU non è eseguito; il walker è chiamato viaCABI con controllo di stack, callee register e gp/fp, e ripristino degli argomenti volatili al ritorno astratto. L'ordine errore→completion è scelto dal test; altri interleaving non sono provati qui.

Tutti i1024 byte del buffer restano31 e le guardieA5 sono integre. Non viene simulata una copia DMA. Il percorso di scrittura del file del dumper non è validato per analogia con questo lettore.

Prossimo: arbitraggio/post e arresto originali, poi raccordo del percorso filesystem asincrono; per produrre il dump restano **scrittura/creazione esclusiva e close, mappa fisica completa, memoria propria del task/hook e compatibilità dell'immagine della macchina**. L'analisi è V1.1, distinta dalla V1.0 nei log hardware. Nessun hardware o nuovo BIN, nessuna modifica GNU o alC AkeruOS; circa10% funzionale invariato, **NON_INSTALLARE**.

## Continuazione — risorse originali e ramo write

I [34casi risorse](S33_Dumper_RAM_SD_Arbitraggio_Risorse_e_Stop_Software_Originali.md) superano le fixture1594E4/1594A4 e267BAC del presente gruppo:1594E4 prenota effettivamente un token e scrive1byte;il post ripristina il token oppure lo consegna al waiter. Le uscite precoci mantengono token0. I [36casi write](S33_Dumper_RAM_SD_Scrittura_Asincrona_e_PIO_Originali.md) estendono il lavoro a3040DC,stato,timeout/release e copiePIO con catture dei dati scritti nelMMIO simulato. Prossimo raccordo filesystem;nessunhardware o binding installabile.
