# S33 — avanzamento FAT, directory multisettore e identità del file

23 ottobre 2026, R0/R1/R4. Continuazione del [lettore/cache e trasferimento](S33_Dumper_RAM_SD_Settori_Cache_e_Trasferimento_Originale.md). Analisi ed esecuzione offline del firmware originale, nessuna azione sulla fotocamera.

## Risultato

La ricerca ora percorre più settori e cluster attraverso **2A3360 →2A318C →2A2D88 →2ABC68 →1F25D8/1F250C →2A0C60 →226204/1F3524 →callback sintetica**. È stata inoltre unita la precedente sequenza r/open→lookup→close alla lettura inferiore originale, su un distinto albero con un settore per directory.

Tre risultati richiedono attenzione per il futuro binding del dumper:

- un errore della lettura FAT può diventare **01A00002, file non trovato**, mentre lo stesso errore sui dati resta01A00021;
- con una **voce FAT sintetica corrotta a0**, una ricerca in sottodirectory può tornare alla root e restituire il file omonimo con stato0;
- un ciclo FAT2→3→2 ripete i settori nel tratto osservato, senza un ritorno normale prima dello stop imposto dal probe.

Non sono condizioni misurate sulla SD dell'utente. Sono risultati sul codice originale con dati e callback controllati, utili a evitare che il nuovo software consideri successo e identità del file equivalenti.

## Prove e riproduzione

| Gruppo | Casi | Confine e fonte |
|---|---:|---|
| Avanzamento e FAT | 34 | 12avanzamento con FAT sostituita +22decoder/cache originali; [evidenza](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Cluster/20261023T083807Z/verified_evidence.json) |
| Lookup multisettore/catena FAT | 13 | 12ritorni normali +1osservazione di ciclo limitata; [evidenza](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Chain/20261023T084542Z/verified_evidence.json) |
| r/open→driver→file close→volume close | 7 | Settori sintetici, lettore/wrapper/dispatch originali; [evidenza](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Device/20261023T084542Z/verified_evidence.json) |
| Regressioni profili lookup | 20+20+20 | [driver](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lookup_Device/20261023T084542Z/verified_evidence.json), [settori](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lookup_Sectors/20261023T084638Z/verified_evidence.json), [precedente confine](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lookup_Tree/20261023T084638Z/verified_evidence.json) |
| Regressione r/close col lettore sostituito | 7 | [evidenza](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Tree/20261023T084638Z/verified_evidence.json) |

I tre nuovi gruppi verificano rispettivamente6/28/26 finestre GNU. Le matrici di regressione ripetono casi precedenti con il codice condiviso aggiornato, non sono nuovi comportamenti del firmware.

```sh
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_cluster.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_chain.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_device.py
```

Snapshot dei sorgenti,16hash payload, log, tracce e disassemblati sono conservati nei risultati. I prodotti dell'helper3342A8 sono ancora sostituiti dal modello modulo2^32 perché MULUDW non è implementato dal P-code; divisione335B34, scanner, avanzamento, lettore FAT e I/O generico sono eseguiti. Nessuna nuova prova della semantica DSP fisica.

## Avanzamento originale 0x2ABC68

Argomenti `(ctx,&cluster,&indiceRecord)`. Incrementa l'indice; la verifica del confine settore usa `halfword[ctx+84]−1` come maschera. Nei test si usano16 o32record per settore, senza generalizzare a geometrie arbitrarie.

Se non è un confine settore, pubblica soltanto il nuovo indice e il cluster corrente. A un confine:

| Stato | Azione verificata |
|---|---|
| cluster0, indice sotto halfword[ctx+0x18] | resta nella root |
| cluster0, indice al limite root | cluster1 e indice0 |
| cluster nonzero, indice/recordPerSettore sotto byte[ctx+0x12] | resta nel cluster |
| fine cluster | chiama1F25D8 con tre argomenti opzionali0 |
| FAT ritorna stato0 | pubblica il cluster restituito e azzera indice |
| FAT ritorna errore | pubblica comunque il cluster restituito e conserva l'indice incrementato |

Nell'ultimo caso sintetico: cluster2/indice31 →FAT restituisce sentinella0FFFFFFF ed errore01A00021 →celle finali0FFFFFFF/32, ritorno01A00021. La routine non ripristina i due valori iniziali. Il caso FAT-next0 di questo gruppo è una risposta imposta al confine; il lookup integrato seguente esegue invece il vero decoder FAT su una voce0.

## Decoder 0x1F25D8 e cache 0x1F250C

Il decoder rifiuta il cluster di ingresso sotto2 o sopra word[ctx+0x78], scrive01A0001E e ritorna0FFFFFFF. Il campo ctx+0x70 seleziona il formato osservato:

| Valore software | Lettura della voce | Confine trattenuto | Valori maggiori del confine |
|---|---|---|---|
| 1 | FAT12: offset cluster+cluster/2, nibble basso per pari/alto per dispari | 0FF8 | sentinella0FFFFFFF |
| 6 | FAT16: due byte, offset2×cluster | FFF8 | sentinella0FFFFFFF |
| 12 | quattro byte, offset4×cluster | 0FFFFFF8 | sentinella0FFFFFFF |

Le condizioni effettive sono **strettamente maggiore**, non maggiore o uguale. Non viene qui corretta la logica Nikon né presunta la semantica di tutti i valori riservati. I test dimostrano cheFF8/FFF8/0FFFFFF8 restano valori di ritorno con stato0; FF9/FFF9/0FFFFFF9 diventano la sentinella. Anche0 e1 sono restituiti dal decoder con stato0 quando provengono dalla voce di un cluster di ingresso valido.

Nel ramo a quattro byte il confronto avviene sul valore raw prima della maschera finale a28bit: la voceF0000003 diventa sentinella, non cluster3. È un caso di contratto con dati sintetici, non prova di una voce reale presente nel filesystem.

I campi della finestra sono:

| Offset dal contesto | Ruolo verificato |
|---|---|
| 772=193×4 | primo settore relativo alla FAT nella finestra |
| 776=194×4 | stato: il consumatore1F2484 tenta scritture solo sul valore1; nei test vale2, pulito |
| 780=195×4 | buffer finestra |
| 784=196×4 | numero settori della finestra |
| +0x58 | base usata per la lettura FAT inferiore |
| halfword+0x10 | dimensione settore nel caso,512 |
| halfword+0x1E | limite settori FAT nel ramo ordinario provato |

La cache-list globale a36938C è posta a0 e i flag di369368 sono inizializzati a0: percorsi specchio/cache esterna non coperti. Con una finestra di due settori, i casi FAT12 freddi leggono20/2 oppure22/2; il loader allinea il settore iniziale alla coppia nel percorso eseguito. La voce dispari341 ha offset511 e attraversa il confine512: i due byte sono decodificati correttamente sia dalla finestra già presente sia dopo caricamento. La lettura fallita conserva la vecchia posizione della finestra, restituisce l'errore e fa ritornare la sentinella al decoder. FAT16/32 sono provate da cache già predisposta, non dal relativo mount o caricamento freddo.

## Catena integrata e propagazione degli errori

Geometria della matrice13:512byte/settore,16record/settore,2settori/cluster; root100/101, data102, FAT20/21. Cluster2→102/103,3→104/105,4→106/107. I settori pieni contengono record cancellatiE5 per costringere l'avanzamento senza un marcatore0 anticipato. Nomi brevi, attributi e puntatori directory sono espliciti.

| Scenario | Settori richiesti alla callback | Esito |
|---|---|---|
| file nel secondo settore root | 100,101 | cluster0/indice17,32byte del record atteso |
| file nel secondo settore cluster2 | 100,102,103 | cluster2/indice17 |
| file dopo un salto FAT2→3 | 100,102,103,20/2,104 | cluster3/indice1 |
| file dopo due salti2→3→4 | 100,102,103,20/2,104,105,106 | cluster4/indice0; seconda lettura FAT dalla cache |
| directory SUB nel secondo settore di DIR | 100,102,103,104 | file finale cluster3/indice0 |
| fine catenaFFF | 100,102,103,20/2 | 01A00002 |
| errore leggendo la FAT | 100,102,103,20/2 fallita | **01A00002**, sebbene avanzamento ritorni01A00021 |
| errore sul secondo settore dati | 100,102,103 fallita | 01A00021 |

Il punto che perde l'errore FAT è verificato dal risultato originale a2A30EC: il codice confronta r0 dopo2ABC68 e salta all'uscita, ma lo stato poi pubblicato a2A317E/2A3180 viene dal precedente `[sp+0x2C]`, rimasto0 dopo la lettura dati riuscita. Scanner nullo con stato0 diventa01A00002 nel coordinatore. Un errore del settore dati, invece, era già scritto nello stato del lettore e viene mantenuto.

La root piena senza marcatore0 costituisce un caso distinto: il ciclo dello scanner tenta la posizione102. Il lettore la rifiuta perché coincide con data-start, prima di chiamare il driver. L'avanzamento successivo riconosce root esaurita e pubblica cluster1, ma non cancella l'errore01A0000D già presente. Quindi il lookup integrato ritorna01A0000D. Il primo tentativo del probe aspettava01A00002: la traccia ha smentito quella previsione; i casi finali asseriscono anche la posizione rifiutata102.

## Voce FAT0 e identità del file

Fixture esplicita: root contieneDIR(cluster2) eTARGET.BIN; DIR ha due settori di record cancellati; voce FAT del cluster2=0. Richiesta `\DIR\TARGET.BIN`:

```text
root100 →DIR102 →DIR103 →FAT20/2 →root100
```

Il vero decoder ritorna0/stato0; l'avanzamento pubblica cluster0/indice0; lo scanner interpreta nuovamente quel cluster come root e trova il suoTARGET.BIN. Il risultato finale è **stato0, cluster0, indice1**, con32byte identici al record root verificato dal probe. Non basta verificare nome, successo e handle: su dati corrotti può essersi persa l'identità della directory.

La voce1 termina invece la ricerca come sentinella1 con01A00002. La voceFF8 non viene normalizzata dal decoder: viene tentato il cluster4088 e il lettore calcola posizione8274, oltre il limite sintetico1000; nessun trasferimento a quella posizione arriva al driver e il risultato è01A0000D. Anche8274 è asserito al ramo originale di rifiuto2A11AC.

## Ciclo FAT: osservazione limitata

La fixture2→3→2 con nessun record corrispondente produce:

```text
100,102,103,20/2,104,105,102,103,104,105,102, ...
```

Il probe si ferma **al dodicesimo ingresso nella callback dati**, prima di soddisfare quella dodicesima richiesta. Sono osservati quattro avanzamenti e quattro chiamate al decoder FAT; la finestra evita altre letture della FAT. Non c'è ritorno normale entro questo confine. Questo dimostra la ripetizione nel percorso eseguito, non un timeout fisico o una prova universale di ciclo infinito.

Due scratch sono già liberati e due restano attivi al momento dello stop; le guardie di tutti sono verificate. L'emulatore viene poi distrutto: questo caso non prova il cleanup normale né un leak persistente sulla fotocamera. Gli altri12casi tornano con stack, scratch e sezioni critiche bilanciati.

## Raccordo r/open→driver→close, ora nella stessa esecuzione

La nuova matrice7 riusa l'albero root/DIR/sub precedente, con **un settore per cluster**, root100/data101, non la geometria della matrice13. Esegue l'open callback1F43AC/21A0D0, parser/lookup/scanner, lettore2A1178, trasferimento2A0C60, seek226204, dispatch1F3524 e la callback dispositivo sintetica. Quindi tenta volume close con file vivo, chiude il file e ritenta volume close.

Successo crea l'oggetto tramite2AC528, chiusura volume rifiuta01A00010 finché vivo,2AC564 rimuove l'oggetto al file close e il volume poi chiude. Mancanza file ed errore dati non registrano oggetti. Rimangono anche i due falsi successi OOM257 con record vuoto, uno con errore alloc01A00006 registrato dal codice originale nel task+38: ora l'intera sequenza include anche il lettore inferiore e il driver sintetico.

Il close volume percorre i veri free a1F484C/1F485A/1F4868: libera una volta ciascuno i tre buffer preparati ctx+436/+712/+716, sotto il semaforo con count0, dopo che il file è stato rilasciato. A fine close il semaforo torna1 e ctx+424 è0; **le tre celle puntatore conservano però i vecchi indirizzi**. Il probe registra l'ownership e i free senza riutilizzare quei buffer; la durata non va estesa dal solo fatto che il puntatore nel contesto sia ancora nonnullo.

Questa sequenza copre il nuovo confine r/driver/close, ma non incorpora ancora la matrice FAT multisettore nella medesima esecuzione r. Restano simulati pool, clock, predicato dirty/cache del close e ioctl3. Non è un mount completo o un close con persistenza fisica.

## Prossimo passo e limiti

Raccordare la ricerca multisettore alla sequenza r/close con la medesima FAT e verificare il contratto della callback PMSD/DEVSD su letture parziali, errori e buffer. Il percorso di creazione esclusiva deve rifiutare l'uso di un errore FAT tradotto in «mancante» o di un record proveniente dalla directory sbagliata. È una condizione per il futuro binding, non una patch Nikon già implementata.

Non coperti: long-name/DCIM, cache-list globale, specchi e scritture FAT, rami FAT32 multipli, concorrenza, DMA e driver fisico. Restano mappa RAM completa, creazione esclusiva SD, wait RTOS e memoria/task/hook propri. Il lavoro modifica verificatori e documentazione; firmware originale, dump, GNU, C AkeruOS e BIN restano invariati. Circa10% funzionale invariato, **NON_INSTALLARE**, goal aperto.

## Continuazione — r/FAT/PMSD/DEVSD/close integrati

[S33_Dumper_RAM_SD_Catena_PMSD_DEVSD_e_Contratto_Conteggi.md](S33_Dumper_RAM_SD_Catena_PMSD_DEVSD_e_Contratto_Conteggi.md):22casi contratto conteggi/flag e13matrici r/FAT/close ora attraversano PMSD, DEVSD e adattatore SD originale, con2015/16 e semafori. Count raw intero/0 ed errore copiato; flag49=1 può riportare successo senza aggiornare buffer. Separazione FAT/r superata; motori dati e runtime flag restano aperti. Nessun hardware, GNU o BIN modificato.

## Continuazione — motori read e PIO eseguiti

[S33_Dumper_RAM_SD_Lettura_PIO_Motori_e_Completamento_Originali.md](S33_Dumper_RAM_SD_Lettura_PIO_Motori_e_Completamento_Originali.md):20PIO,28motori,13r/FAT/PMSD/SD/PIO/close. Il confine prima degli interi B15B4/B16D0 è superato: preparazione,descrittori,copia CPU/MMIO e completamento ora eseguiti. Dispatcher comandi2E52F4 e25AA8C restano fixture;profili sintetici,non prova elettrica. Percorso write/asincrono non generalizzato dal read. Nessun hardware o BIN modificato.
