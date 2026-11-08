# S33 — r/open, FAT, PMSD/DEVSD e contratto dei conteggi

23 ottobre 2026, R0/R1/R4. Continuazione di [FAT e identità file](S33_Dumper_RAM_SD_Catena_FAT_Multisettore_e_Identita_File.md), [backend SD](S33_Dispositivo_SD_e_Completamento.md) e [controlli](S33_Controlli_Completamento_e_Close_Volume.md). Nessuna operazione sulla fotocamera o sulla SD.

## Risultato e prove

La medesima esecuzione ora unisce r/open1F43AC/21A0D0, lookup e FAT multisettore, lettore2A1178, trasferimento2A0C60, seek226204, controlli1F2348/2A0A14, PMSD2A0870, DEVSD2A0594/2A0504, adattatore SD16825C/1681D0 e file/volume close. Il confine simulato è nei servizi datiB15B4/B16D0 e nel recupero25B63C; nessun MMIO fisico eseguito.

DEVSD restituisce **conteggio intero richiesto oppure0**, copiando lo stato del backend nel campo errore. PMSD conserva il conteggio e copia l'errore. Ridimensiona il precedente dubbio sulla callback generica parziale: il wrapper2A0C60 ammette parziale/errore0, ma il normale adattamento DEVSD esaminato converte uno stato finale nonzero in count0/errore nonzero. Questo non prova che lo stato0 del servizio dati garantisca un trasferimento completo.

Inoltre, con byte volume+49 esattamente1, **read e write saltano il backend ma dichiarano il conteggio completo e azzerano l'errore**. Nel test read il buffer mantiene il contenuto precedente benché lo strato filesystem riporti successo.

| Gruppo | Casi | Fonte |
|---|---:|---|
| FS→PMSD→DEVSD→adattatori SD, read/write | 22 | [evidenza](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Partition/20261023T090629Z/verified_evidence.json),15finestre GNU |
| r/FAT multisettore→PMSD/DEVSD/SD→close | 13 | [evidenza completa](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_SD_Chain/20261023T090629Z/verified_evidence.json),43finestre GNU |
| r/FAT→callback dispositivo sostituita→close | 13 | [profilo intermedio](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Chain/20261023T090710Z/verified_evidence.json),34finestre GNU |
| Regressione lookup FAT senza r/open | 13 | [regressione](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Chain/20261023T090710Z/verified_evidence.json),28finestre GNU |

Ogni matrice13 comprende12ritorni normali e1osservazione di ciclo interrotta dal probe. È la stessa matrice ripetuta con confini differenti, non61comportamenti indipendenti. Snapshot sorgenti e16hash payload verificati. Prodotti3342A8 ancora modellati modulo2^32 perché MULUDW non è implementato dal P-code; nessuna nuova prova DSP fisica.

```sh
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_partition.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_chain.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_sd_chain.py
```

## Conteggi, errori e tentativi

Celle originali37604C/376050: read16825C/write1684B4. I callback riordinano posizione,conteggio,buffer,parametro verso1681D0/168410, con indice SD0 e contesto4463E0, distinto dalla tabella volumi376018.

Nota pool: `ld.as [pcl,-72]` a1681F0 legge1680D0, con spostamento×4. Il commento GNU1681A8 non identifica il pool corretto. Le parole1680D0 e1687B4 valgono4463E0, verificate sui byte.

| Stato finale backend | Count raw/PMSD | Errore raw/PMSD | Esito FS |
|---|---:|---:|---:|
| 0 | richiesto | 0 | 0 |
| 00E00208 dopo tentativi | 0 | 00E00208 | 00E00208 |
| backend saltato, flag49=1 | richiesto | 0 | 0 |

I conteggi sono osservati ai veri ritorni raw e PMSD, oltre al risultato FS. I campi diagnostici rawCount/pmCount=−1 nei casi count0 significano «callback non invocata», non un−1 restituito da DEVSD.

Read count1 raggiungeB16D0, count2 raggiungeB15B4; write count1 raggiunge25BB5C, count2 raggiunge25B9C0. Questi servizi sono sostituiti da fixture di stato; il read sintetico riuscito riempie il buffer, il write non accede ad alcun dispositivo.

Successo iniziale: un tentativo. Errore poi successo: due. Tre errori con recuperi riusciti: tre tentativi e recuperi0/1/1, nessun quarto. Il limite è esterno e non impone un timeout ai cicli hardware interni.

Differenze verificate:

- read termina se il primo recupero0 fallisce, conservando l'errore dati;
- write può passare dal recupero0 fallito al recupero1; se questo riesce ripete il trasferimento;
- errori di recupero scelti differenti dall'errore dati non lo sovrascrivono;
- un errore iniettato della query write25BF3C non impedisce recupero e successivo successo nel caso eseguito.

Count0 a2A0C60 prepara la posizione ma non chiama callback dati né motore SD. Non generalizzato ai chiamanti diretti dell'adattatore SD con conteggi nulli/negativi.

## Posizione e semafori PMSD originali

Contesto PMSD sintetico: handle raw+0, semaforo+4, selezione/tabella offset da+20, unità dirette+40. Partizione1/offset2048 sono una fixture, non geometria misurata. Posizione FS7 diventa2055 nel file raw prima del servizio SD.

Con ctxFS+848=0 si eseguono gli originali2015/2016 tramite1F2348/2A0A14:

1. 2015 acquisisce il semaforo PMSD e copia ctxFS[0]=1 nel selettore PMSD+20, inizialmente0;
2. seek7 attraversa226204/2A0A14 e aggiunge2048;
3. la callback dati opera con semaforo PMSD acquisito;
4. 2016 lo rilascia anche dopo gli errori provati.

Tre casi scalari eseguono questo bracket e le primitive wait/post/contatore critico originali; altri19disabilitano2015/16 per isolare conteggi e tentativi.

Nel lookup completo è acquisito anche il diverso semaforo filesystem ctx+388: entrambi i conteggi sono0 al confine SD. Nei ritorni normali il PM torna1 per ogni bracket, il FS torna1 dopo open/close. Non prova concorrenza o ordine globale di altri task.

## Flag volume+49: successo senza trasferimento

Con handle predisposto e flag1, read e write count2 producono: zero servizi dati/recuperi, count raw e PMSD2, errori0, esito FS0. Il buffer read resta al pattern iniziale31, non55 della lettura sintetica riuscita. Flag2 non salta il backend.

Il flag iniziale dei record originali è0 secondo le prove precedenti. **Produttore e significato runtime restano aperti.** Il resolver1F19E0 rifiuta flag1 su alcuni percorsi prima dell'apertura: questa prova su handle già predisposti non dimostra che un nuovo open sia ammesso con il flag, né che si attivi sul volume fotografico dell'utente.

## FAT multisettore nella stessa r/open→close

Geometria: root100/101,data102,FAT20/21,due settori per cluster,offsetPM2048. `route` registra posizioni relative; `physicalRoute` registra le posizioni passate al servizio SD, non indirizzi NAND o misure elettriche.

| Caso | Posizioni FS | Posizioni al servizio SD |
|---|---|---|
| secondo settore root | 100,101 | 2148,2149 |
| salto FAT2→3 | 100,102,103,20/2,104 | 2148,2150,2151,2068/2,2152 |
| due salti FAT | 100,102,103,20/2,104,105,106 | 2148,2150,2151,2068/2,2152,2153,2154 |
| errore FAT | 100,102,103,20/2×3 | 2148,2150,2151,2068/2×3 |

L'adattatore ripete tre volte il servizio fallito dentro un solo bracket PM per richiesta FS. FAT fallita: quattro lock e quattro post PM ma sei servizi dati. L'errore01A00021, scelto dal probe e non misurato su SD, diventa ancora01A00002 nel lookup; sul settore dati resta01A00021.

La FAT0 corrotta riporta ancora la ricerca alla root: **r/open registra un oggetto reale della lista per il file root omonimo**, cluster0/indice1,32byte del record verificati. Il close volume rifiuta01A00010 finché il file vive. Questa guardia protegge il lifetime, non l'identità della directory.

Nei12ritorni normali, file close rimuove l'oggetto se presente e volume close libera una volta quattro buffer. ctx+788=1 dichiara l'ownership FAT:1F36C0 libera la finestra e azzera780; le celle dei tre buffer dati436/712/716 restano nonnulle dopo i free. Clock, predicato dirty/cache close, pool e ioctl volume3 sono fixture, senza writeback fisico.

Il ciclo2→3→2 viene fermato al dodicesimo ingresso nel servizio dati:12lock PM/11post, nessun file pubblicato, due scratch attivi, nessun close. È uno **stop intenzionale dentro una chiamata attiva**, non prova di leak hardware. Status del probe non ancora assegnato, non codice Nikon. Verificate guardie e distrutto il modello. Lo stesso limite osservativo vale nei profili intermedi.

## Limiti e prossimo passo

La separazione precedente fra FAT multisettore e r/close è superata fino agli adattatori SD. Prossimo: eseguireB15B4/B16D0 e completamento su profilo hardware dichiarato e risalire al produttore del flag49. Lo stato0 dei servizi dati rimane un presupposto simulato.

Non certificati: mount/registrazione/stato partizioni, cache esterne,long-name/DCIM,scritture FAT,dirty close,concorrenza e recupero fisico. Restano mappa RAM completa, creazione esclusiva, waitRTOS e task/stack/hook propri per il dumper. C AkeruOS,BIN,dump e GNU invariati. Circa10% funzionale invariato, **NON_INSTALLARE**, goal aperto.

## Continuazione — motori read e PIO eseguiti

[S33_Dumper_RAM_SD_Lettura_PIO_Motori_e_Completamento_Originali.md](S33_Dumper_RAM_SD_Lettura_PIO_Motori_e_Completamento_Originali.md):20PIO,28motori,13r/FAT/PMSD/SD/PIO/close. Il confine prima degli interi B15B4/B16D0 è superato: preparazione,descrittori,copia CPU/MMIO e completamento ora eseguiti. Dispatcher comandi2E52F4 e25AA8C restano fixture;profili sintetici,non prova elettrica. Percorso write/asincrono non generalizzato dal read. Nessun hardware o BIN modificato.

## Continuazione — motori write e rilettura,23ottobre2026

[Nuovo collegamento](S33_Dumper_RAM_SD_Motori_Write_PMSD_e_Rilettura.md):24casi eseguono PMSD/DEVSD e motori25B9C0/25BB5C con comandi/gate/PIO originali;13riletture/11264byte,15catture12800byte,regressione36PASS. Errori dopo256byte pertre tentativi diventano raw/PMcount0;flag49=1 conserva falso successo senzaemissione. La scheda è una finestraRAM,nonFAT;async senza copiaDMA dichiarata. Il callback filesystem1F4958/21A4B8 ecluster2A0D70 restano da integrare,poi creazione/sync/close/riapertura. Stime perarea nelrapporto,obiettivoattivo,Cinvariato,NON_INSTALLARE.
