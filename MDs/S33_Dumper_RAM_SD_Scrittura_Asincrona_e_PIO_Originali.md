# S33 — scrittura SD asincrona e copie PIO originali

23 ottobre 2026, R0/R1/R4. Continuazione dell'[arbitraggio risorse](S33_Dumper_RAM_SD_Arbitraggio_Risorse_e_Stop_Software_Originali.md). Il lavoro raggiunge il percorso **buffer→porta SD**, necessario al dumper: il chiamante write originale viene eseguito sia nel ramo con servizio asincrono sia nel fallbackPIO. Non si deduce la scrittura dalla sola somiglianza con il receive.

**Risultato:**24 scenari asincroni eseguono prenotazione, avvio, registrazione stato, attese, notifiche, timeout, avanzamento e rilascio. Altri12 scenari eseguono le istruzioni originali che leggono il buffer e scrivono halfword alla portaMMIO simulata:8 copie complete da1024 byte e4 copie parziali da256 byte con errore. Nessun dato proviene dalla RAM della fotocamera o viene scritto su una SD fisica.

## Prove riproducibili

[36 casi CPU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Write_Async/20261023T143944Z/verified_evidence.json), [traccia](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Write_Async/20261023T143944Z/trace.txt), [GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Write_Async/20261023T143944Z/gnu_verified.txt):**tutti ritornati**,39 finestre GNU,21 istruzioni chiave.16 hash dei payload verificati; snapshot di runner, probe ed helper, comando e log conservati. Le12 catture `.dat` registrano9216 byte complessivi letti dalla porta simulata dopo gli store originali e hanno hash nelJSON.

```sh
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_write_async.py
```

[Runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_write_async.py), [probe](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDWriteAsync.java). Riutilizzati i probe precedenti senza modificarli. Il motoreC del dumper non è ancora collegato a queste funzioni.

## Oggetto write e avvio

Ingresso **3040DC(selettore,buffer,512,2)**, con buffer allineato a4. Il corpo calcola1024 byte tramite3342A8 modellato e chiama **2BFE88→2BFAF8**. Per il profilo provato viene prenotata la risorsa **1E00000**, record **374300**, e pubblicato l'oggetto **512C5C** con id10202/10203. È distinto dal receive512CC8 e dalla sua risorsa1E00003. Il costruttore15933C e il try-acquire1594E4 sono originali; non viene restituito direttamente un oggetto dal test.

**2C00E4** prepara i registri, programma il servizio inferiore266FC8 e salva la callback via **268BC4** nello slot **36B3D8**. Nel caso step=total=1024 provato, è questo slot a essere usato; non36B364. Il dispatcher corrispondente è **2689FC**, che controlla bit1 di0FF00020 e0FF00024 e invoca il puntatore attraverso **268A50**. È un ingresso distinto da267F20; il test lo invoca come funzioneCABI, senza rivendicare il vettoreIRQ fisico.

Il residuo oggetto+8 diventa0 e il byte di uscita del servizio avvio diventa1 **prima della notifica**. Anche sul write quel byte non dimostra che i dati siano arrivati al supporto.

## Stato, completion ed errori

158C30 inizializza l'eventoE00005 dai flag statici2; il modo inferiore è0. La registrazione status266768/26671C installa le callback3042E4/304324 attraverso il router condiviso040E. Il walker2640E0 e il dispatcher2667FC vengono eseguiti prima della callback; i campioni sono letti dall'originale25A0BC a0FF01804−selettore.

| Causa campionata | Evento selettore0 /800 | Ritorno3040DC |
|---|---|---|
| callback dati304368 /304374 | 200 /200000 | 0 |
| stato bit2 | 400 /400000 | E01211 |
| stato bit3 | 800 /800000 | E01321 |
| stato bit2+bit3 | solo400 /400000 | E01211 |

Per ciascun selettore sono provati nessun errore, i due bit separati, entrambi, errore seguito da completion, auto-clear forzato1 ed enable framework fallito. Con errore+completion prevale l'errore e il bit completion rimane pendente201/200001 insieme al bit estraneo1. L'ordine è scelto dal test; non è una prova di tutti gli interleaving.

Il SET originale rimuove il task dalle liste evento/deadline e permette il ritorno effettivo del WAIT. Il chiamante esegue query/CLEAR e **2C0C84/2C0B84**, con post reale della risorsa. Oggetto+4 e cella handle diventano0, il token torna1 e la maschera controller tornaFFFF. I flag software36B3E4 e36C7B4 sono azzerati. Errori di stato fanno eseguire deregistrazione dalla callback e dal chiamante.

Con flags3 forzati, l'auto-clear consuma l'errore prima della query e il chiamante ritorna0: il profilo statico2 non va riconfigurato arbitrariamente. Con framework367884=0 l'enable ritorna200604 prima dello start, ma restano token0, handle/id e maschera **EFDF**; non viene dichiarato un cleanup normale.

## Timeout e avanzamento originali

Sei scenari aggiuntivi provano tre profili per entrambi i selettori. Il test chiama2F70C4 fino alla scadenza registrata dai corpi2313AC/28179C; non sostituisce il codice restituito dal WAIT. Con clock predisposto1000/1000 e r3=100, ogni timeout richiede100 invocazioni software del tick e scade all'uguaglianza.

| Profilo | Timeout/letture266E9C | Esito |
|---|---:|---|
| un timeout, poi callback dati | 1 | 0 |
| contatore invariato | 9 | E01211 |
| campione passa da0 a1 alla quinta lettura, poi resta1 | 14 | E01211 |

Il getter originale legge **FEE0538**, halfword×128. Il test fornisce soltanto il campione MMIO. Dopo il cambio, all'ingresso del sestoWAIT sono asseriti riferimento128 e contatore stagnazione0: il ramo del chiamante è realmente attraversato. Totale **48 timeout,48 letture progress e4800 tick**. Il limite9 riguarda controlli consecutivi senza avanzamento, non9 attese totali e non una durata hardware misurata. E01211 è condiviso con l'errore status bit2, perciò il solo risultato non distingue tutte le cause.

## Copie PIO: byte sorgente contro store originali

Un buffer a indirizzo con resto1 o2 modulo4 devia da3040DC a **304004**. Con resto1 entra ulteriormente in **303F24** e assembla la halfword da due load byte; con resto2 usa loadhalfword.25A430 esegue **sth.di** alla porta **0FF01834−selettore**.

Gli8 casi positivi combinano selettori0/800, allineamenti1/2 e statoFIFO bit4 spento/acceso. Ogni caso verifica512 storehalfword, ordine e valore di tutti i1024 byte. Il test raccoglie i dati **dopo l'esecuzione dello store CPU**, confrontandoli con il pattern sorgente e conservandoli in una cattura; non riempie la porta con i dati attesi al posto del codice originale. Il polling finale legge bit7 del secondo registro, predisposto nel profilo.

I4 negativi fanno comparire bit6 del primo stato dopo128 store e forniscono bit2 oppure bit3 nel secondo. Restituiscono rispettivamente **E01200/E01310**, con esattamente256 byte catturati e nessun altro store. Il sorgente e le guardie restano integri. Non vengono prenotati oggetti asincroni in questi fallback.

Queste prove rendono osservabile la copiaCPU nel laboratorio. La porta è memoria simulata, non una FIFO fisica; nessuna cattura `.dat` è un file già scritto sulla SD.

## Confini e prossimo passo per il dump

Kernel/ready, inizializzazione framework, identitàCPU e MMIO sono predisposti. I prodotti3342A8/336364 sono modellati. Le API risorse/eventi/stato e gli helper software sono originali. **B2D50 rimane intercettato prima del salvataggio del frameCPU**; gli invocatoriCABI controllano stack/callee/gp/fp e ripristinano i volatili. I profili asincroni non eseguono una copiaDMA; i profiliPIO eseguono la copia versoMMIO simulato. Non è una prova elettrica, di cache, di persistenza o del firmware completo.

Prossimo: raccordare i motori write a PMSD/DEVSD e al write filesystem, fino a creazione esclusiva e close; mantenere il controllo dell'identità del file e degli errori già scoperti. Rimangono necessarie mappa fisica RAM completa, memoria privata e hook/task, compatibilità dell'immagine della macchina e recupero. AnalisiV1.1 distinta dallaV1.0 nei log hardware. Nessun hardware o firmware installabile prodotto; GNU eC AkeruOS invariati, **NON_INSTALLARE**, circa10% funzionale invariato.

## Continuazione — motori write e rilettura,23ottobre2026

[Nuovo collegamento](S33_Dumper_RAM_SD_Motori_Write_PMSD_e_Rilettura.md):24casi eseguono PMSD/DEVSD e motori25B9C0/25BB5C con comandi/gate/PIO originali;13riletture/11264byte,15catture12800byte,regressione36PASS. Errori dopo256byte pertre tentativi diventano raw/PMcount0;flag49=1 conserva falso successo senzaemissione. La scheda è una finestraRAM,nonFAT;async senza copiaDMA dichiarata. Il callback filesystem1F4958/21A4B8 ecluster2A0D70 restano da integrare,poi creazione/sync/close/riapertura. Stime perarea nelrapporto,obiettivoattivo,Cinvariato,NON_INSTALLARE.
