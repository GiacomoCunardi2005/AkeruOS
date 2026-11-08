# S33 — lettore SD asincrono: attese e uscite parziali del chiamante

23 ottobre 2026, R0/R1/R4. Continuazione dei [comandi SD nella catena originale](S33_Dumper_RAM_SD_Comandi_Risposte_e_Controllo_Originali.md). Eseguito il ramo allineato di **25A83C** nel P-code originale, insieme ai veri helper MMIO della maschera. Le API di acquisizione/avvio/progresso/rilascio, registrazione callback e attesa eventi restano fixture esplicite. Questo gruppo prova i rami e gli obblighi del chiamante; non esegue un trasferimento asincrono reale né lo integra nel filesystem.

## Evidenza e riproduzione

[21 scenari](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Async/20261023T130343Z/verified_evidence.json), [traccia](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Async/20261023T130343Z/trace.txt), [finestre GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Async/20261023T130343Z/gnu_verified.txt). **20 ritorni e 1 osservazione interrotta**,5finestre GNU,14istruzioni chiave e8pool verificati. La seconda esecuzione aggiunge asserzioni sul valore finale dell'handle e sulla sequenza esatta delle maschere evento; lo snapshot precedente rimane storico.

```sh
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_async.py
```

Sorgenti: [probe](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDReadAsync.java) e [runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_read_async.py). Ogni prova conserva snapshot/hash,identità16payload,log,comando e traccia. Gli errori E07770..E07778 sono codici distinti scelti dal test per riconoscere quale API viene propagata; non sono attribuiti al controller Nikon.

## Contratto osservato al confine inferiore

25A83C riceve selettore,buffer,dimensione blocco e conteggio. I test usano buffer allineato4 e512×2byte. Il prodotto3342A8 è ancora modellato modulo2^32 per MULUDW non supportato. Il fallback non allineato alla copia CPU è già coperto dal [gruppo motori precedente](S33_Dumper_RAM_SD_Lettura_PIO_Motori_e_Completamento_Originali.md).

| Passaggio originale | Argomenti controllati |
|---|---|
| 25A488 → 2801F0 acquisizione | porta0FF01834−selettore,1024,1024,id202/203,&handle sullo stack |
| 266768 registrazione | id1002/1004,callback25AD3C/25AD78 |
| 26671C abilitazione | id1002/1004 |
| 158CE0 pulizia iniziale | gruppoE00005,mask1C0/1C0000 |
| 28080C avvio | handle,buffer,callback25ADBC/25ADC4,&uscita a stack+4 |
| 158D04 attesa | gruppoE00005,mask1C0/1C0000,arg2=0,arg3=100 |
| 266E9C avanzamento | handle,&contatore a stack+12 |
| 158E28 lettura evento | gruppoE00005,&bit a stack+8 |
| 281158 o alias2812B8 | &handle sullo stack |

Le due colonne di valori si riferiscono ai selettori0/800. Non è provata l'unità temporale dell'argomento100 o una particolare implementazione DMA.

25A444 modifica il registro **0FF01840−selettore**, cancellando maschera2010;25A464 la reimposta nell'uscita comune. I due store `.di` sono originali e il test controlla indirizzo e valore: partendo daFFFF,passaggioDFEF e ritornoFFFF. La semantica fisica del registro non è certificata.

## Acquisizione seguita da errore iniziale

| Errore API iniettato | Release chiamata | Unregister chiamato | Registro finale | Handle alla fine del chiamante |
|---|---:|---:|---|---|
| acquisizione2801F0 | 0 | 0 | FFFF | nullo |
| registrazione266768 | 0 | 0 | DFEF | ancora quello pubblicato dalla fixture |
| abilitazione26671C | 0 | 0 | DFEF | ancora pubblicato |
| pulizia evento158CE0 | 0 | 0 | DFEF | ancora pubblicato |
| avvio28080C | 1 | 1 | FFFF | consumato dalla fixture release riuscita |

I primi tre errori **successivi all'acquisizione** raggiungono25AA4A senza passare per il tratto comune25AA2E. L'assenza di release e ripristino è dunque verificata nel corpo del chiamante,non dedotta dal solo stato finale. Non basta per diagnosticare un leak fisico: bisogna ancora eseguire2801F0 e stabilire ownership,durata e azioni delle API inferiori.

Il ramo avvio fallito raggiunge invece281158 e l'uscita comune. Se anche la release fixture fallisce e conserva l'handle,il risultato finale resta quello dell'avvio E07774. Il chiamante non trasforma automaticamente l'errore secondario nel proprio esito e non verifica che la cella sia stata azzerata.

## Avanzamento: trenta controlli consecutivi, non trenta attese totali

Quando l'attesa restituisce nonzero,il chiamante interroga266E9C. Errore di questa API →release e uscita con quell'errore. Altrimenti confronta il nuovo valore con il precedente: un cambiamento aggiorna il riferimento e azzera il contatore di stagnazione; un valore uguale incrementa il contatore. Il confronto originale25A944 è con **1E=30**.

| Profilo inferiore fornito | Risultato originale |
|---|---|
| 30 avanzamenti uguali0 | 30 attese,release,00E01520 |
| 10 uguali0,poi4,poi invariato | 41 attese totali,release,00E01520 |
| avanzamento cresce a ogni interrogazione | 63 interrogazioni completate;stop del test al64°ingresso attesa,nessun ritorno |

Il secondo caso distingue un limite di stagnazione da un limite complessivo. L'osservazione interrotta conserva handle,registrazione e mascheraDFEF: il controllo è ancora dentro l'operazione. Non è una perdita dopo un ritorno. Non è stata simulata la durata di ogni attesa,né eseguito uno scheduler.

Questo reader differisce dal [percorso write3040DC studiato staticamente](S33_SD_Registri_Comando_e_Percorsi_Dati.md),che usa nove controlli senza progresso. I due limiti non vanno unificati per analogia.

## Evento, completamento e precedenza degli errori

Con attesa fixture riuscita,158E28 fornisce i bit e il chiamante li verifica nell'ordine bit7,bit19,bit8,bit20. Bit7/19 producono00E01520,bit8/20producono00E01620. Un caso con tutti i bit bassi1C0 sceglie il bit7. La pulizia della singola maschera e il gruppoE00005 sono asseriti esattamente.

Nel ramo residuo,bit6presente →clear40;altrimenti →clear40000. Poi **2812B8 è un branch originale verso281158**,la stessa API usata per le uscite d'errore. Il probe esegue il branch ma sostituisce il corpo release: non attribuisce ancora a quel corpo uno specifico contratto di sincronizzazione del trasferimento.

Se la release finale riesce,il chiamante ripristina la maschera e chiama unregister. Se la release finale fallisce,il suo codice E07776 viene propagato e **unregister viene chiamato due volte**,prima del tratto comune e al suo interno. Un errore dell'unregister dopo release riuscita non sostituisce il risultato0 conservato inr13. Sono verifiche di propagazione del chiamante con esiti inferiori controllati.

Un profilo di contratto fornisce attesa0,query riuscita e maschera ricevuta0:anche così il corpo residuo può raggiungere release e tornare0. Questa combinazione non è dimostrata raggiungibile con i servizi evento reali;la prova delimita la dipendenza del chiamante dal contratto wait/query,non dimostra una race fisica.

**In tutti gli scenari il buffer di1024byte resta esattamente31**,con guardie esterne A5 intatte,perché nessuna fixture effettua il trasferimento. Anche i risultati0sono quindi soltanto successi del flusso di controllo sotto quei contratti,non prove di dati acquisiti o della possibilità di riusare in sicurezza il buffer reale.

## Prossimo confine e limiti

Prossimo: eseguire **2801F0 e selettore27FCD4**,poi **28080C/281158** con oggetti reali del modello. Servono identità dell'oggetto,ownership,maschere,callback e ultimo uso del buffer;poi collegare eventi originali e ramo asincrono alla catena filesystem. Il produttore del flagvolume49 resta separato e aperto.

Nessuna acquisizione reale di oggetti,nessun trasferimento,DMA/cache,interrupt,waitRTOS o filesystem in questo gruppo. Non sono cambiati firmware originali,dump,GNU,C AkeruOS o BIN. Mappa RAM completa,creazione esclusiva e task/stack/hook del dumper restano aperti. Circa10% funzionale invariato,**NON_INSTALLARE**,goal aperto.

## Continuazione — oggetti di ricezione originali

[S33_Dumper_RAM_SD_Oggetti_Ricezione_Acquisizione_e_Rilascio.md](S33_Dumper_RAM_SD_Oggetti_Ricezione_Acquisizione_e_Rilascio.md):18casi2801F0/27FCD4/281158/281064 e21caller25A83C collegati all'oggetto512CC8,regressione21PASS. Tre oggetti receive512CC8/512CEC/512D10 distinti dai precedenti oggetti write512C5C/512C80/512CA4;release consumaid+4 ehandle anche con errorepost. Le releasefixture precedenti non descrivono questo contratto reale. Earlycallback-error lasciarecord nonripulito,senza prova di leakglobale o avviofisico. Avvio28080C/progress266E9C,semafori/eventi e hookstop restano daeseguire. NON_INSTALLARE,nessunhardware.

## Continuazione — avvio receive e notifica originali

[S33_Dumper_RAM_SD_Avvio_Receive_Callback_e_Contatore_Originali.md](S33_Dumper_RAM_SD_Avvio_Receive_Callback_e_Contatore_Originali.md):33casi28080C/programmazione/MMIOdispatcher/callback e266E9C. Slotread36B358/35C/360 ecallbackADBC/ADC4→E00005/40o40000,distinti dal percorso write storico. Il bytefine del servizio avvio è calcolato prima della callback;getterprogress halfword×128nonvalidaownership. Evento158CBC ancora recorder e ingresso dispatcher esplicito; nessuntrasferimento fisico. Prossimo raccordare25A83C/oggetti/start/progress/callback/release e servizi evento originali. NON_INSTALLARE.

## Continuazione — catena con eventi RTOS originali

[S33_Dumper_RAM_SD_Catena_Asincrona_Eventi_RTOS_Originali.md](S33_Dumper_RAM_SD_Catena_Asincrona_Eventi_RTOS_Originali.md):13scenari25A83C/oggetti/start/dispatcher/callback/SET/WAIT/query/CLEAR/release,10ritorni+3waitaccodati osservati prima2313AC. Eventoeffettivo373228,tabellastaticabase372A48;auto-clear1spiega querysenza completion dopowait riuscito. EndByte1puòcoesisterecon task1069ancora inwait. Progressgetter nonraggiunto daquestiprofili:prossimo deadline/scheduler/timeout e callbackstatus reali;notificaCABIinnestata,nonIRQfisico. NON_INSTALLARE.
