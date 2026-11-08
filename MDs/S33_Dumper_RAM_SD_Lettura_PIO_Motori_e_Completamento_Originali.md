# S33 — lettura CPU, motori SD e completamento originali

23 ottobre 2026, R0/R1/R4. Continuazione della [catena PMSD/DEVSD](S33_Dumper_RAM_SD_Catena_PMSD_DEVSD_e_Contratto_Conteggi.md). Il percorso di lettura non è più sostituito al ritorno del servizio SD: ora vengono eseguiti B15B4/B16D0, preparazione, descrittori, copia CPU dalla porta dati e completamento. Il profilo MMIO è sintetico; nessuna fotocamera o SD fisica coinvolta.

## Prove e confine simulato

| Gruppo | Casi | Evidenza |
|---|---:|---|
| CPU reader e accessi MMIO | 20 | [prova](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_PIO/20261023T091814Z/verified_evidence.json),5finestre GNU |
| Motori single/multi, descrittori e completamento | 28 | [prova](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Engine/20261023T093432Z/verified_evidence.json),16finestre GNU |
| r/FAT/PMSD/DEVSD/motori/PIO/close | 13 | [prova integrata](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_PIO_Chain/20261023T092810Z/verified_evidence.json),56finestre GNU |
| Regressioni ai confini precedenti | 13+13+13 | [adattatore SD](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_SD_Chain/20261023T092951Z/verified_evidence.json),[callback dispositivo](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Chain/20261023T092951Z/verified_evidence.json),[lookup diretto](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Chain/20261023T092951Z/verified_evidence.json) |

PIO:18ritorni e2osservazioni di attesa interrotte. Motori:27ritorni e1attesa interrotta. Ogni matrice FAT13:12ritorni e1ciclo interrotto. Sono scenari ripetuti a confini differenti, non100comportamenti indipendenti terminati. Snapshot sorgenti,hash16payload,log,tracce eGNU conservati.

```sh
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_pio.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_engine.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_pio_chain.py
```

Restano fixture: esiti del dispatcher comandi2E52F4 e risposta di preparazione, controllo25AA8C,cache17FAA4,acquisizione servizio2801F0 nei casi appositi,recupero25B63C nella catena,delay2E500C e primitive heap/pool/close già dichiarate. La moltiplicazione3342A8 resta prodotto modulo2^32 modellato perché MULUDW non è supportato. Nessuna semantica DSP fisica provata.

Gli accessi dati e stato sono invece le istruzioni originali `ldh.di`: il test scrive soltanto i campioni nei registri del modello immediatamente prima del load. La destinazione è riempita dagli store originali del firmware, non dal test. Questo prova il percorso software con quei campioni, non FIFO reale,cache,DMA o interrupt fisici.

## Lettore CPU 25A74C e fallback byte 25A690

Firma osservata `(selettore,buffer,bytePerBlocco,blocchi)`. Il buffer pari usa store halfword con incremento2; il buffer dispari passa a25A690 e scrive due byte separati. Sono verificati allineamenti0/1/2/3,uno/due blocchi,512×2byte e selettori0/800.

| Helper | Indirizzo letto nel codice, meno selettore |
|---|---|
| 25A084 | 0FF01800,primo stato |
| 25A0BC | 0FF01804,secondo stato |
| 25A41C | 0FF01834,porta dati |

Le prove asseriscono gli indirizzi effettivi al load, tutti i byte destinazione e guardie esterne. Il campione isolato è `(0x4100+73*n)&FFFF`: permette di riconoscere ordine e parte alta/bassa della halfword. Con secondo selettore vengono usati0FF01000/004/034.

Primo stato bit4=0 ammette il trasferimento. Nell'altro ramo si legge il secondo stato: bit0 sceglie00E01510,altrimenti bit1 sceglie00E01610. Entrambi impostati: prevale bit0. Dopo due halfword già copiate, un errore iniettato nel ramo interno produce00E01611: i primi4byte rimangono nel buffer e gli altri sono invariati.

Il bit6 del primo stato seleziona il ramo a gruppi; il caso32byte verifica16campioni con tre sole letture del primo stato. Non è dedotta la capacità FIFO fisica da quel numero.

Un profilo attende tre volte e poi diventa pronto: la copia riprende e riesce. Un altro resta occupato ed è interrotto al32°ingresso di lettura del primo stato, prima di copiare dati. L'attesa finale del bit7 è distinta: un caso copia tutto il buffer,poi è interrotto al64°ingresso sul secondo stato senza ritorno normale. **Buffer pieno non equivale a operazione completata.**

Il limite finale1B2920 e l'errore00E01410 sono verificati nei byte e nei confronti originali; questo numero di iterazioni non è stato esaurito dinamicamente. Gli stop32/64 sono limiti del probe, non timeout Nikon né misure temporali.

Casi di contratto con geometria non ordinaria: block-size17 per2blocchi copia32byte contigui e lascia2byte della lunghezza richiesta invariati; size0/count1 e size16/count0 possono tornare0 senza dati. Il lettore usa la parte intera della divisione per2. Non si afferma che il contesto Nikon reale ammetta dimensioni dispari o nulle: la catena integrata usa512.

## B15B4 e B16D0: preparazione, descrittori e range

Il multi B15B4 riceve conteggio esplicito; il single B16D0 usa1. Configurazione sintetica isolata: capacità100,dimensione blocco16,RCA1234,parametroCC=1 e modalità indirizzoD8.

Il campo D8 esattamente1 conserva la posizione nel descrittore. Altri valori seguono il prodotto posizione×dimensione: nei test7→112. È condizionale al modello di3342A8. Il costruttore originale2E509C scrive tipo,comando,conteggio,argomento e flag nel descrittore sullo stack; il probe li verifica al dispatcher.

La preparazione originale2E514C emette descrittori0D finché la risposta assume stato3 o4. Stato3 esegue poi07 e completamento; **stato4 ritorna direttamente0**,senza07 né quel polling: anche questo ramo è eseguito nel probe. Con risposta2 costante esegue **100poll originali**,sceglie00E00011 e il motore passa alla propria uscita d'errore. La traccia contiene101comandi0D:100di preparazione più1di recupero. Non è una prova di un timeout in millisecondi.

| Percorso | Sequenza comandi osservata |
|---|---|
| single riuscito | 0D,07,11 |
| multi riuscito | 0D,07,12,0C |
| errore comando single | 0D,07,11,0D |
| errore dati multi | 0D,07,12,0C,0D |
| range rifiutato prima della preparazione | 0D |

I numeri sono i selettori nei descrittori,senza attribuire qui nomi di protocollo esterno. Il controllo25AA8C riceve1all'ingresso e0all'uscita normale; i suoi risultati sono sostituiti e nel caso di errore iniettato non cambiano il risultato conservato del motore. Non è eseguito il suo polling hardware interno.

Range: single richiede posizione<capacità,multi anche posizione+conteggio<=capacità. Verificati ultimo settore99,richiesta98+2 ammessa,99+2 rifiutata e posizione100 rifiutata. Errori00E00301single/00E00300multi. **Anche il rifiuto del range emette il descrittore di recupero0D**,con argomentoRCA<<16,pur senza copia dati. Il primo probe si aspettava nessun comando: la traccia ha smentito questa previsione e il ramo originale verso l'epilogo d'errore ne conferma la causa. Overflow e conteggi arbitrari non sono coperti.

## Esito dati, stop e completamento

2E52E8→25AA54 seleziona il lettore CPU quando modo diverso da1. Con modo1 prepara il buffer tramite17FAA4 e passa a25A83C: buffer non allineato4 ripiega sullo stesso CPU reader; buffer allineato raggiunge il servizio2801F0. Il probe verifica il contratto dell'acquisizione e ne inietta un errore prima che l'oggetto sia acquisito. Completamento asincrono,attese e rilascio del servizio non sono provati da questi casi.

Nel multi,l'esito dati viene conservato mentre si emette0C. Un errore dati prevale sull'errore0C. Se dati riusciti e0C fallisce,quell'errore prevale,tranne00E00200 che viene accettato anche lontano dalla fine capacità: poi viene verificato il completamento2E5634→25A658. Questo differisce dalla condizione di confine del percorso write storico; non generalizzare la regola fra read e write.

25A658 è eseguito nel P-code: bit2 del secondo stato produce00E00103,bit8produce0;altri rami/errori e ripetizione restano quelli del corpo originale. Un errore qui dopo la copia lascia il buffer completo ma ritorna errore,poi viene emesso0D senza perdere l'errore iniziale. Nel caso di attesa finale interrotta,il buffer è completo ma il controllo0d'uscita non è ancora stato invocato.

Il single,al contrario,non chiama un secondo completamento2E5634 dopo il lettore dati riuscito: la prova prepara correttamente il dispositivo,poi offre durante la PIO il solo bit7,senza bit8,e il motore ritorna0. Nel caso con preparazione stato3 rimane il suo completamento precedente. Un ulteriore caso stato4 esegue solo0D,11 e il controllo PIO bit7: nessun25A658. Non è assenza di ogni controllo hardware,perché resta il polling dati.

## r/FAT/PMSD/PIO/close nella stessa esecuzione

La matrice integrata mantiene root100/101,data102,FAT20/21,due settori per cluster,offsetPM2048 e blocchi512. Aggiunge contesto SD sintetico4463E0 con capacità4096 e indirizzi a blocchi. I due semafori FS/PM e2015/16 originali restano attivi. Il dispatcher comandi è ancora fixture; l'ingresso ai motori non riempie più direttamente la RAM.

Per ogni richiesta il test costruisce soltanto lo stream della porta dai settori sorgenti. Ciascuna halfword entra tramite il load originale25A426 e viene scritta dal reader CPU. Il numero di campioni e l'identità finale del record sono verificati:

| Caso | Halfword caricate dalla porta | Risultato |
|---|---:|---|
| secondo settore root | 512 | record cluster0/indice17 |
| un salto FAT | 1536 | record cluster3/indice1 |
| due salti FAT | 2048 | record cluster4/indice0 |
| FAT0 corrotta | 1536 | r/open accetta ancora il file root omonimo |
| errore PIO sulla FAT | 768precedenti | errore00E01510 dall'avanzamento,lookup01A00002 |
| errore PIO sui dati | 512precedenti | r/open ritorna00E01510 |

L'errore ora nasce dai rami MMIO originali,non da un codice restituito direttamente dal motore sintetico. La lettura fallita viene ritentata3volte dall'adattatore SD. Restano riproducibili perdita dell'errore FAT e identità directory errata con dati corrotti,anche attraversando i motori e la copia reali del firmware.

Nei12ritorni normali vengono liberati una volta i quattro buffer predisposti e rilasciati entrambi i semafori. Il ciclo FAT è fermato prima di eseguire il12°ingresso nel motore:3072campioni già caricati,PMlock12/post11 e nessuna chiusura normale. È un'osservazione interrotta deliberatamente,non un leak fisico o un ritorno0.

## Limiti e prossimo passo

Il prossimo confine è **il dispatcher comandi2E52F4**: ricostruire ed eseguire emissione/risposte e controlli25AA8C con un profilo registri dichiarato. Separatamente resta il percorso asincrono25A83C e il produttore del flagvolume49 che può saltare il backend.

Nessuna validazione elettrica di MMIO,FIFO,cache,DMA o interrupt;nessun mount completo,dirty writeback o recupero fisico. Restano mappa RAM completa,creazione esclusiva,waitRTOS e task/stack/hook per il dumper. Firmware originali,dump,GNU,C AkeruOS e BIN invariati. Circa10% funzionale invariato,**NON_INSTALLARE**,goal aperto.

## Continuazione — dispatcher e gate originali eseguiti

[S33_Dumper_RAM_SD_Comandi_Risposte_e_Controllo_Originali.md](S33_Dumper_RAM_SD_Comandi_Risposte_e_Controllo_Originali.md):40casi isolati e16scenari r/FAT/PMSD/SD/comandi/PIO/close;2E52F4 e25AA8C non sono più fixture nel nuovo profilo. Provati timeout8000 e limiti gate2000, risposta dalla porta originale, tipo0 che scarta errore e resetcountalto fisso0FF01854. Errori comando/risposta dati propagati dopo3tentativi, erroreFAT ancora trasformato in02. Quattro regressioni13casi PASS. Le prove precedenti mantengono il proprio confine; nientehardware. Prossimo25A83C/2801F0 asincrono e lifetime buffer, produttoreflag49. NON_INSTALLARE.

## Continuazione — chiamante read asincrono

[S33_Dumper_RAM_SD_Lettore_Asincrono_Attese_e_Uscite_Parziali.md](S33_Dumper_RAM_SD_Lettore_Asincrono_Attese_e_Uscite_Parziali.md):21scenari del corpo25A83C,servizi inferiori/eventi fixture. Verificati30controlli consecutivi senza progresso,uscite parziali dopo acquisizione e precedenza degli errori cleanup. Non trasferisce dati e non amplia il profilo filesystem integrato. Prossimo2801F0/27FCD4,28080C/281158,ownership ecallback/eventi originali. NON_INSTALLARE,nessunhardware.
