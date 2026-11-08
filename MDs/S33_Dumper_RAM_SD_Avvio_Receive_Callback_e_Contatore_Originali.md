# S33 — avvio receive, callback e contatore originali

23 ottobre 2026, R0/R1/R4. Continuazione degli [oggetti di ricezione](S33_Dumper_RAM_SD_Oggetti_Ricezione_Acquisizione_e_Rilascio.md). Il nuovo gruppo esegue **28080C**,i tre programmatori dei registri,la pubblicazione della callback,il dispatcher267F20 fino alla chiamata indiretta e le callbackSD25ADBC/25ADC4. Eseguito separatamente anche il getter avanzamento266E9C sui sei oggetti write/read.

**Il byte di uscita del servizio avvio è calcolato prima della notifica:**riflette la quantità residua dopo la sottrazione,non dati già ricevuti. La callback viene invocata soltanto in una seconda fase del test,con registri e ingresso al dispatcher predisposti esplicitamente. Nessuna consegna interrupt fisica o copia dati è provata.

## Prove riproducibili

[33 scenari](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Start/20261023T132917Z/verified_evidence.json), [traccia](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Start/20261023T132917Z/trace.txt), [finestre GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Start/20261023T132917Z/gnu_verified.txt). **13 avvii/dispatch +20 getter avanzamento,tutti ritornati**;60finestre GNU mirate,16istruzioni chiave e pool di callback,registri ed errori verificati. Snapshot/hash dei sorgenti e16payload,comando e log conservati.

```sh
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_start.py
```

Sorgenti: [probe](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDReadStart.java), [runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_read_start.py). Non cambia i probe condivisi precedenti. La sola API di esito sostituita durante il percorso start/dispatch è158CBC,usata come registratore della richiesta di pubblicazione evento. Le divisioni335B34 e le sezioni critiche1786E8/179354 sono eseguite nei corpi originali.

## Avvio e registri del buffer

28080C conserva oggetto,buffer,callback e indirizzo dell'uscita byte. Riconosce i tre oggetti fissi già ricostruiti;il test predispone direttamente i campi,senza ripetere l'acquisizione in questo gruppo.

| Oggetto | Programmatore originale | Registro buffer low/high | Setter callback → slot |
|---|---|---|---|
| 512CC8 | 280338 | FEE04C8/FEE04CC | 266FB0 →36B358 |
| 512CEC | 280540 | FEE00C4/FEE00C8 | 266FB8 →36B35C |
| 512D10 | 2806A4 | FEE0144/FEE0148 | 266FC0 →36B360 |

Gli indirizzi del buffer sono verificati sulle halfword finali,non soltanto sugli argomenti del servizio. Buffer laboratorio02010010 →low0010/high0201. La callback viene realmente salvata dagli store dei setter originali:un precedenteCAFEBABE viene sostituito anche quando il nuovo valore è0.

I programmatori chiamano2822C4 con divisore128,che scrive sullo stack resto normalizzato e quoziente arrotondato verso l'alto usando335B34. Se il resto è0,il primo campo viene sostituito con128. Questi campi alimentano gli store dei registri di controllo/conteggio. La suite attraversa i tre programmatori con step1024e il confine corto7FFF80 sul primo oggetto;non è una prova di ogni formato lungo,di ogni registro o di un motoreDMA reale.

Il byte software36C19B distingue il ramo iniziale da quello di continuazione. Entrambi sono eseguiti per512CC8. L'oggetto sconosciuto0200A000 viene rifiutato con01E03D71,lasciando callback e uscita byte precedenti invariati. Tutti i ritorni di start/dispatch ripristinano stack e livello critico.

## Quantità residua e uscita byte

Nel tratto comune280C94..280CA4,il codice sottrae **oggetto+C** da **oggetto+8**,salva il residuo e scrive1nell'uscita byte soltanto se il risultato è0. Queste scritture precedono l'ingresso del test nel dispatcher di notifica.

| Total iniziale / step nel descrittore predisposto | Residuo dopo start | Uscita byte | Ritorno |
|---|---|---:|---:|
| 1024/1024 | 0 | 1 | 0 |
| 2048/1024 | 1024 | 0 | 0 |
| FFFFFFFF/1024 | FFFFFBFF | 0 | 0 |
| 0/1024 | FFFFFC00 | 0 | 0 |
| 7FFF80/7FFF80 | 0 | 1 | 0 |

I casi0eFFFFFFFF sono **contratti di descrittori predisposti**,non una dimostrazione che ogni caller reale produca quelle combinazioni. Il ramo provato applica la sottrazione unsigned senza rifiutare localmente il caso0. La suite precedente aveva verificato separatamente la sentinellaFFFFFFFF nel wrapper di acquisizione;non è ancora una prova integrata di tutte le transizioni fra i due servizi.

Anche nel caso uscita1,non sono ancora avvenuti né l'invocazione della callback né il trasferimento nel modello. Quel byte non basta per decidere il riuso del buffer.

## Dallo slot alla notificaSD

Il test esegue l'intero ingresso originale **267F20**,con il relativo prologo,anziché saltare direttamente alla chiamata indiretta. Dopo start predispone una sola causa di stato e la maschera corrispondente.

| Slot | Bit della halfwordFEE0038 che deve essere0 | Bit presente inFEE0034 | Flag software scritto1 |
|---|---:|---:|---|
| 36B358 | 7 | 7 | 36B3E7 |
| 36B35C | 0 | 0 | 36B3E8 |
| 36B360 | 1 | 1 | 36B3E9 |

Nel ramo scelto,il dispatcher imposta il bit della maschera,scrive il flag e riscrive la maschera selezionata sul registro di stato. Poi carica il puntatore dallo slot ed esegue **jl_s[r0] a2689F6** se non nullo. Le asserzioni controllano che venga raggiunta proprio la callback precedentemente salvata da28080C,senza sostituire setter,load dello slot,chiamata indiretta o corpo della callback.

25ADBC raggiunge158CBC con gruppo **E00005** e maschera **40**;25ADC4 usa **40000**. Il test registra questi argomenti al confine della API evento e ne fornisce l'esito0. Non esegue qui l'oggetto evento,la lista waiter o il risveglio RTOS. Il percorso write storico usa altre callback e altre maschere:non confondere questi bit con200del precedente [rapporto write](S33_Avvio_Trasferimento_e_Callback_SD.md).

Sono verificati anche tre esiti distinti:bit della causa mascherato →nessuna callback;stato assente →nessuna callback;stato presente con slot nullo →flag/writeback eseguiti,nessuna pubblicazione evento. Nel caso nullo il setter originale ha realmente scritto0nello slot. Lo slot non viene azzerato dal dispatcher dopo l'invocazione.

### Confine aggiuntivo nei casi negativi

Il primo tentativo si è fermato su una lettura non inizializzata aFE1000C:quando nessuna callback precedente viene selezionata,lo stesso dispatcher attraversa un'altra famiglia di cause. Il [log conservato](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Start/20261023T132650Z/headless.log) documenta un limite del profilo,non un difetto della fotocamera.

Il profilo finale dichiara **FE1000C=7**,che maschera i tre bit0/1/2 controllati nella coda. Le prove negative asseriscono tre letture di questa maschera e nessuna lettura del relativo pending **FE10008**,che resta non inizializzato. Non è stato riempito il pending con uno zero inventato per superare il controllo. Le altre condizioniMMIO del profilo sono esplicite e sintetiche;non vengono presentate come valori misurati.

## Getter di avanzamento266E9C

Il getter riconosce sei puntatori fissi,comprendenti sia gli oggetti write sia quelli receive. Legge una halfword `.di` e salva **campione<<7**,quindi ritorna0.

| Oggetto | Registro letto |
|---|---|
| 512C5C | FEE0538 |
| 512C80 | FEE032C |
| 512CA4 | FEE03AC |
| 512CC8 | FEE04F4 |
| 512CEC | FEE00EC |
| 512D10 | FEE016C |

Per ciascuno sono eseguiti campioni0,1,FFFF →valori0,80,7FFF80. Asseriti indirizzo effettivo del load,unica lettura,risultato,guardie dell'uscita e stack. Puntatore non riconosciuto o uscita nulla →01E03600senza lettura MMIO o modifica della cella predisposta.

Le strutture del gruppo getter sono azzerate e non acquisite:la routine restituisce comunque0per i sei indirizzi riconosciuti. **Questo getter non valida ownership o campo+4attivo**;un valore di avanzamento non dimostra che l'associazione al trasferimento sia ancora valida. Il significato elettrico e l'unità fisica del contatore non vengono assegnati oltre alla trasformazione software eseguita.

## Limiti e prossimo passo

Destinazione1024byte sempre31,guardieA5 intatte:programmazione dei registri e notifica sintetica non emulano il trasferimento fisico. I casi con step alto non leggono un buffer di quella dimensione. Il dispatcher è invocato dal test,non da un vettoreCPU/interrupt consegnato dal modello. Writeback,W1C,DMA/cache e arresto fisico restano aperti.

Prossimo: collegare **25A83C + acquisizione +28080C +266E9C + dispatcher/callback + rilascio** nella stessa esecuzione e poi sostituire il confine evento con i servizi RTOS originali. Gli errori artificiali dei vecchi fixture start/progress non vanno promossi automaticamente a casi raggiungibili dei corpi originali. Arbitraggio delle risorse,ultimo uso del buffer,filesystem asincrono e binding del dumper restano da completare.

Firmware originali,dump,GNU,C AkeruOS e BIN invariati. Circa10% funzionale invariato,**NON_INSTALLARE**,goal aperto.

## Continuazione — catena con eventi RTOS originali

[S33_Dumper_RAM_SD_Catena_Asincrona_Eventi_RTOS_Originali.md](S33_Dumper_RAM_SD_Catena_Asincrona_Eventi_RTOS_Originali.md):13scenari25A83C/oggetti/start/dispatcher/callback/SET/WAIT/query/CLEAR/release,10ritorni+3waitaccodati osservati prima2313AC. Eventoeffettivo373228,tabellastaticabase372A48;auto-clear1spiega querysenza completion dopowait riuscito. EndByte1puòcoesisterecon task1069ancora inwait. Progressgetter nonraggiunto daquestiprofili:prossimo deadline/scheduler/timeout e callbackstatus reali;notificaCABIinnestata,nonIRQfisico. NON_INSTALLARE.
