# S33 — oggetti di ricezione SD: acquisizione e rilascio originali

23 ottobre 2026, R0/R1/R4. Continuazione del [chiamante asincrono](S33_Dumper_RAM_SD_Lettore_Asincrono_Attese_e_Uscite_Parziali.md). Eseguiti **2801F0,27FCD4,281158 e281064** nel P-code originale. Il gruppo integrato collega questi corpi a25A83C e conferma le uscite parziali con un oggetto originale del modello. Semafori,servizio di avvio/avanzamento,eventi e hook di arresto conservano il confine simulato dichiarato sotto.

## Prove

| Gruppo | Esito | Evidenza |
|---|---|---|
| Oggetti isolati | 18 ritorni;43finestre GNU,6istruzioni chiave | [18 casi](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Object/20261023T131159Z/verified_evidence.json) |
| Chiamante25A83C + oggetto originale | 20 ritorni +1osservazione interrotta;47finestre GNU,19istruzioni chiave | [21 scenari](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Async_Object/20261023T131447Z/verified_evidence.json) |
| Regressione chiamante con oggetto sintetico | 20ritorni +1osservazione interrotta;5finestre GNU | [21 scenari precedenti rieseguiti](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Async/20261023T131447Z/verified_evidence.json) |

Le due matrici21 ripetono gli stessi contratti a confini differenti;non sono42comportamenti indipendenti conclusi. Snapshot,hash dei sorgenti e16payload,comandi,log,tracce eGNU conservati. I corpi originali1786E8/179354 eseguono e bilanciano le sezioni critiche;nelle acquisizioni/rilasci riusciti del gruppo isolato si osservano3coppie,compresa quella annidata del rilascio interno.

```sh
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_object.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_async_object.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_async.py
```

Sorgenti: [oggetto](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDReadObject.java), [chiamante condiviso](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDReadAsync.java), [profilo integrato](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDReadAsyncObject.java). I runner omonimi sottoPython_Trace_Scripts salvano tutti gli input e confrontano i risultati. Nessuna API di acquisizione o rilascio viene sostituita nel nuovo profilo integrato.

## Tre strutture fisse e selezione

27FCD4 sceglie fra tre oggetti,con passo **24hex=36byte**:

| Oggetto | Profilo eseguito | Registro modo associato nel rilascio281064 |
|---|---|---|
| 512CC8 | prima disponibilità osservata;oppure configurazione modo3 | 0FF00028 |
| 512CEC | prime due disponibilità nulle,wait sul servizio04 riuscita;oppure modo4 | 0FF00008 |
| 512D10 | prima disponibilità nulla,seconda presente;oppure modo6 | 0FF00048 |

La configurazione speciale è il record **3F76D4**: parola+0 confrontata con l'id richiesto,parola+4 modo,byte+8 esattamente1. Nei casi configurati il selettore non chiama le API di disponibilità del percorso ordinario;il rilascio interno riconosce lo stesso record e salta il post. I test coprono modi3/4/6 e id202/203,non tutti gli id o tutti gli stati del record.

Nel percorso ordinario il test fornisce risultati alle API1594E4/1593AC:identificativi **01E00003,01E00005** per i controlli osservati,e **01E00004 con argomento5** per l'attesa del profilo selezionato. Lo statoMMIO bit0 è predisposto1. La mappatura fra questi esiti e il puntatore è eseguita dal selettore originale;non è un puntatore restituito direttamente dal probe. Non si deduce ancora un protocollo completo di arbitraggio o prenotazione dalla sola disponibilità simulata.

Il gruppo integrato sceglie512CC8 con quel profilo per entrambi i selettori SD0/800. Le altre due strutture sono provate nel gruppo isolato,non dentro l'intero reader asincrono.

## Pubblicazione e controlli del wrapper2801F0

| Campo dell'oggetto scelto | Contenuto originale verificato |
|---|---|
| +0 | 000F4240,significato non assegnato qui |
| +4 | id202/203 |
| +8 | terzo argomento,total |
| +0C | secondo argomento,step |
| +10..+23 | invariatiA5 nel test di acquisizione isolato |

Il wrapper pubblica poi il puntatore nella cella di uscita del chiamante e azzera il byte36C19B. La struttura non è una copia sullo stack:lo stack contiene la sua associazione tramite handle. Il byte36C19B+1 è un'altra decisione del selettore;il profilo ordinario qui lo pone0.

Le verifiche degli argomenti vengono eseguite prima della selezione:

| Contratto provato | Risultato |
|---|---|
| cella di uscita nulla | 01E02400 |
| porta con due bit bassi nonzero | 01E02410 |
| step1023 per id202 | 01E02410 |
| step1024,total1025 non multiplo | 01E02411 |
| step80000080,total uguale | 01E02413 |
| step80000000,total uguale | accettato |
| step80000080,totalFFFFFFFF | accettato |
| id7FF fuori dalle famiglie selezionate | 01E03420 |

La verifica di allineamento dello step è specifica della famiglia:id202/203 richiedono i7bit bassi nulli;alcune altre famiglie nel codice applicano un controllo diverso e non sono generalizzate da questi test. Il resto della divisione viene calcolato dal corpo originale335B34. **TotalFFFFFFFF salta sia quel controllo sia il limite superiore dello step**. Sono prove di contratto del descrittore:nessun buffer di2GiB viene allocato o trasferito.

Se il selettore restituisce l'errore query o wait iniettato,la cella pubblica rimaneCAFEBABE,il valore precedente impostato dal test. Il selettore aveva già scritto il puntatore predefinito nella propria cella interna,ma2801F0 non lo pubblica dopo un esito nonzero. Cella interna e cella del chiamante non vanno confuse.

## Rilascio: handle consumato anche con errore

2812B8 è un branch originale a281158. La routine legge il puntatore dalla cella ricevuta,esegue i ramiMMIO per l'oggetto fisso,chiama280FE4 con l'id,esce dalla sezione critica e passa a281064. I rami provati chiamano anche267BAC/267BB4/267BBC:questi hook restano fixture e il loro esitoE09999 non diventa l'esito finale del percorso osservato.

281064 porta il campo identificativo **oggetto+4 a0** e modifica il registro modo della tabella sopra,forzando i bit4/5/6 con `(valore & ~70) |70`. Nel profilo ordinario chiama1594A4 con il servizio03/04/05 associato;nel profilo configurato corrispondente salta quel post. Infine281158 azzera la cella handle del chiamante nel delay slot2812B4.

Il caso post-fallito restituisce **E07782**,ma sia oggetto+4 sia handle sono già0. Questa è esecuzione dei corpi originali,con l'errore iniettato al servizio inferiore;non una scelta di consumo compiuta dalla fixture release. Gli altri tre campi pubblicati restano invariati. Il chiamante perde l'associazione anche quando l'operazione restituisce nonzero.

**Correzione di confine rispetto al gruppo precedente:**la fixture281158 poteva conservare l'handle in caso di errore per sondare il comportamento del chiamante. Non rappresentava una conclusione sul corpo release reale. Nei nuovi casi normali e post-fallito il rilascio originale consuma invece la cella. Nessuna di queste condizioni prova da sola l'arresto fisico del motore o l'ultimo uso del buffer.

## Oggetto originale dentro25A83C

I21scenari del chiamante sono ripetuti eseguendo2801F0/27FCD4/281158/281064. Il record512CC8 riceve000F4240,id202o203,total1024,step1024. Sono asseriti i campi finali,lo stack e il livello critico.

Errori di registrazione callback,abilitazione o clear evento dopo acquisizione lasciano **il campo+4 ancora202/203**,l'handle sullo stack e il registro mascheraDFEF. Nessuna chiamata release viene attraversata. Si tratta di un record software non ripulito dal chiamante;il trasferimento non è ancora stato avviato in questi casi. Non è dimostrato un leak globale o un motore fisico in esecuzione.

Nel ramo avvio fallito,anche un errore del post durante il rilascio lascia handle0 e campo+4=0,mentre25A83C mantiene come risultato l'errore primario dell'avvio. Nel ramo di completamento,lo stesso errore di post viene propagato e il chiamante esegue due unregister,ora con handle già consumato. Un errore dell'unregister dopo rilascio riuscito resta ignorato.

Restano riprodotti30controlli stagnanti,41attese con cambio di progresso dopo10e lo stop deliberato al64°ingresso di attesa con63query crescenti. In quest'ultimo caso il campo+4 è nonzero perché l'operazione è ancora dentro il suo ciclo;non è un cleanup fallito dopo ritorno. Anche con gli oggetti originali il buffer1024rimane31:avvio e trasferimento sono ancora simulati.

## Prossimo passo e confine residuo

**28080C avvio e266E9C avanzamento** sono il prossimo confine:programmazione dei contatori/indirizzi,memorizzazione callback,produttore della notifica e reale relazione fra ultimo uso del buffer e281158. Poi occorre raccordare registrazione/eventi originali e selezione delle risorse con sincronizzazione effettiva.

Restano fixture:1594E4/1593AC/1594A4,hook di arresto,28080C/266E9C,eventi e registrazione callback del caller;3342A8 prodotto modellato. Nessun DMA/cache,interrupt/scheduler o trasferimento fisico verificato,nessuna persistenza o recupero. Nessun nuovo collegamento del percorso asincrono al filesystem o al dumper RAM. Originali,dump,GNU,C AkeruOS e BIN invariati;circa10% funzionale invariato,**NON_INSTALLARE**,goal aperto.

## Continuazione — avvio receive e notifica originali

[S33_Dumper_RAM_SD_Avvio_Receive_Callback_e_Contatore_Originali.md](S33_Dumper_RAM_SD_Avvio_Receive_Callback_e_Contatore_Originali.md):33casi28080C/programmazione/MMIOdispatcher/callback e266E9C. Slotread36B358/35C/360 ecallbackADBC/ADC4→E00005/40o40000,distinti dal percorso write storico. Il bytefine del servizio avvio è calcolato prima della callback;getterprogress halfword×128nonvalidaownership. Evento158CBC ancora recorder e ingresso dispatcher esplicito; nessuntrasferimento fisico. Prossimo raccordare25A83C/oggetti/start/progress/callback/release e servizi evento originali. NON_INSTALLARE.

## Continuazione — catena con eventi RTOS originali

[S33_Dumper_RAM_SD_Catena_Asincrona_Eventi_RTOS_Originali.md](S33_Dumper_RAM_SD_Catena_Asincrona_Eventi_RTOS_Originali.md):13scenari25A83C/oggetti/start/dispatcher/callback/SET/WAIT/query/CLEAR/release,10ritorni+3waitaccodati osservati prima2313AC. Eventoeffettivo373228,tabellastaticabase372A48;auto-clear1spiega querysenza completion dopowait riuscito. EndByte1puòcoesisterecon task1069ancora inwait. Progressgetter nonraggiunto daquestiprofili:prossimo deadline/scheduler/timeout e callbackstatus reali;notificaCABIinnestata,nonIRQfisico. NON_INSTALLARE.

## Continuazione — prenotazione effettiva dei token

[34casi successivi](S33_Dumper_RAM_SD_Arbitraggio_Risorse_e_Stop_Software_Originali.md) eseguono15933C/1594E4/1593AC/1594A4 e gli helper267BAC/BB4/BBC. Correzione:“query”1594E4 è try-acquire con decremento del token e uscita byte,non controllo readonly. Trehandle viviCC8/D10/CEC conservano token distinti;releaseinverso ripristina1. I rami configuredfixed saltano try/post. Gli helperstop azzerano soltanto flagsoftware;nessuna garanzia elettrica nuova. Le vecchie fixture mantengono il proprio confine storico.
