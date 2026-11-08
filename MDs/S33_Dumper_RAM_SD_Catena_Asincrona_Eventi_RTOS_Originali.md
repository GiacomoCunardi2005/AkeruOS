# S33 — catena asincrona con eventi RTOS originali

23 ottobre 2026, R0/R1/R4. Continuazione di [avvio,callback e contatore](S33_Dumper_RAM_SD_Avvio_Receive_Callback_e_Contatore_Originali.md). La stessa esecuzione attraversa ora **25A83C → acquisizione → avvio → dispatcher/callback → SET → WAIT → query → CLEAR → rilascio**. SET,WAIT,query eCLEAR sono corpi originali:il risultato del lettore dipende dal contenuto dell'evento,non da un codice preconfezionato al confine della API evento.

Il contatore266E9C non viene raggiunto nei profili pronti o accodati qui usati:resta coperto separatamente dai33casi precedenti. La scadenza dell'attesa e il suo ritorno per timeout non sono ancora eseguiti.

## Prove e riproduzione

[13 scenari](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Async_Events/20261023T134341Z/verified_evidence.json), [traccia](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Async_Events/20261023T134341Z/trace.txt), [GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Async_Events/20261023T134341Z/gnu_verified.txt):**10ritorni e3osservazioni d'attesa interrotte**,108finestre GNU,19istruzioni chiave. Snapshot/hash del probe,runner,helper e16payload,comando e log conservati.

```sh
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_async_events.py
```

Sorgenti:[probe](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDReadAsyncEvents.java),[runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_read_async_events.py). Nessun helper condiviso precedente è modificato in questo gruppo;le prove precedenti mantengono i propri confini e i loro hash.

## Record evento originale e stato predisposto

Il resolver158C8C carica dal pool158E48 **la base diretta372A48**,non una cella contenente un altro puntatore alla tabella. Nei payload originali sono verificati85record di38hexbyte con magic45564E4C e identificativo nonzero;la terminazione è a373CE0. **E00005 è il record36,a373228**,con flag iniziali2.

Il profilo attiva soltanto quel record impostando il gate bit31 a+8,predispone una lista waiter vuota e sceglie il modo interno0oppure1. Non esegue qui la creazione dell'evento al boot. Gli indirizzi relativi usati nel gruppo sono:

| Campo del record373228 | Stato/uso |
|---|---|
| +0 | magic45564E4C |
| +4 | gruppoE00005 |
| +8 | gate bit31,flag bassi2 |
| +14/+18 | testa/coda lista waiter;inizialmente puntano a+14 |
| +1C halfword | numero waiter |
| +24 | parola dei bit evento |
| +28 | modo interno,bit0 di cancellazione automatica nel wait provato |
| +2C/+30/+34 | campi aggiornati dal wrapper wait,non buffer dati |

Le API superiori passano **record+C** alle primitive inferiori:perciò il campo bit visto da23C758/23C8AC aoggetto+18 èrecord+24. Il profilo kernel contiene un task corrente,lo stesso task come primo ready,tracehook disabilitato e nessun altro task da selezionare. È uno stato di laboratorio dichiarato,non un boot Nikon ricostruito.

## Catena effettivamente eseguita

L'acquisizione2801F0/27FCD4 sceglie512CC8 e pubblica id202o203,total1024,step1024. Il lettore registra/abilita il callback di stato tramite le API ancora simulate,poi il **CLEAR originale158CE0→23C8AC** rimuove i bit vecchi della maschera1C0o1C0000. Il test aveva predisposto quei bit più un bit estraneo1:prima dell'attesa deve restare esattamente1.

28080C e il programmatore originale configurano il buffer e salvano25ADBCo25ADC4 nello slot36B358. All'ingresso di158D04 il test verifica residuo0e bytefine1,poi innesta il dispatcher267F20 come chiamataCABI esplicita. Il dispatcher usa il bit7 diFEE0038/0034,legge lo slot e invoca la callback originale. **158CBC→23C758 esegue realmente l'OR della maschera40o40000 sul campo evento**.

Il ritorno dall'innesto controlla stack,registri callee r13..r25,gp e fp;il test ripristina argomenti volatili e blink per riprendere158D04. Questa è una chiamata controllata al confine della API,non una consegna interrupt con contestoCPU/status32 o registrazione dei vettori dimostrati. Le altre cause della coda dispatcher restano mascherate conFE1000C=7;FE10008 non riceve campioni.

Ora158D04→23C938→2C9994 verifica i bit già pubblicati e ritorna attraverso il percorso pronto senza cambio di task. **158E28 legge veramente il campo+24 nella cella del caller**. Il successivoCLEAR originale rimuove la maschera di completamento,lasciando il bit estraneo1. Infine281158/281064 azzerano id ehandle e il chiamante ripristina la propria maschera del controller.

## Esiti normali ed errori del confine residuo

| Scenario | Risultato osservato |
|---|---|
| completamento,selettore0/800 | callback,SET,WAIT,query,CLEAR e rilascio;risultato0 |
| post inferiore del rilascio fallito | E07776,handle e id già0,due unregister |
| unregister inferiore fallito | risultato0 conservato |
| registrazione/enable callback fallita | E07771/E07772,oggetto id202ancora pubblicato,nessuna release |
| acquisizione inferiore fallita | E07770,nessun oggetto pubblicato |
| evento con gate inattivo | errore originale200304duranteCLEAR dopo acquisizione;uscita comune saltata |
| magic del record evento non valido | errore originale200307duranteCLEAR;stesso confine di cleanup |

E077xx sono codici distinti iniettati nelle API residue,non errori hardware attribuiti a Nikon. I due errori200304/200307 provengono invece dal resolver originale. Le guardie di readiness dell'evento possono dunque interrompere il caller dopo che l'oggetto è già acquisito;non dimostrano un leak globale o un motore fisico avviato.

## Cancellazione automatica: query senza il bit non implica mancata notifica

Con modo interno0,WAIT conserva il bit e la query restituisce1|40(per il selettore0). Il chiamante lo cancella esplicitamente.

Con **modo1** il corpo originale2C9994 rimuove il bit durante il wait riuscito. La query restituisce soltanto1,ma il lettore continua fino al rilascio e ritorna0. Il ramo già sondato con una query sintetica senza bit di completamento ha quindi un percorso concreto nei servizi originali **sotto questa configurazione dell'evento**:non serve ipotizzare una race.

Non è verificato che la creazione dell'eventoSD al boot scelga questo modo. Il test mantiene separati configurazione possibile del servizio,configurazione runtime Nikon e prova elettrica.

## Attesa accodata con bytefine1

Tre profili non producono il bit richiesto:nessun innesto del dispatcher;causa mascherata;stato assente. In tutti il CLEAR iniziale ha rimosso i bit vecchi e l'evento contiene solo1,estraneo alla maschera attesa.

Il WAIT originale inserisce allora un waiter nel ring,senza restituire al lettore. Sono asseriti:

- count del record+1C=1,testa/coda+14/+18=task+188;
- task+8=1069,task+30=testa del ring,task+196=maschera richiesta;
- handle512CC8 e id202ancora associati,nessuna release/unregister;
- livello critico1al confine osservato,maschera controllerDFEF;
- residuo oggetto0e bytefine1già presenti prima del wait.

Il probe si ferma **prima di2313AC**,il servizio che registrerebbe l'attesa temporizzata nello scheduler. Non è un ritorno0,un timeout concluso,un leak dopo un ritorno o una prova di deadlock. Gli stati del task sono quelli raggiunti prima di proseguire con la registrazione della scadenza.

Questa esecuzione conferma direttamente che il bytefine1non autorizza a trattare il buffer come completato:il task può ancora essere dentro il wait originale.

## Preparazione della scadenza e limiti temporali

231330,23C904,2C993C e26983C preparano il descrittore della scadenza. Il profilo pone la base temporale34FAD4 a0e i due parametri kernel+200/+204 a1000. Due prodotti336364 e il prodotto3342A8 del caller restano modelli matematici dichiarati,per i limitiDSP del decoder;335D34e il resto della preparazione sono eseguiti.

Nei tre casi accodati viene verificata la tripla **100/0/0** all'ingresso di2313AC. È il risultato sotto quei parametri sintetici;non assegna una frequenza fisica al clock né dimostra che l'argomento100corrisponda a100millisecondi sulla macchina.

## Prossimo passo

Proseguire con2313AC,registrazione della scadenza,ritorno dell'attesa e risveglio/timeout. Solo dopo un ritorno nonzero del wait si potrà collegare in questa stessa catena il getter266E9C e il conteggio dei30controlli senza progresso. Separatamente restano registrazione/abilitazione del callback di stato266768/26671C e gli errori reali25AD3C/25AD78.

Continuazioni successive:[scadenza e risveglio originali](S33_Dumper_RAM_SD_Scadenza_Risveglio_e_Progress_Originali.md) eseguono2313AC/28179C,tick2F70C4,WAITripreso e266E9C;[28casi callback di stato](S33_Dumper_RAM_SD_Callback_Stato_Errori_e_Inizializzazione.md) eseguonoAPIstatus/router040E/walker/callbackerrori e158C30 sulrecordSDflags2→auto-clear0. Questi passi sono superati nei nuovi profili;rimangono frameCPU,arbitraggio/post/stop efilesystem/binding. Nessuna nuova prova hardware.

Restano simulati arbitraggio/post delle risorse,hook di arresto e API callback di stato,prodottiDSP e contesto iniziale. Nessun trasferimento fisico:il buffer1024byte rimane31con guardieA5. Nessun filesystem asincrono,binding del dumper,consegnaIRQ fisica,cache/DMA,persistenza o recupero certificati. Originali,dump,GNU,C AkeruOS e BIN invariati;circa10% funzionale invariato,**NON_INSTALLARE**,goal aperto.
