# S33 — scadenza, risveglio e avanzamento originali nella catena SD

23 ottobre 2026, R0/R1/R4. Continuazione della [catena con eventi RTOS](S33_Dumper_RAM_SD_Catena_Asincrona_Eventi_RTOS_Originali.md). Eseguiti2313AC e28179C fino all'inserimento effettivo del task nella lista temporizzata. Poi SET originale oppure il tick2F70C4 rimuovono il task dalle liste e lo rendono pronto. Il lettore ritorna dal WAIT originale,raggiunge il vero266E9C e prosegue fino al completamento o all'errore dopo30controlli stagnanti.

**Confine dichiarato:**B2D50 è intercettato prima di salvare il frameCPU. Il test esegue a quel confine il dispatcher oppure i tick,e restituisce dalla funzione di cambio contesto soltanto dopo aver verificato che il codice originale abbia reso pronto il task. Non esegue il salvataggio/ripristino del contestoCPU,la selezione di un altro task o la consegna di un interrupt fisico.

## Prove

[8 scenari](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Async_Wake/20261023T135918Z/verified_evidence.json),[traccia](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Async_Wake/20261023T135918Z/trace.txt),[GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Async_Wake/20261023T135918Z/gnu_verified.txt):**7ritorni e1osservazione interrotta**,112finestre GNU,16istruzioni chiave. Il numero di scenari non misura il numero di scadenze:la matrice attraversa136timeout originali e136letture di avanzamento,oltre ai risvegli per evento. Correzione editoriale23ottobre:il precedente totale137 era una somma errata;1+1+30+41+63=136,con13600tick. Tracce e snapshot storici invariati.

```sh
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_async_wake.py
```

Sorgenti:[probe](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDReadAsyncWake.java),[runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_read_async_wake.py). Snapshot/hash dei sorgenti e16payload,log,comando e traccia conservati. Nessun probe condiviso precedente modificato.

## Inizializzazione originale dell'oggetto evento inferiore

Il gruppo esegue prima **23C674(recordSD+C,modo)**,con recordSD373228. Il costruttore inizializza il ring waiter,i contatori e il modo,registra l'oggetto nella lista globale kernel+46C/470 e incrementa il contatore halfwordkernel+474. Viene verificato il livello critico finale0.

Un campo ulteriore diventa rilevante dopo un'attesa accodata:**marker6C65766E aoggetto inferiore+14**,ossia **record+20**. Non è il magic superiore45564E4C del resolver. Il test verifica la scrittura originale del marker,non lo introduce come valore restituito da una fixture.

Il percorso di ritorno da un wait accodato controlla questo campo. Con un oggetto non inizializzato può selezionare1039,che non va confuso con il timeout valido. I gruppi precedenti che arrestavano l'esecuzione prima della registrazione della scadenza non avevano attraversato questo ritorno. Qui il costruttore originale fornisce lo stato inferiore necessario;il gate superiore del record evento rimane predisposto dal test,senza rivendicare il boot completo.

## Due liste e inserimento della scadenza

Il WAIT2C9994 inserisce il nodo **task+BC** nel ring evento a record+14e imposta stato1069(42Dhex).2313AC somma la scadenza relativa al tempo corrente tramite26983C e salva la tripla a task+5C/+60/+64.

28179C rimuove il nodo principale del task dalla lista pronta e lo inserisce nella lista temporizzata **kernel+4C/50**;incrementa count halfword **kernel+54** e aggiunge bit100allo stato,che nel profilo diventa52Dhex. Il nodo evento e il nodo temporizzato sono distinti e appartengono alle due liste contemporaneamente.

Al confine B2D50 sono asseriti ring temporizzato con un elemento,ring ready vuoto,un waiter evento,stato52D e livello critico2. La scadenza assoluta low vale tempo corrente+100,high0. La routine contiene l'ordinamento per scadenza;questa matrice ha un solo task temporizzato per volta e non verifica l'ordinamento fra più task.

## Risveglio per evento dopo l'accodamento

Nei casi queued-event,queued-event800equeued-auto,il test innesta267F20 al confine del cambio contesto. La callbackSD salvata nell'oggetto raggiunge il SET originale158CBC/23C758.

Il SET percorre il waiter,riconosce la maschera e:

- rimuove il nodo task+BC dall'evento e porta il count waiter a0;
- rileva il bit100 e rimuove anche il nodo temporizzato,decrementando kernel+54;
- azzera task+30,porta il task a stato2e lo reinserisce nel ring ready;
- pubblica i bit oppure li consuma secondo il modo automatico.

Solo dopo questi controlli il test effettua il ritorno astratto daB2D50. I corpi2313AC,2C9994e158D04 proseguono realmente. Il WAIT decide successo perché task+30è stato azzerato dal SET;il test non restituisce un codice di successo al posto del WAIT.

Entrambi i selettori0/800 e il modo auto-clear sono verificati,con query,CLEAR,rilascio dell'oggetto e ritorno finale0. Il bit estraneo1dell'evento resta conservato.

## Scadenza prodotta dal tick originale

Negli altri profili,il test chiama direttamente **2F70C4**. Ogni invocazione incrementa il tempo kernel+34/38e scorre la lista temporizzata. È il corpo software chiamato dal servizio TIMER0 storico;qui non sono eseguiti registri count0/control0,il vettoreCPU o una consegnaIRQ.

Quando la scadenza viene raggiunta,il tick originale rimuove il nodo dalla lista temporizzata. Poiché lo stato include il bit400dell'attesa evento,rimuove anche il nodo task+BC e decrementa il count dell'evento. Poi porta il task a stato2e lo reinserisce in ready.

**Il timeout conserva task+30nonzero**,a differenza del SET. Questo campo permette al WAIT ripreso di scegliere il risultato di scadenza. Il corpo inferiore produce1310,il wrapper originale lo mappa a **200305**. Il probe asserisce che i ritorni del WAIT siano0oppure200305;non ne sostituisce la traduzione.

Nel profilo con parametri temporali1000/1000,base iniziale0e scadenza relativa100,ogni scadenza avviene esattamente all'uguaglianza dopo100invocazioni del tick:lag osservato e asserito0. Non sono100millisecondi misurati né una frequenza hardware certificata.

## Lettore dopo il timeout: avanzamento originale e limite di stagnazione

Dopo200305,25A83C chiama davvero266E9C con512CC8. Il load originale leggeFEE04F4e scrive il campione moltiplicato per128. Il test fornisce soltanto la halfword del registro;non scrive direttamente il valore nella cella avanzamento del chiamante.

| Scenario | Wait/timeouts | Avanzamento originale | Tick invocati | Esito |
|---|---|---|---:|---|
| evento accodato0/800/auto | 1wait,0timeout | non letto | 0 | 0 |
| un timeout,poi evento | 2wait,1timeout | campione0→0 | 100 | 0 |
| un timeout con progresso,poi evento | 2wait,1timeout | campione1→128 | 100 | 0 |
| nessun progresso | 30wait/30timeout | 30letture0 | 3000 | E01520 |
| cambio dopo10controlli | 41wait/41timeout | campione1dall'11°controllo,poi invariato | 4100 | E01520 |
| progresso continuo | 63timeout completati,stop al64°ingressoWAIT | 63campioni crescenti | 6300 | nessun ritorno |

Nel caso con avanzamento1,all'ingresso del secondo wait sono controllati riferimento128e contatore stagnazione0;con avanzamento0rimangono riferimento0e contatore1. Il collegamento fra timeout vero,load MMIO e rami del chiamante è dunque eseguito nella stessa sessione.

I due errori finali E01520 invocano il rilascio originale,azzzerano id/handle e ripristinano la maschera del controller. Il caso continuo si ferma prima di iniziare il64°WAIT,con task già pronto da precedente timeout,nessun nodo nelle due liste e livello critico0. L'oggetto e la maschera controller restano associati all'operazione;non è un cleanup normale né un task attualmente accodato.

**Task+30può restare nonzero anche dopo il ritorno per timeout**,con task pronto e liste vuote. Non usarlo da solo come predicato “task attualmente in wait”:servono stato e membership delle liste. Nei casi terminati poi da un evento,il SET lo azzera.

## Confini del modello e prossimo passo

Il test sostituisce il ritorno del cambio contestoB2D50dopo aver osservato il risveglio originale. Verifica stack,registri callee,gp/fp attorno alle chiamateCABI e ripristina gli argomenti volatili,ma **non esegue il frameCPU,lo scheduler idle o l'elezione di un altro task**. L'ordine delle notifiche e l'invocazione dei tick sono scelti dal test.

Restano fixture arbitraggio/post della risorsa,hook di arresto,registrazione/enable/unregister dei callback di stato e prodotti3342A8/336364. Il costruttore inferiore,SET/WAIT/query/CLEAR,registrazione della scadenza,tick,contatore e rilascio sono invece originali entro i profili descritti. Tutti i buffer restano31con guardieA5:nessuna copia fisica è emulata da questa notifica.

Prossimo:eseguire e verificare il frame di cambio contestoCPU,oppure chiudere il ramo dei callback di stato266768/26671C/2667B0e25AD3C/25AD78 per gli errori reali del controller. Restano inoltre arbitraggio concorrente,più deadline,rollover temporale,percorso asincrono nel filesystem e binding del dumper. Nessun hardware o nuovo BIN;originali,dump,GNU eC AkeruOS invariati,circa10% funzionale invariato,**NON_INSTALLARE**,goal aperto.

## Continuazione — callback di stato e inizializzatore superiore

[28 casi successivi](S33_Dumper_RAM_SD_Callback_Stato_Errori_e_Inizializzazione.md) eseguono266768/26671C/2667B0,router040E,walker2640E0 e callback25AD3C/25AD78 fino al ritorno del lettore. Il ramo errori non è più fixture nel nuovo gruppo. Eseguito anche158C30 sul recordSD originale:flags2→auto-clear0 e gate80000002. La precedente preparazione manuale del gate è superata in quel gruppo;il boot completo resta aperto. Forzando flags3 l'errore viene consumato prima della query e il lettore ritorna0. Prossimo arbitraggio/post/stop e raccordo filesystem;nessunhardware/BIN,NON_INSTALLARE.
