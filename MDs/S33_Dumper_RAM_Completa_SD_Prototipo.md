# Dumper RAM completa sulla SD: prototipo cooperante

22 ottobre 2026 — R0/R3/R4. Richiesta utente: un task che esporti la RAM sulla SD. **Precisazione accolta durante il lavoro: l'obiettivo è tutta la RAM, non solo strutture iris/timer.** È stato implementato e verificato il motore di esportazione, senza installarlo o collegarlo a indirizzi Nikon non validati.

## Risultato concreto

- [C freestanding](../AkeruOS/ram_dump.c), [contratto dell'adapter](../AkeruOS/ram_dump.h), [test C](../AkeruOS/tests/ram_dump_test.c).
- [Verificatore riproducibile](../Python_Trace_Scripts/s33_verify_ram_dumper.py), [lettore dei file](../Python_Trace_Scripts/s33_read_ram_dump.py).
- [Evidenza valida](../Risultati/Runtime_Kernel/RAM_Dumper/20261022T082454Z_3a51a23c/verified_evidence.json): **28 casi host PASS**, streaming completo di **128 MiB sintetici** in blocchi da 4096 byte, **20 file incompleti/danneggiati respinti**, compilazione ARC700 senza simboli esterni irrisolti né rilocazioni SDA. Host compilato con AddressSanitizer e UndefinedBehaviorSanitizer.
- Oggetto ARC `AkeruOS/build/ram_dump.o`: 3164 byte text/rodata, nessun dato/BSS globale mutabile. Buffer da 4096 byte e configurazione appartengono all'oggetto fornito dal chiamante; non sono allocati su una regione Nikon presunta libera.

La prova da 128 MiB genera dati RAM sintetici e conta l'output senza conservarlo integralmente: controlla letture, avanzamento, byte esportati e uso del buffer. **Non legge 128 MiB dalla fotocamera, non misura RAM fisica e non verifica la velocità della SD.** Il file `fixture.dmp` nelle evidenze è anch'esso sintetico e riguarda l'opzione diagnostica ridotta, non un dump hardware.

Riproduzione dalla radice:

```bash
make -C AkeruOS ram-dump-verify
make -C AkeruOS build/ram_dump.o
python3 Python_Trace_Scripts/s33_read_ram_dump.py percorso/AKR00000.DMP
```

## Comportamento scelto

Il futuro adapter controlla la presenza di **`B:AKERUDMP.ON`**, sul volume SD `B:` individuato nei rapporti del filesystem. Dopo un'attesa cooperante di 5 secondi il task acquisisce **una volta l'intera mappa RAM fornita dalla piattaforma**, in streaming in un file nuovo `B:AKR00000.DMP`. La prima versione fa una sola acquisizione completa. Le ripetizioni sono configurabili, con una pausa dopo il completamento del file precedente: non si promette una cadenza di 5 secondi per un dump che richieda più tempo.

Il task cede l'esecuzione anche fra i blocchi tramite l'adapter RTOS. Il file di attivazione viene ricontrollato prima di ogni lettura; se manca, il task termina, tentando la chiusura del file parziale. Se il task è già terminato, aggiungere il file non lo riavvia: occorre un nuovo avvio del task. Nessuna operazione viene eseguita in una callback di interrupt TIMER1.

Ogni file viene creato **esclusivamente**, senza sovrascrivere nomi già presenti. Collisioni fanno avanzare il numero, con un massimo di 32 tentativi per cattura; il numero non torna a zero dopo 99999. Scritture corte sono completate, errori/zero write/close fallito fermano la sessione. Nessun file viene cancellato. Un errore non fa ricominciare all'infinito il ciclo.

## Copertura della RAM e mappa ancora da verificare

`akeru_ram_dump_defaults()` prepara una singola acquisizione ma **non sceglie intervalli fisici**. La piattaforma deve chiamare `akeru_ram_dump_use_full_map()` con tutti i banchi RAM verificati, ordinati e senza sovrapposizioni. Senza mappa il modulo restituisce errore di configurazione e non apre file. Una piccola lista di strutture resta disponibile soltanto con `akeru_ram_dump_use_selected_regions()`, che marca il file come cattura parziale.

Il motore non limita più il dump a 4 MiB. Il limite di quantità è 512 MiB per controllare l'aritmetica; **non è una stima della RAM Nikon**. La versione corrente ammette soltanto intervalli sotto `0x0FE00000`, escludendo la fascia MMIO nota, e non costituisce una prova che tutti gli indirizzi inferiori siano leggibili. Eventuali banchi o alias ulteriori richiederanno un'estensione esplicita e motivata.

La [configurazione DDR](S33_BootNAND_DDR_ID_Dimensione_e_Checksum.md) indica 256 MiB come limite software. Il test BootNAND è però sparso, salta `0x08000000` e termina dopo `0x0F700000`. I [128 MiB del simulatore](S33_Emulazione_RAM_128_MiB.md) sono una scelta di laboratorio; le [finestre alte](S33_Limiti_Indirizzi_e_Stima_RAM.md) hanno alias/natura fisica ancora aperti. Non sono state trasformate queste osservazioni in un loop hardware da zero a 256 MiB. La completezza fisica richiede questa verifica prima dell'acquisizione reale.

## Formato e coerenza

Formato little-endian `AKRDMP1`: header 32 byte con versione, sequenza, numero regioni, byte totali, tempo iniziale e flags. Ogni regione conserva base, lunghezza, tempo iniziale, dati, tempo finale e CRC32 su descrittore/dati/tempo finale. Un footer `AKRDONE` conserva numero regioni completate e tempo finale. Il lettore rifiuta troncamenti, checksum errati, range MMIO, sovrapposizioni, totale incoerente e byte aggiunti.

Flag 0 indica acquisizione sequenziale/non atomica; flag 1 indica tutti i banchi **dichiarati dalla piattaforma**, non una certificazione della mappa fisica. I timestamp possono attraversare il wrap a 32 bit. I CRC proteggono i record delle regioni; il formato non è una firma crittografica o una prova di persistenza SD.

Un dump completo in streaming copre gli indirizzi, ma la macchina continua a cambiare durante la lettura. Il writer e il filesystem modificano a loro volta la RAM. Non è uno snapshot simultaneo né include automaticamente PC/SP/GP degli altri task. Un close fallito può lasciare un file completo dal punto di vista del formato: il task conserva errore e non lo conta come successo; il parser da solo non può certificare l'esito fisico del close.

## Integrazione Nikon ancora aperta

Il codice contiene un adapter esplicito per presenza del file, attesa RTOS, clock, copia RAM, creazione esclusiva, scrittura e chiusura. **Nessun puntatore è stato associato automaticamente a funzioni Nikon e il loop `firmware_main` esistente non è stato trasformato in un callback bloccante.** L'oggetto compilato resta ET_REL, non un firmware installabile.

Le piste concrete sono già disponibili: [template task e creazione](S33_Avvio_Runtime_e_Creazione_Task.md), [stack/gp/lifetime](S33_Task_Stack_Contesto_e_GP.md), [attesa cooperante](S33_Attesa_Task_Switch_e_Risveglio.md), [apertura e volume B:](S33_Apertura_File_e_Volumi.md), [scrittura/close filesystem](S33_Callback_Filesystem_e_Controlli_Close.md). Restano da fissare firme, restituzioni, modalità di creazione senza overwrite, servizio di attesa finita, memoria del nuovo task e hook d'avvio. Non usare `0x23C620` come sleep RTOS senza verificarne il comportamento e non presumere che `w+` sia un'apertura esclusiva.

Prossimo passo: validare il binding di un'operazione file nuova sulla SD e del task, parallelamente alla mappa RAM completa. Solo dopo si può preparare un aggancio concreto all'immagine compatibile e verificare caricamento/recupero. Nessuna scrittura su fotocamera, flash o SD eseguita in questa sessione; GNU rimane in sola lettura; circa 10% funzionale invariato, NON_INSTALLARE.

## Avanzamento del23ottobre: eventi e callback di errore SD

La [catena di risveglio](S33_Dumper_RAM_SD_Scadenza_Risveglio_e_Progress_Originali.md) esegue ora le scadenze e il tick fino al ritorno del WAIT e al contatore originale. Il [gruppo callback di stato](S33_Dumper_RAM_SD_Callback_Stato_Errori_e_Inizializzazione.md) aggiunge28casi con registrazione,router040E,walker,errore e rilascio originali;158C30 dai flagSD2 imposta auto-clear0. Nessun binding hardware è stato aggiunto alC del dumper. La regressione del motore è stata [rieseguita](../Risultati/Runtime_Kernel/RAM_Dumper/20261023T141447Z_569c2ace/verified_evidence.json):28casi host,20rifiuti parser e128MiB sintetici. Restano scrittura/creazione/close,mappa fisica e task compatibile prima dell'acquisizione reale;NON_INSTALLARE.

## Avanzamento successivo: prenotazione e percorsi write

[34casi risorse](S33_Dumper_RAM_SD_Arbitraggio_Risorse_e_Stop_Software_Originali.md) e[36casi write](S33_Dumper_RAM_SD_Scrittura_Asincrona_e_PIO_Originali.md) eseguono ora anche prenotazione/post originali e3040DC fino a callback,timeout,errore e rilascio. I fallbackPIO copiano i byte del buffer nella portaMMIO simulata tramite istruzioni originali,con catture confrontate. IlC del dumper resta invariato:non è stata associata una mappaRAM presunta o collegato un adapter hardware. Il dump completo rimane l'obiettivo;servono ancora write/creazione/close filesystem,mappa fisica e task/hookcompatibile. NON_INSTALLARE.

## Continuazione — motori write e rilettura,23ottobre2026

[Nuovo collegamento](S33_Dumper_RAM_SD_Motori_Write_PMSD_e_Rilettura.md):24casi eseguono PMSD/DEVSD e motori25B9C0/25BB5C con comandi/gate/PIO originali;13riletture/11264byte,15catture12800byte,regressione36PASS. Errori dopo256byte pertre tentativi diventano raw/PMcount0;flag49=1 conserva falso successo senzaemissione. La scheda è una finestraRAM,nonFAT;async senza copiaDMA dichiarata. Il callback filesystem1F4958/21A4B8 ecluster2A0D70 restano da integrare,poi creazione/sync/close/riapertura. Stime perarea nelrapporto,obiettivoattivo,Cinvariato,NON_INSTALLARE.

## Continuazione — fileFAT e correzione write,23ottobre2026

[13nuovi scenari](S33_Dumper_RAM_SD_File_FAT_Creazione_Scrittura_Close_e_Riapertura.md) eseguono creazione n/collisione,allocazioneFAT,12DE3C→PMSD/DEVSD/controller,close e riapertura con contesto nuovo.4immagini positive superanofsck;il negativo frammentatoFF7 viene respinto. Stato0puòaccompagnarecount0 o1024/2048 ecountpienopuònasconderefileError1A00006. HardwareDMA esplicitamente modellata,81timeout/8100tick,regressione24PASS. Ilprimo confine superiore èora1F21F8/12DBFC/12D604 conregistro/slot/ownership,poibackend7/modi eadapter. C eGNU invariati,mappafisica/task/hookancoranecessari,obiettivoattivo,NON_INSTALLARE.

## Continuazione — registro, close superiore e modi,23ottobre2026

[17casi lifecycle](S33_Dumper_RAM_SD_Registro_Apertura_Close_e_Ownership_Integrati.md) eseguono ora anche registro/open generico/open eclose superiori. L’errore prima3015 conserva handle/slot/oggetto perretry;ready0consuma wrapper/slot/cella ma lascia oggettoFAT vivo. Non associare cella0 a cleanup completo. 4fsckpositivi e7negativiFF7attesi,regressione13PASS. [20casi modi](S33_Dumper_RAM_SD_Modi_Apertura_FAT_e_Gate_Backend7.md) verificano w/w+,n/n+,r/r+,x/x+ sulFAT;backend7 solo gatechiuso. Il nuovo confine è backend7 attivo e adapter con proprietà/guardia/sessione verificati;nessun bindinghardware,C/GNU/originali invariati,NON_INSTALLARE.
