# Accesso alla NAND dal PC: inizializzazione, buffer e nucleo di lettura

**Continuazione corrente21ottobre:** [S33_NAND_PC_Parser_Buffer_Privato_e_Contenitore_Offline.md](S33_NAND_PC_Parser_Buffer_Privato_e_Contenitore_Offline.md). Parser e bufferprivato integrati, contenitoreoffline NON INSTALLARE; Nikondevice033 nuovamenteMSDC22MiB alle08:55UTC. Le condizioni di assenza e i limiti del prototipo descritti sotto sono checkpoint precedenti.

**Continuazione21ottobre:** [transazioneBOT e adattatore](S33_USB_BulkOnly_Transazione_RAW_e_Adattatore_Offline.md):17casi completi con nucleoC eseguitoARC700; corretta interpretazione della listaopcode, nessuna modifica necessaria perFF/IN. AdattatoreRAW testato nativo eARC con binding simulati. Nuova raccolta08:20UTC: nessunaNikon rilevata, distinta dalla precedente confermaMSDC.

21 ottobre 2026 — R0/R3/R4. L’obiettivo attivo richiesto dall’utente termina quando è verificato l’accesso dal PC alle altre regioni NAND oppure è pronto un aggiornamento installabile sulla S33. **Questo checkpoint non conclude l’obiettivo:** MSDC funziona, ma il disco esposto resta limitato a22MiB; il nuovo codice è ancora un nucleo offline senza collegamento al firmware.

## MSDC verificato nuovamente sulla fotocamera

Su richiesta esplicita dell’utente è stata verificata la connessione corrente. [Dieci campioni](../Risultati/Hardware/MSDC_Default/20261020T225849Z/observation.json), esito `OBSERVED_MSDC_WITH_NIKON_BLOCK_DEVICE`, nessun errore:

- Nikon04b0:035d, product **COOLPIX S33-MSDC**, bus3/device30, driverusb-storage, interfaccia08/06/50.
- sda discende dal dispositivo Nikon:45.056settori512,23.068.672byte=22MiB.
- sda1 montata a `/run/media/jack/disk`; [findmnt](../Risultati/Hardware/MSDC_Default/20261020T225849Z/mounted_volume_verification.json) conferma filesystem **vfat**.

La raccolta usa lo [script esistente](../Python_Trace_Scripts/s33_observe_msdc_usb_enumeration.py). Sono state lette soltanto enumerazione, descrittori cached, sysfs e metadati del sistema operativo: nessun settore grezzo, sessionePTP, comando vendor o scrittura dell’agente. Il sistema operativo aveva già montato il volume in lettura/scrittura; l’agente non ha eseguito quel mount e non ne ha cambiato le opzioni.

**MSDC attivo è ora osservato direttamente.** L’utente conferma che l’aggiornamento MSDC è installato; il suo hash effettivo in flash non è stato riletto. L’assenza della SD non è dimostrata dai soli descrittori. Questa raccolta device30 è distinta dalla precedente device29 e dai campioni con capacitàzero.

## Il ramo MSDC viene selezionato dalla classe dell’interfaccia

Le [15 finestre statiche](../Risultati/USB_SCSI/Accesso_NAND_PC/init_verified_gnu.txt) e il [manifest](../Risultati/USB_SCSI/Accesso_NAND_PC/init_verified_static.json) chiudono il collegamento rimasto aperto nel [rapporto SCSI](S33_USB_SCSI_Callback_Dispatcher_e_Capacita_Storage.md):

```text
139258 → 81DBA4 → 190C3C: descrittore configurazione a3680A4
13925C → 81DBB8 → 190C24: initializer1392CC a3680CC
191314..191322: selezione configurazione1, byte descrittore+0E
191328..191330: callback3680CC, argomento=classe interfaccia
MSDC3901B0+0E = 8 → 1392CC ramo diverso da6
PTP3900F0+0E  = 6 → 1392CC ramo6
```

La chiamata191330 non passa una costante6: l’argomento proviene dal descrittore. Nel percorsoMSDC,12A71C deve riuscire prima della registrazione INQUIRY139690 e del backend820D04. La [prova CPU](../Risultati/USB_SCSI/Accesso_NAND_PC/init_cpu_latest.json), riproducibile con [s33_verify_usb_init_route.py](../Python_Trace_Scripts/s33_verify_usb_init_route.py), supera4casi: successoMSDC, erroreproviderMSDC, erroreproviderPTP e callbacknulla. Esegue il registrar dei descrittori, quello dell’inizializzatore, estrazione della classe, chiamata indiretta e il ramo1392CC. Sono simulati12A71C e81DCA4; la prova non esegue l’intero SET_CONFIGURATION o il boot. Il primo ingresso di laboratorio saltava unmov necessario ed è conservato come tentativo fallito; il PASS riparte da191314.

Le callback storage+00/+0C sono entrambe16825C e+08/+14 entrambe168990; il predicato+18 è139998.81F5F8 può riordinare i record9A3478 portando il tipo2NAND nello slot0. Questo raccorda staticamente il nomeINQUIRY4MP-CARD con il fallbackNAND: il nome dipende dall’indice, il lettore dal tipo del record. L’osservazione hardware e la provaCPU restano evidenze distinte.

## Buffer Nikon esistente: ID1E,64KiB

Il template risorse a3766F4 contiene il record37709C, seiword:

```text
ID=1E, riferimento layout=4E, flag=0, base=0, dimensione=10000h, allineamento=4
```

Il riferimento4E descrive la relazione di layout col predecessore; non identifica da solo un proprietario esclusivo. Inizializzazione e allocazione costruiscono la base. PerMSDC l’inizializzatore richiedeID1E e registra la base in89AB7C+34, tramite81DC88→81F528. **Non è RAM nuova assegnata ad AkeruOS.**

La [prova delle risorse](../Risultati/USB_SCSI/Accesso_NAND_PC/resource_cpu_latest.json), [script](../Python_Trace_Scripts/s33_verify_usb_resource_lease.py), supera6casi CPU senza stub di funzioni Nikon: cinque query ed un cicloacquire→registrazioneUSB→query→release→secondorelease. Manager, tabella e record sono dichiarati come statoRAM di laboratorio; non sono un dump runtime.

Risultati operativi:

-12A748→1EF920 copia24byte del record anche quando il flag è0. Una query riuscita non concede un buffer in uso.
-12A71C→1EF7F8 imposta il flag e restituisce base/dimensione; controlla anche sovrapposizioni con altri record attivi.
-12A738→1EF8BC azzera il flag; il secondo rilascio ritorna01D00008.
-Manager non inizializzato, indice fuori intervallo e voceassente restituiscono01D00001/04/05 senza alterare la destinazione di prova.

Un futuro adattatore dovrà richiedere descrittorevalido, flag1, base coerente col campoUSB e dimensione sufficiente, quindi dimostrare durata e sincronizzazione del possesso. I64KiB del template non autorizzano da soli accessi concorrenti o l’uso dopo disconnessione.

## Nucleo RAW in sola lettura, ancora offline

Sono stati creati [header](../S33-sections/usb_nand_readonly/akrn_read.h), [implementazione](../S33-sections/usb_nand_readonly/akrn_read.c) e [test](../S33-sections/usb_nand_readonly/test_akrn_read.c). Il nucleo accetta soltanto una pagina RAW per richiesta, con geometria esplicita e lettore iniettato; non contiene API di scrittura o indirizzi MMIO.

Formato proposto, non presente nel firmware attuale:

```text
CDB16: FF 'A' 'K' 'R' 'N' 01 chip page block_BE16 zero[6]
Direzione CBW: esattamente80h/IN
Lunghezza: esattamente dati_pagina + spare_pagina
```

Valida magic/versione, lunghezzaCDB, riservati, coordinate, geometria con passi512dati/16spare, overflow, direzione, lunghezzaUSB e capacità del buffer. Input invalidi non chiamano il lettore. Errori del lettore sono conservati separatamente e lunghezza restituibile0 impedisce di presentare come completa una lettura parziale.

[Test e compilazione riproducibili](../Risultati/USB_SCSI/Accesso_NAND_PC/raw_core_20261021/run_checks.py), [manifest con hash e comandi](../Risultati/USB_SCSI/Accesso_NAND_PC/raw_core_20261021/manifest.json): test nativi con avvisi severi, ASan eUBSan superati; oggettoARC700 freestanding compilato,320byte.text,0data/bss. L’oggetto ARC non è ancora eseguito. Il lettore del test è una fixture: non legge la NAND. La geometria4/500/64 e2048+64 usata nei test non è una nuova misura fisica.

Questi file non sono un aggiornamento, un firmware collegato o un clientUSB operativo. Non è stato modificato il candidatoMSDC già installato dall’utente.

## Collegamenti necessari prima di un aggiornamento installabile

1. **Trasporto:** la rigaFF della tabellaSCSI9A33D4 punta attualmente a820B2C, semplice ritorno0. La precedente interpretazione del ramo820E26..4C come whitelistIN è corretta nel [rapporto successivo](S33_USB_BulkOnly_Transazione_RAW_e_Adattatore_Offline.md): controlla direzioni errate eFF/IN raggiunge già il dispatcher. Il puntatore della tabella è sostituito solo nella provaRAM; completare il collegamento al lettoreNikon e al buffer posseduto resta necessario. Servono collegamento ed esecuzioneCBW→handler→dati→CSW, con rifiuto delle direzioni e delle lunghezze errate.
2. **Lettore fisico:**25F428 è il servizio del dumpRAW e usa coordinatechip/page/block; il vecchio exporter1ED37C perde l’esito della singola lettura. Il nuovo adattatore dovrà conservare l’esito, riusare la sincronizzazioneNAND01B00001 e provare il layoutRAW, compresi i casi speciali del primo blocco. Il nucleoC non sostituisce questo contratto.
3. **Residenza e ABI:**320byte del solo nucleo superano i220byte della vecchia routineSD. La precedente zona sperimentale non viene automaticamente ampliata o dichiarata libera. Occorrono collocazione verificata, collegamento e conservazione dei registri/GP, senza modificareGNU.
4. **Regioni e limiti:**G+8 e l’ID NAND runtime non sono ancora misurati; una geometria ipotetica non autorizza letture oltre i confini dimostrati. I lettoriBoot,partizioniP1 eFAT hanno mapping diversi. Il [controllo PTP mirato](../Risultati/USB_SCSI/Accesso_NAND_PC/ptp_routes_20261021/risultato.txt) non ha trovato una catena già verificata host→offsetNAND→bufferUSB; non è un’esclusione di tutte le chiamate indirette.
5. **Installazione:**restano compatibilità, integrità del contenitore, comportamento all’avvio e recupero. Nessun nuovo BIN viene dichiarato pronto finché queste prove mancano.

Il passo successivo concreto è collegare il nucleo al lettoreNikon ed eseguire offline l’intera transazioneBulk-Only, verificando buffer, errori eCSW. L’accesso reale daPC oltre22MiB e l’aggiornamento installabile restano le condizioni di completamento, non sostituite dai test di questo checkpoint.
