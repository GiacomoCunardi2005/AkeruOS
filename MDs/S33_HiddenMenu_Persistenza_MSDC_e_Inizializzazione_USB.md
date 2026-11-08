# HiddenMenu: memorie, persistenza e applicazione MSDC

20 ottobre 2026. Ricerca richiesta per **tutte le impostazioni**, con priorità MSDC. Risultati parziali verificati; il contratto di salvataggio globale rimane aperto. Nessuna operazione sulla fotocamera.

## Risultato pratico su MSDC

Il toggle MSDC modifica un byte RAM, ma **non applica immediatamente una nuova configurazione USB e non esegue un salvataggio persistente**. Il codice originale contiene entrambe le configurazioni USB, selezionate leggendo quel byte durante l'inizializzazione:

| Byte `0x366B9D` | Testo menu | Descrittore selezionato da `0x139120` | Backend selezionato da `0x139658` |
|---:|---|---|---|
| 2 | OFF | `0x3900F0`: classe 06, sottoclasse 01, protocollo 01, PTP | `0x1394E0`, che chiama `0x1392CC(6)` |
| 1 | ON | `0x3901B0`: classe 08, sottoclasse 06, protocollo 50, mass storage | `0x13959C`, percorso differente |

La distinzione dei descrittori è ora verificata sui byte, insieme ai rami che li selezionano. Questo supera la precedente sola inferenza dall'etichetta “MSDC Card”. **Non è ancora un'enumerazione mass storage osservata sulla macchina.** Il ramo prende il secondo percorso per qualsiasi valore diverso da 2, ma gli unici stati del toggle sono 1 e 2: gli altri valori provati non sono impostazioni consigliate.

La comparsa PTP sul PC mentre il display mostrava ON è compatibile con una configurazione costruita quando il byte valeva ancora 2. È una spiegazione possibile, non una ricostruzione temporale dell'osservazione hardware.

## Nuovo reset a OFF nell'inizializzazione

È stata individuata e riancorata una chiamata precedentemente non discussa:

```text
C6234 ... C6272 -> C5EC0
C5EC0 ... C5EEA: r0 = 2
           C5EEC: call 138F7C
```

Dal punto d'ingresso `0xC5EC0` a questa chiamata non ci sono diramazioni condizionali nel corpo visibile: sono presenti chiamate a servizi, il cui comportamento completo non viene eseguito qui. Il valore 2 viene imposto prima del controllo dei tasti 9/11. Il successivo `0xC5F1A` può impostare nuovamente 2 se entrambi i tasti sono attivi; **non è l'unico reset del selettore**.

Il corpo del setter `0x138F7C..0x138F94` contiene un solo store byte, a `0x366B9D`, e nessuna chiamata a servizi di persistenza. Anche il dato iniziale nel payload vale 2. Una futura gestione della preferenza deve quindi considerare l'ordine **inizializzazione dei default → ripristino della preferenza → costruzione USB**; cambiare soltanto il byte iniziale del payload non risolverebbe la successiva assegnazione di 2.

Questa verifica non esclude un eventuale ripristino da un archivio in un altro punto del firmware. Non dimostra che ogni tipo di accensione attraversi la stessa catena completa o che il byte non venga cambiato successivamente da accessi indiretti.

## Dove e quando USB legge MSDC

1. `0x13901C` legge `0x366B7C+0x20` per chiamare `0x139120`. Quest'ultima, a `0x1391F8..0x139202`, legge separatamente **`+0x21`, cioè MSDC**, per scegliere i descrittori PTP o mass storage. I due selettori non vanno confusi.
2. Il `ld.as` a `0x1391F8` usa `(PC & ~3) - 86*4 = 0x1390A0`, che contiene `0x366B7C`. Il commento GNU non scalato non è il puntatore corretto. Anche il caricamento a `0x1392E0` risolve lo stesso pool usando `-144*4`.
3. `0x139658` legge direttamente il byte tramite il pool `0x139678`. Se vale 2 chiama `0x1394E0`, altrimenti `0x13959C`.
4. `0x138E9C` invoca `0x138EFC`, che porta a `0x139658`, soltanto se il byte guardia **`0x366BB2` vale zero**. Prima della chiamata lo imposta a 1. Richiedere nuovamente quel percorso con guardia nonzero non reinizializza il backend.
5. Il corpo `0x13901C` termina anche con `0x139092`: store zero a `0x366B98+0x1A`, la stessa guardia. La ricostruzione dell'intero ciclo e del suo legame con connessione/disconnessione fisica non è conclusa. Non va descritto come blocco permanente dopo la prima chiamata.
6. Il toggle `0x7D02EE..0x7D0310` chiama getter, setter, getter e aggiorna il testo; non chiama questi percorsi d'inizializzazione USB.

**Condizione software necessaria individuata:** ON deve essere presente quando vengono scelti descrittori e backend. **Procedura pratica ancora non dimostrata:** ottenere quella sequenza sulla macchina, mantenendo ON e rispettando il ciclo della guardia. Non sono autorizzati da questa ricerca comandi USB di reset o scritture RAM/flash.

## Un altro scrittore: percorso dell'interprete

La scansione dei 16 payload ha trovato un ulteriore callsite al setter: **`0x80D61C`**, nel corpo riancorato `0x80D604..0x80D634`. La funzione prende un parametro e scrive 2 se questo è esattamente 1; scrive 1 negli altri casi. Non è un commit persistente.

È chiamata dal dispatcher `0x809F78`, nel ramo parametro/funzione **`0x6E`** a `0x80A7A0..0x80A7B0`. L'interprete chiama quel dispatcher a `0x2D77BE`. Il getter `0x809F70` restituisce la tabella compatta `0x9A0D20`, lunga `0x1274` byte secondo il getter `0x809F68`; il codice `0x2D67DC..0x2D67F0` passa entrambi al gestore delle definizioni.

La tabella compatta è stata decodificata integralmente usando il formato del lettore originale `0x2D667C`: byte di tipo ritorno, nome ASCII terminato da zero, tipi dei parametri terminati dal byte 7. Sono **234 record che consumano esattamente tutti i 4.724 byte**, non un conteggio delle sole stringhe. Il record **110 / `0x6E`**, a `0x9A1490`, è **`USBDevModeSwitch`** (nome a `0x9A1491`), con tipo ritorno 6 e un parametro di tipo 0. Il ramo `0x6E` del dispatcher chiama l’helper sopra; il collegamento fra nome, indice e setter è quindi verificato staticamente. I significati completi dei codici tipo 0/6 e la sintassi del linguaggio restano da attribuire. Restano da verificare la sintassi, l'ingresso file/servizio, le condizioni di esecuzione e il momento rispetto a USB. **Non è ancora una ricetta per creare uno script su SD o un comando USB da inviare.**

Questa pista è rilevante: potrebbe permettere di riapplicare una preferenza usando una capacità già presente, prima di progettare una nuova patch. La sua disponibilità effettiva non è provata dal solo nome.

## Memorie delle altre impostazioni

L'inventario conserva **181 righe** dei sette rami: comprendono **60 record dell'elenco errori**, tre voci INFO, 14 procedure di calibrazione, 28 azioni NAND, 16 SKY, 39 DEBUG e 21 IQ. **Non sono 181 preferenze da salvare.** L'analisi puntuale nuova chiude il corpo del setter per 24 voci DEBUG/IQ, oltre a MSDC; non chiude tutti i consumatori o la persistenza globale.

Per quei 24 casi il codice scrive RAM senza commit nel setter. I byte dei corpi, dei callsite dal menu e dei pool coincidono col MainCode fornito. Il controllo dei formati IQ include i valori accettati 1/2/255 e i rami di ritorno; “1/2/255” riguarda il setter, non una corrispondenza già attribuita a ogni formato sul display.

Due casi impediscono un “salva tutti i byte e riscrivili” generico:

- **SaveCCDRawOnTake e Take12BitCCDRawImage condividono setter e byte `0x36C26E`.** La seconda callback contiene ulteriori chiamate, compresa `0x14A2B8`: non va trasformata automaticamente in una preferenza da ripetere al boot.
- **BatGauge AutoPowerOff:** il getter `0xC8B84` restituisce sempre 0; il setter `0xC86B8..0xC86CC` salva/ripristina soltanto il frame, senza cambiare l'opzione. È il comportamento dei byte del build analizzato; non è prova che una modifica di questo interruttore sia stata effettuata o salvata sulla macchina.

Le opzioni termiche HotKey/10 Sec richiamano anche il setter dell'altra opzione in alcuni rami. La persistenza richiederebbe quindi preservare il contratto del gruppo, non solo tre valori isolati. Calibrazioni, NAND Restore/Reset/Format e test hardware sono procedure distinte dal salvataggio delle preferenze.

## Gestione del salvataggio: cosa è dimostrato e cosa manca

**Non è stato trovato un “Salva tutto” verificato.** Il ramo ResetCameraConfirmMenu già analizzato resta un ripristino, non un salvataggio. Anche esportare CameraParam o MainCode non salva automaticamente i byte RAM elencati qui.

Per ogni preferenza il contratto da chiudere è: setter → memoria runtime → eventuale serializzazione/commit → archivio → caricamento → ultimo override d'inizializzazione. Un setter senza commit prova solo l'assenza di salvataggio nel suo corpo, non l'assenza globale di serializzazione differita o copie di strutture più ampie.

Per MSDC le alternative da verificare, in ordine, sono:

1. Eventuale percorso originale di ripristino/serializzazione collegato alla struttura `0x366B7C`, cercando anche accessi tramite base+offset e copie, non soltanto puntatori letterali.
2. Interprete originale e `USBDevModeSwitch`: sorgente dello script, sintassi, ingresso e ordine di esecuzione; la firma compatta è stata decodificata.
3. Solo se necessario, una preferenza AkeruOS su SD riletta dopo i default e prima dell'inizializzazione USB. È una proposta architetturale, **nessun nuovo file di configurazione riconosciuto dal firmware o BIN installabile è stato creato**. Non richiede per definizione riscrivere NAND, ma SD pronta, momento d'applicazione, errori e recupero andrebbero dimostrati.

L'ambito “tutte” resta aperto: le voci ancora non risolte nella tabella sotto richiedono backend, archivio e inizializzazione propri. La copertura di un setter locale non equivale alla prova di conservazione dopo spegnimento.

## Correzione della procedura USB normale

Il manuale Nikon S33, pagina stampata **96** (PDF pagina 118, indice 117), indica per il trasferimento USB di partire con la macchina spenta e collegare il cavo; l'accensione segue automaticamente. Nelle prove precedenti era stato suggerito di mantenerla accesa: non era la sequenza documentata. Questa correzione riguarda il collegamento normale; non prova che MSDC ON sopravviva al percorso d'accensione.

[Manuale ufficiale Nikon](https://download.nikonimglib.com/archive2/BaNzv00IB5UX02SDox925rKD0D79/S33RM_%28En%2905.pdf), [copia e provenienza SHA-256](../Risultati/HiddenMenu_Persistenza/fonti_pubbliche/source_manifest.json). Il manuale non documenta HiddenMenu o il salvataggio MSDC. Nessuna nuova prova hardware è stata effettuata applicando questa sequenza.

## Verifiche, evidenze e limiti

```bash
python3 Python_Trace_Scripts/s33_verify_msdc_lifecycle.py
```

- [Script](../Python_Trace_Scripts/s33_verify_msdc_lifecycle.py).
- [Indice dell'ultima esecuzione](../Risultati/HiddenMenu_Persistenza/latest.json): manifest, GNU, sei scenari CPU, fixture dichiarate, inventario e contratti dei flag nella stessa cartella.
- Firmware originale verificato per dimensione e SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`; 16 payload verificati dagli helper, dump e strumenti originali ricontrollati invariati.
- Scansione delle occorrenze LE/ARC e delle diramazioni lineari su ciascuno dei 16 payload, con conversione ELF→BIN ricontrollata. I risultati sono **candidati**; il falso positivo apparente `0x138DB8→0x138E9C` cade in un pool, non in una chiamata eseguibile. I candidati nel payload risorse 9 non sono promossi a codice.
- 32 finestre principali, 24 collegamenti menu→setter e relativi corpi/pool, più il caso BatGauge; controlli aggiuntivi sui descrittori e sul byte guardia.
- Sei scenari CPU con valori iniziali 0/1/2/5/6/255 eseguono getter/setter/toggle originali, selettore originale `0x81DC38` con store reale `0x190BF0` nella tabella RAM `0x3ADD64`, ramo originale `0x139658`, frammento originale `0xC5EEA..0xC5EF0` e helper originale `0x80D604`.
- La guardia `0x138E9C` è eseguita due volte per scenario: con guardia iniziale 0 il registratore è chiamato una volta, con guardia nonzero mai. Il corpo di `0x138EFC` è sostituito da un registratore in questa prova; il suo vero raccordo a `0x139658` è verificato staticamente.
- Le due inizializzazioni backend `0x1394E0`/`0x13959C` e il servizio `0x136550` sono simulati. Il menu è provato entrando nel case con un chiamante di laboratorio; la continuazione UI è sostituita da ritorno. Il frammento di inizializzazione è eseguito dopo le precedenti chiamate, non eseguendo tutto `0xC5EC0`. Nessuna simulazione di scheduler, MMIO, USB o persistenza fisica.
- I primi tentativi falliti restano archiviati: lookahead oltre uno stub troppo corto, ritorno del chiamante di laboratorio corretto dopo un timeout, e confine di una finestra che troncava un'istruzione. Non sono difetti attribuiti al firmware. Le prove PASS usano padding dichiarato negli stub e finestre riancorate.

Nessun builder GNU eseguito, nessuna scrittura negli alberi GNU. Compilazioni, fixture e snapshot sono nelle cartelle di risultati del progetto. Circa **10% funzionale AkeruOS invariato**.

## Continuazione e audit dell'obiettivo

| Requisito | Stato attuale | Evidenza ancora necessaria |
|---|---|---|
| Individuare memoria e setter MSDC | Verificato nel build e nel dump | Nessun nuovo requisito locale |
| Capire perché ON può non applicarsi subito | Selettori, descrittori e guardia verificati; spiegazione hardware solo compatibile | Correlazione temporale con una connessione reale |
| Conservare MSDC dopo spegnimento | Non dimostrato; assegnazione OFF aggiuntiva individuata | Archivio/ripristino o percorso interprete, ordine e verifica runtime |
| Inventariare tutte le voci | Inventario dei sette rami disponibile | Distinguere completamente preferenze, azioni e procedure |
| Capire memoria e salvataggio di tutte le impostazioni | 24 voci più MSDC con corpi setter verificati; BatGauge chiarito | Completare voci mancanti, consumatori, commit e caricamento |
| Procedura pratica affidabile per MSDC | Non ancora disponibile | Percorso d'inizializzazione con ON conservato e osservazione USB coerente |

Prossimo punto verificabile: decodificare il record `USBDevModeSwitch` nella tabella compatta a `0x9A0D20`, seguendo `0x2D6718` e l'ingresso dell'interprete. Non partire dai candidati del payload risorse e non inventare sintassi o file di autoavvio. La ricerca mantiene l'obiettivo completo, senza promuovere questo checkpoint a soluzione del salvataggio globale.

## Tabella corrente delle 60 voci DEBUG/IQ

La tabella viene ricavata dall'inventario della prova collegata. “RAM nel setter” non certifica persistenza o assenza di effetti nei consumatori.

| Menu / indice | Voce | Memoria / setter | Salvataggio verificato |
|---|---|---|---|
| DEBUG / 0 | Perf Log | — / — | Da ricostruire |
| DEBUG / 1 | LCD Select | — / — | Da ricostruire |
| DEBUG / 2 | LCD Brightness Adjust | — / — | Da ricostruire |
| DEBUG / 3 | LCD Timeout:ON | — / — | Da ricostruire |
| DEBUG / 4 | LCD Backlight:ON | — / — | Da ricostruire |
| DEBUG / 5 | LCD Smart Display:Disabled | — / — | Da ricostruire |
| DEBUG / 6 | Display ADC | — / — | Da ricostruire |
| DEBUG / 7 | BatGauge Info | — / — | Da ricostruire |
| DEBUG / 8 | BatGauge AutoPowerOff:ON | — / 0xc86b8 | Setter senza modifica; getter costante 0 |
| DEBUG / 9 | Temperature Protection:ON | 0x365a04 / 0xd46f0 | RAM nel setter; persistenza globale aperta |
| DEBUG / 10 | High Temp. Trigger(10 Sec):OFF | 0x365a05 / 0xd4714 | RAM nel setter; persistenza globale aperta |
| DEBUG / 11 | High Temp. Trigger(HotKey):OFF | 0x365a06 / 0xd4738 | RAM nel setter; persistenza globale aperta |
| DEBUG / 12 | Audio Adjust | — / — | Da ricostruire |
| DEBUG / 13 | Audio Stereo Info | — / — | Da ricostruire |
| DEBUG / 14 | Play Sample.wav | — / — | Da ricostruire |
| DEBUG / 15 | Manual Focus | — / — | Da ricostruire |
| DEBUG / 16 | Exposure Time | — / — | Da ricostruire |
| DEBUG / 17 | ISO | — / — | Da ricostruire |
| DEBUG / 18 | Smart Display Testing | — / — | Da ricostruire |
| DEBUG / 19 | EV | — / — | Da ricostruire |
| DEBUG / 20 | AE Metering | — / — | Da ricostruire |
| DEBUG / 21 | Punch Through:ON | 0x36578e / 0xccb28 | RAM nel setter; persistenza globale aperta |
| DEBUG / 22 | Color Sharding:ON | — / — | Da ricostruire |
| DEBUG / 23 | 10 Sec. Video Length Limit:OFF | 0x367a01 / 0x173b40 | RAM nel setter; persistenza globale aperta |
| DEBUG / 24 | Still HW Smear Comp | — / — | Da ricostruire |
| DEBUG / 25 | Video HW Smear Comp | — / — | Da ricostruire |
| DEBUG / 26 | S2S Test:Disabled | 0x68201c / 0x660c68 | RAM nel setter; persistenza globale aperta |
| DEBUG / 27 | HDMI Output Mode | — / — | Da ricostruire |
| DEBUG / 28 | TV Test | — / — | Da ricostruire |
| DEBUG / 29 | Strobe Test | — / — | Da ricostruire |
| DEBUG / 30 | SD HotPlug:Enabled | 0x365793 / 0xcd7d0 | RAM nel setter; persistenza globale aperta |
| DEBUG / 31 | SD High Speed:Enabled | 0x365649 / 0xc7a84 | RAM nel setter; persistenza globale aperta |
| DEBUG / 32 | SD High Speed Clock | — / — | Da ricostruire |
| DEBUG / 33 | SD Clock Current:4XmA | — / — | Da ricostruire |
| DEBUG / 34 | SD Data Current:4XmA | — / — | Da ricostruire |
| DEBUG / 35 | PWM Adjustment | — / — | Da ricostruire |
| DEBUG / 36 | MSDC Card:OFF | 0x366b9d / 0x138f7c | RAM; reset OFF e lettura USB verificati, nessun commit nel setter |
| DEBUG / 37 | NAND Flash BadBlock | — / — | Da ricostruire |
| DEBUG / 38 | Fast Lang Change:OFF | 0x367268 / 0x1590ec | RAM nel setter; persistenza globale aperta |
| IQ / 0 | ThumFormat | 0x366c10 / 0x13aeb4 | RAM nel setter; persistenza globale aperta |
| IQ / 1 | VGAFormat | 0x366c14 / 0x13aed8 | RAM nel setter; persistenza globale aperta |
| IQ / 2 | FullFormat | 0x366c18 / 0x13aefc | RAM nel setter; persistenza globale aperta |
| IQ / 3 | SaveCCDRawOnTake | 0x36c26e / 0x28d498 | RAM nel setter; persistenza globale aperta |
| IQ / 4 | SaveCFARawOnIRP | 0x366c20 / 0x13af20 | RAM nel setter; persistenza globale aperta |
| IQ / 5 | SaveThumYRGB | 0x366c21 / 0x13af30 | RAM nel setter; persistenza globale aperta |
| IQ / 6 | SaveThumJPEG | 0x366c22 / 0x13af40 | RAM nel setter; persistenza globale aperta |
| IQ / 7 | SaveVGAYRGB | 0x366c23 / 0x13af50 | RAM nel setter; persistenza globale aperta |
| IQ / 8 | SaveVGAJPEG | 0x366c24 / 0x13af60 | RAM nel setter; persistenza globale aperta |
| IQ / 9 | SaveFullYRGB | 0x366c25 / 0x13af70 | RAM nel setter; persistenza globale aperta |
| IQ / 10 | SaveFullJPEG | 0x366c26 / 0x13af80 | RAM nel setter; persistenza globale aperta |
| IQ / 11 | SaveAEOnS1 | — / — | Da ricostruire |
| IQ / 12 | Take12BitCCDRawImage | 0x36c26e / 0x28d498 | RAM condivisa con indice3; contiene anche un’azione |
| IQ / 13 | Switch Require formating | — / — | Da ricostruire |
| IQ / 14 | Log Clock Settings | — / — | Da ricostruire |
| IQ / 15 | Trigger Self_LED for PERF | — / — | Da ricostruire |
| IQ / 16 | Video LiveView | 0x3657f4 / 0xd081c | RAM nel setter; persistenza globale aperta |
| IQ / 17 | SaveCFAAtVideoLiveview | 0x36c26f / 0x28d4bc | RAM nel setter; persistenza globale aperta |
| IQ / 18 | Fast DPS Error Message | 0x369e1e / 0x225308 | RAM nel setter; persistenza globale aperta |
| IQ / 19 | Tune AF LED Current | — / — | Da ricostruire |
| IQ / 20 | LiveviewDisplayBatteyAD | — / — | Da ricostruire |

Prova di riferimento: `Risultati/HiddenMenu_Persistenza/20261020T183318Z/verified_evidence.json`.

## Continuazione richiesta: default MSDC senza persistenza

È stato creato e verificato il [candidato offline a un solo immediato](S33_USB_MSDC_Predefinito_Candidato_Offline.md): C5EEA passa1 invece di2, con backend e descrittori originali invariati.48scenari/288fasi confermano la selezione mass storage nell’ordine d’inizializzazione predisposto. Gli override originali restano: entrambi i tasti9/11, toggle e USBDevModeSwitch. Il ramo del padre che ripulisce la guardia è distinto dalla sua reimpostazione esplicita nel test. Non è persistenza globale, un’enumerazione hardware o recupero dimostrato. Questa è la priorità corrente dell’utente; lo studio delle altre preferenze resta distinto. Prossimo: scrittori tramite struttura/alias/copiedi366B7C e ordine reale dei diversi avvii; nessun flash.

## Continuazione — USBDevModeSwitch chiarito senza nuovo BIN

La [nuova verifica della struttura](S33_USBDevModeSwitch_Identita_e_Scritture_Struttura_USB.md) conferma che il nome USBDEVMODE usato in chat si raccorda alla funzioneUSBDevModeSwitch deiMD: parametro esattamente1→PTP, altro→MSDC.808casi, inclusi520casi dell’helper, distinguono il selettore dalla diagnostica e verificano gli store locali circostanti. ComMgrTask138E20 è creato prima dell’assegnazione del default; attende una notifica prima di costruireUSB. Interpretazione dei tipi/sintassi, produttori dell’evento e ordine runtime rimangono aperti. CandidatoMSDC predefinito precedente invariato, nessuna azionehardware.

## Continuazione — notifica e guardia condizionale, 20 ottobre 2026

Il [nuovo rapporto ComMgr](S33_ComMgr_Notifica_USB_Ordine_e_Guardia_Condizionale.md) aggiunge 156 casi originali con servizi esterni simulati: il backend precede la notifica; stato grezzo 1/3 invia evento applicativo4109, gli altri provati pubblicano ComMgr02100001/bit1, anche con errore backend. Il reset locale della guardia139092 è saltato dal ramo139084 quando entrambi i predicati1399D8/1399FC sono nonzero. 139CF4 è un registratore, quindi i suoi effetti reali sulla guardia restano aperti. La matrice precedente del candidato imponeva l’ordine descrittori→backend e il reset delle fasi successive: non prova l’intero avvio. Nessun BIN o hardware modificato. Proseguire su4109, predicati e ordine task/default prima di concludere sul comportamento globale.
