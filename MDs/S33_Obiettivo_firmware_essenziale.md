# Nikon S33 — Firmware essenziale

## Obiettivo richiesto

Una fotocamera dedicata allo scatto: minore attesa, maggiore autonomia, poche impostazioni e grafica sobria. Queste sono le priorità del progetto; la ricostruzione generale del firmware serve a raggiungerle.

## Prima versione proposta

- Accensione direttamente nella schermata di ripresa, senza passaggi decorativi aggiuntivi.
- Schermata con inquadratura, batteria, foto disponibili, stato del flash e della messa a fuoco; avvisi di errore leggibili.
- Menu breve per flash, autoscatto, dimensione/qualità della foto e luminosità. Riproduzione e cancellazione delle foto restano accessibili, con conferma della cancellazione.
- Effetti, cornici, animazioni e suoni decorativi esclusi dal percorso principale. È un indirizzo progettuale: non sono ancora stati identificati tutti i componenti da modificare.
- Gestione automatica dell'inattività, da tarare insieme al tempo di risveglio; nessuna promessa numerica prima delle misure.

Questa è una proposta minima, non un elenco di funzioni già implementate. Non introduce video, RAW, nuove modalità o altri ampliamenti di progetto.

## Strategia tecnica

La direzione scelta dall'utente è recuperare le parti fondamentali del firmware originale e costruire sopra una nuova applicazione essenziale. Questo sostituisce la precedente proposta di limitarsi a modifiche mirate dell'applicazione Nikon.

Il confine di riutilizzo da verificare è il seguente:

| Strato | Obiettivo |
|---|---|
| Avvio e runtime | Conservare inizializzazione hardware, memoria, interrupt e servizi necessari all'esecuzione |
| Hardware e fotografia | Riutilizzare controllo di sensore, ottica, autofocus, esposizione, JPEG, SD, schermo, tasti e alimentazione, comprese calibrazioni e gestione degli errori |
| Nuova applicazione | Implementare il ciclo ripresa → scatto → salvataggio → ripresa, una UI sobria e la politica di inattività |

Sono confini progettuali, non moduli già separati. Abbiamo binari compilati, non un progetto sorgente ricompilabile: i blocchi RHIR non equivalgono automaticamente a driver o librerie. Prima di estrarre o spostare codice vanno individuati chiamate, dati globali, indirizzi fissi, inizializzazioni e dipendenze dal runtime.

Per una prima prova si valuterà di mantenere codice e dati originali ai loro indirizzi e trasferire il controllo a una piccola applicazione nuova dopo l'inizializzazione necessaria. Anche questa possibilità richiede verifica: non abbiamo ancora un punto d'ingresso sicuro, interfacce richiamabili documentate, spazio di caricamento accertato o una toolchain validata sul dispositivo. La rimozione fisica dei componenti inutilizzati verrà valutata solo dopo aver dimostrato che la nuova applicazione può farne a meno.

Nascondere un menu non prova che il relativo codice smetta di consumare tempo o energia. Occorre identificare i percorsi realmente eseguiti. Allo stesso modo, la presenza di immagini decorative nel file non misura il loro costo durante lo scatto.

L'obiettivo è migliorare la reattività a qualità fotografica invariata, salvo una successiva scelta esplicita dell'utente. Non si saltano calibrazioni, controlli batteria, gestione degli errori o completamento delle scritture SD per ottenere risultati apparentemente migliori.

## Cosa misurare sulla fotocamera

| Obiettivo | Confronto necessario con il firmware originale |
|---|---|
| Pronta a fotografare | Tempo dall'accensione alla possibilità effettiva di acquisire una foto |
| Scatto reattivo | Ritardo con fuoco già acquisito, separato dal tempo di autofocus |
| Scatti successivi | Tempo fra due acquisizioni e tempo necessario a completare il salvataggio |
| Autonomia | Consumo in ripresa/inattività e numero di scatti con una sequenza ripetibile |
| Risveglio | Tempo per tornare operativi dopo il risparmio energetico |

I confronti richiedono stessa batteria e carica iniziale, stessa SD, scena, luce, qualità, uso del flash e luminosità dello schermo. Nessuna di queste misure hardware è ancora disponibile. Uno standby più aggressivo e la disponibilità immediata allo scatto possono essere obiettivi in conflitto: vanno valutati insieme.

## Prime piste trovate con REA

La ricerca statica ha trovato e registrato stringhe nei blocchi originali, controllandone gli SHA-256:

| Area | Stringhe osservate |
|---|---|
| Scatto | `Recorder Capture Image Start`, `Recorder Capture Image End`, `Capture image done` |
| Elaborazione | `ImgMgrJPEGTask` |
| Alimentazione | `BatteryMgr.c`, `BatteryMgr_PowerOnStatus() power off`, `Deep Sleep` |
| Schermo | `LCD Backlight:OFF` |
| Interfaccia | `BootupMenuBackgroundSelect` |

Offset, indirizzi candidati e hash sono in `s33_obiettivi_indizi.json`. Sono ancore per cercare i riferimenti nel codice, non funzioni già identificate. Alcuni testi potrebbero appartenere a diagnostica o test di fabbrica.

Prova REA: `ev_d8f850db6b9abdbe27bee10bdc98efe4bce4dbe2132746aa4f8f727d6e502a28`. Processo terminato con codice 0, cattura non troncata. Il codice della verifica è conservato negli argomenti dello scenario del bundle `s33_rea_obiettivi_evidence.json`.

## Prossima tappa concreta

Il capitolo 5 documenta il confronto GNU/Radare2, l'header interno TBIB con checksum verificato, 4 task TBIB e 53 task TBM. È stata individuata la routine a `0x158E78` che consulta la tabella principale per ID, oltre ai percorsi candidati di inizializzazione e ai servizi condivisi da scatto e JPEG. Le discrepanze del decoder Radare2 sono ora riproducibili; per queste finestre si usa GNU objdump ARC700.

La prossima tappa è ricostruire il passaggio TBIB → TBM e seguire le inizializzazioni chiamate dal task `RTOSINIT` a `0x167A20`, quindi identificare come l'applicazione richiede lo scatto e riceve il completamento del salvataggio. La mappa dei task non prova ancora che i componenti possano essere separati: servono dipendenze e protocolli, non soltanto gli indirizzi d'ingresso.

Il primo traguardo funzionale sarà una piccola applicazione che, appoggiandosi alla base verificata, mostra l'inquadratura, legge il tasto di scatto, acquisisce e salva una foto e torna pronta. Non serve ancora un sistema di menu completo. Prima delle prove sul dispositivo occorrono una build compatibile e una procedura di recupero verificata: il checksum dei 16 blocchi è noto, ma gli altri controlli dell'aggiornamento e il recupero da un mancato avvio restano da ricostruire.

Stato: mappa iniziale della base e dei task recuperata, disassemblaggio corretto in alcune finestre, checksum TBIB e blocchi TBM verificati. Nessun nuovo firmware compilato o installato, nessun guadagno di prestazioni o autonomia ancora misurato.
