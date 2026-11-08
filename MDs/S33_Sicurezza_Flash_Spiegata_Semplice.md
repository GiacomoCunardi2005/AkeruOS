# Nikon S33: è sicuro installare la modifica?

**PacchettoNAND/PC,21ottobre2026 — verifica successiva:** il [dispatch originale eseguito offline](S33_NAND_PC_Dispatch_Pacchetto_Boot_Invariato_e_Contatore.md) richiede la scritturaBoot anche con byteBoot invariati. Dieci casi mostrano inoltre che una seconda chiamata diretta dopo errore può terminare con successo prematuro, per contatore conservato; non è una sessioneUI reale. Non interpretare questa osservazione come una procedura sicura di retry o spegnimento. **Installazione ancora sconsigliata**, recupero fisico e durataRAM aperti.

**CandidatoNAND dal PC,21ottobre2026:** la versione corrente è0bb25fd6…cb324e9; i precedenti52f8714d… sono esclusi per offset differiti incoerenti. [Ultima verifica](S33_NAND_PC_Main_Updater_Rilettura_Retry_e_Limite_Recupero.md):12casi dell’updaterMain su RAM, compresa rilettura/confronto e tre tentativi. Un errore può arrivare dopo modifiche già effettuate; notifica6 non equivale a confronto riuscito. **Sconsigliata l’installazione:** durataRAM, percorso completo dei componenti e recupero fisico restano aperti. Le sezioni successive conservano le valutazioni degli altri candidati e i checkpoint precedenti.

**Uscita senza confermare reset,20 ottobre2026:** [24nuoveproveCPU](S33_HiddenMenu_Uscita_e_Conservazione_Impostazioni.md#continuazione-ramo-di-annullamento-eseguito--20-ottobre-2026) del callbackdiannullamento,con5servizisimulati:MSDCe stackconservati,resetnonchiamato;noninteraUI né salvataggioalriavvio. P1RES/DSC/Clock/Perfaggiunti noncontengonounnuovosalvataggio. SceltafisicaNo/Annulla daidentificare,nonusareconfermaresetripristino persalvare.

**Uscita e conservazione,20 ottobre 2026:** [verifica dedicata](S33_HiddenMenu_Uscita_e_Conservazione_Impostazioni.md): ritornoDEBUG→root distinto dalla confermareset della radice. SetterMSDC soloRAM; nessuna procedura salva-tutto o conservazione alriavvio dimostrata. Non confermare reset per salvare.

**USB reale, 20 ottobre 2026:** con MSDC Card:ON confermato dall’utente, il PC ha identificato la Nikon in modalitàPTP; nella ripetizione è poi risultata assente. [Dettagli](S33_USB_MSDC_e_Accelerazione_Analisi_OS.md#osservazione-usb-reale--20-ottobre-2026). Questo dimostra una connessione USB osservata, non stabilità, accessoRAM o recupero. Nessuna scrittura sulla macchina.

**Nuova evidenza dai dump,20 ottobre 2026:** [classificazione e confronti](S33_Classificazione_Dump_Fotocamera.md). MainCode fornito contiene ilTBM candidato identico;BootCode contieneTBIB originale eNANDReserved ilP1RES originale completo. Questo supera il solo confronto del nome delBIN per i byte del dump consegnato; acquisizione fisica non osservata dall’agente, recupero ancora non dimostrato.

**Aggiornamento hardware del20 ottobre 2026:** il candidato è stato installato dall’utente e [le foto](S33_HiddenMenu_Hardware_Foto_e_Versioni.md) mostrano il menu funzionante; senzaSD l’utente riferisce avvio normale. Ora abbiamo quindi un caso reale favorevole. Questo non prova ancora il casoSDsenza marcatore, l’uscita, la stabilità fotografica e il recupero dopo guasto. Le valutazioni NO-GO seguenti erano il consiglio prima dell’installazione; non sono una negazione dell’avvio riuscito ora documentato. Nessuna nuova scrittura sulla fotocamera eseguita dall’agente.

Aggiornato: **20 ottobre 2026**. Questo è il documento semplice da mantenere aggiornato con le prossime verifiche.

**Oggi non abbiamo prove sufficienti per consigliare l'installazione. La decisione resta NO-GO: non procedere al flash con le sole evidenze attuali.** Non abbiamo dimostrato che la modifica guasterebbe la fotocamera; abbiamo osservato un avvio riuscito, ma non dimostrato stabilità generale e recupero se qualcosa va storto.

“Flash” significa riscrivere il software conservato nella memoria della fotocamera. Una prova sul computer può chiarire molti passaggi, ma non dimostra automaticamente cosa succederà sulla macchina reale.

## Confronto con i vecchi BIN

**Il nuovo BIN con interruttore SD non è dimostrato sicuro quanto la semplice patch CMP1.** Le somme del pacchetto sono coerenti in entrambi. La vecchia patch cambia un confronto dentro codice già esistente; il nuovo candidato aggiunge220byte di codice e8byte di collegamento, richiede una posizione ancora da confermare e aggiunge accessi SD al selettore. I60scenari favorevoli controllano quel tratto nel modello; non trasferiscono automaticamente al candidato le vecchie prove limitate d’avvio CMP1.

Il nuovo controllo evita di cambiare lo stato Nikon e permette di saltare la richiesta del menu quando il file manca. Sono vantaggi circoscritti. Non garantiscono l’avvio o il recupero e non permettono di assegnare una percentuale affidabile di rischio. **Entrambi i modificati restano NO-GO, ma per un insieme diverso di incertezze.** Il firmware originale non contiene queste nostre aggiunte; anche l’installazione ordinaria richiede compatibilità e condizioni appropriate.

## Ora esiste il BIN, ma non è ancora pronto da installare

Abbiamo creato [S33_MODIFICA_SD_SPERIMENTALE_NON_INSTALLARE.bin](../Risultati/Firmware_sperimentali/SD/S33_MODIFICA_SD_SPERIMENTALE_NON_INSTALLARE.bin): un contenitore completo di29.602.084byte, con il nuovo controllo del file, non un programma per computer rinominato. Le somme tornano e60scenari eseguiti dalla nuova posizione danno25richieste HiddenMenu e35continuazioni normali. L’originale è conservato; nessuna operazione sulla Nikon.

Il limite concreto è la posizione del codice. Abbiamo evitato due zone già referenziate e usato220byte intermedi inizialmente a zero. **Non abbiamo ancora dimostrato che il firmware non usi quella zona attraverso indirizzi calcolati, né che resti eseguibile durante il vero avvio.** Per questo il file porta il nome NON_INSTALLARE. Restano anche SD reale, avvio completo e recupero dopo errore. Togliere `modifica.modifica` non ripristina il firmware e non salva da un blocco precedente al controllo. [Dettagli e prove](S33_HiddenMenu_BIN_Candidato.md).

Le prove favorevoli giustificano continuare il lavoro sul candidato. Non giustificano ancora installarlo: **NO-GO flash invariato**. Le sezioni successive conservano anche le fasi precedenti; oggi il BIN esiste, mentre le precedenti affermazioni “solo prototipo ELF” sono storiche.

## Nuovo controllo: quanto codice abbiamo davvero provato?

Abbiamo contato i punti diversi raggiunti nell’avvio simulato: **3.193**, anche se il contatore mostra583.306 passi perché ripete molte istruzioni. Il confronto diretto copre circa **0,32% delle righe candidate del programma principale** e **0,052% del listato complessivo**. Non è una percentuale di avvio completato o di istruzioni sicuramente corrette: il listato contiene anche dati e l’emulatore ha limiti ancora aperti.

Tre nuove prove partono con la memoria riempita rispettivamente di zero e di due valori diversi. Producono la stessa traccia fino allo stesso arresto; tre controlli separati confermano che i riempimenti sono stati applicati. È un indizio favorevole: quel tratto non cambia visibilmente al cambiare di quei valori iniziali. **Non dimostra che ogni dato letto sia conosciuto o corretto.** Servono controlli espliciti sulle letture di memoria mai scritta, sulle istruzioni e sul vero passaggio dal caricatore al programma principale. Alcune istruzioni matematiche restano basate su un modello provvisorio.

[Rapporto con conteggi, prove e sei questioni aperte](S33_Copertura_Esecuzione_e_Audit_Modello.md). Le nuove verifiche sono tutte sul computer; **NO-GO flash invariato**.

## Il software ora ha un collegamento provato nel simulatore

Abbiamo creato un [programma di prova per computer](S33_HiddenMenu_Prototipo_Collegato_Offline.md) che contiene anche il salto dal punto Nikon originale alla nuova routine. Altri60scenari passano attraverso quel salto, con stato Nikon immutato. Quel file è ELF per il laboratorio e non va usato come aggiornamento. Il successivo BIN candidato è descritto sopra; resta sperimentale.

Una prima posizione piena di zeri risultava usata come dato e non è stata sovrascritta. Il BIN successivo usa un intervallo distinto, ancora da confermare per proprietà e residenza. La posizione usata dal vecchio ELF era solo laboratorio.

È stato aggiunto anche un controllo più severo sulle letture RAM:29prove verificano che byte mai inizializzati vengano fermati, comprese scritture parziali. I prefissi d’avvio studiati arrivano allo stesso limite hardware senza nuove letture sconosciute nei percorsi controllati. Questo riduce un’incertezza del modello; non certifica ancora avvio, schermata, uso e recupero reali. **NO-GO flash invariato**.

## Un file sulla SD per scegliere il menu

Abbiamo provato sul computer un nuovo prototipo: **file `modifica.modifica` presente nella radice SD → richiesta HiddenMenu; file assente → continuazione normale**. Una cartella omonima e gli errori restituiti dai servizi disabilitano la richiesta. Il file può essere vuoto; non viene letto il suo contenuto. La variabile di stato Nikon resta invariata.

Sessanta scenari simulati e una baseline originale sono stati eseguiti. Nei sette casi negativi con stato normale1, registri e flag coincidono con l’originale al punto di rientro controllato. La lettura fisica della SD e la sessione completa del menu restano da dimostrare: [rapporto e limiti](S33_HiddenMenu_Interruttore_File_SD.md).

**Togliere il file disattiverebbe l’apertura del menu, ma non ripristinerebbe il firmware originale.** Non aiuta se il caricatore viene danneggiato o la macchina si blocca prima del controllo. Serve anche verificare che il controllo della SD non introduca attese durante l’avvio normale. Il controllo è ora collegato a un BIN sperimentale, ma non verificato per l’installazione: **NO-GO flash invariato**.

## HiddenMenu è un menu grafico? E cambia l’USB?

Nel software abbiamo verificato il titolo **HIDDEN MENU**, una lista di sette voci e il codice che ne gestisce le selezioni. È quindi un’interfaccia grafica prevista dal firmware. Le foto reali del20 ottobre mostrano il menu e le sue pagine informative; il rendering completo nel simulatore resta incompleto.

L’abilitazione diagnostica USB ha un controllo separato. Non abbiamo dimostrato che aprire HiddenMenu attivi automaticamente nuove modalità o comandiUSB; anche due oggetti chiamati “CALI.MENU” e “Calibration” sono diversi. [Prove e limiti](S33_HiddenMenu_GUI_e_Diagnostica_USB.md). Nessuna nuova provaUSB; decisione flash invariata.

## Perché la modifica potrebbe funzionare

- **Le differenze sono delimitate.** La vecchia patch CMP1 cambiava quattro byte. Il nuovo candidato con interruttore SD ne cambia230: il salto, la nuova routine e i campi d’integrità. Il confronto integrale esclude altre differenze nel file, ma non gli effetti runtime della nuova routine.
- **La CPU segue il ramo previsto nei test.** Con lo stato adatto, la modifica cambia la scelta che porta a cercare HiddenMenu. Questo passaggio è stato eseguito nell'emulatore.
- **Il menu esiste già nel software Nikon.** Con risultati del filesystem forniti dal test, entrambe le varianti raggiungono la funzione principale e la funzione d'ingresso del menu. Non stiamo supponendo l'esistenza di un menu dal solo nome di un file.
- **I controlli del pacchetto verificati risultano coerenti.** Le somme di controllo della patch sono state aggiornate e confrontate con il formato originale.

Questi sono motivi concreti per continuare l'analisi. Non equivalgono ancora a un sì all'installazione.

## Perché oggi non possiamo chiamarla sicura

### Non abbiamo visto un avvio completo

Le prove confrontano porzioni dell'avvio. L'emulatore si arresta quando incontra registri hardware o istruzioni che non sa riprodurre correttamente. Un vecchio errore dell'emulatore è stato corretto e controllato, ma rimangono altri limiti.

Quegli arresti non dimostrano un guasto della Nikon. Significano che la prova non è arrivata fino alla fine.

### Non abbiamo una sessione completa del menu

Il menu viene raggiunto soltanto sotto condizioni dichiarate del test. Non abbiamo dimostrato tutta la sequenza schermata visibile → comandi → uscita → ritorno al normale uso fotografico.

In un test separato, un evento candidato d'uscita apre il menu di **conferma del ripristino impostazioni**. Non abbiamo inviato la conferma. Non è ancora verificato quale tasto fisico corrisponda a quell'evento, quindi non possiamo promettere un'uscita innocua.

Inoltre stato 1 e stato 3 non sono equivalenti in tutto il programma: in un caso negativo controllato le due varianti prendono percorsi diversi. La modifica non è ancora dimostrata come un semplice interruttore senza altri effetti.

### Un byte modificato non significa un byte scritto sulla macchina

Il file distribuito comprende programma principale, caricatore d'avvio e risorse. Nel codiceV1.1 ricostruito, l'aggiornamento può raggiungere anche la scrittura del caricatore.

Il caricatore è identico nei due file, ma **non è dimostrato che l'aggiornamento eviti di riscriverlo**. Durante una riscrittura, perdere alimentazione potrebbe quindi coinvolgere proprio il software necessario per ripartire. Non abbiamo dimostrato che rimanga sempre una copia utilizzabile.

### Conservare il firmware originale non basta a garantire il recupero

Avere il file originale è utile. Per usarlo dopo un guasto deve però restare un programma capace di avviare la fotocamera, leggere il file e riscrivere la memoria.

Abbiamo trovato nel caricatore codice che può tentare sorgenti alternative. Non abbiamo dimostrato che quel caricatore sopravviva a ogni interruzione dell'aggiornamento, né che quel percorso permetta il ripristino sulla macchina reale. Il file originale non è nemmeno un backup integrale delle calibrazioni specifiche della fotocamera.

### La versione sulla fotocamera è diversa dal campione analizzato

I log disponibili dichiarano **V1.0** sulla Nikon. Il binario studiato è **V1.1**. Durante il primo aggiornamento lavora il software già presente sulla macchina: non possiamo attribuirgli automaticamente tutti i comportamenti ricostruiti nellaV1.1.

## Le due operazioni prima e dopo il controllo ora sono codice CPU

Abbiamo eseguito un nuovo prototipo che chiama davvero la funzione Nikon per impostare 3 prima del confronto e 1 dopo. La prova precedente cambiava quel byte dall'esterno del simulatore; questa esegue le istruzioni della CPU.

Su 105 scenari, 35 usano le due chiamate reali. Il risultato del confronto viene conservato e si arriva alla richiesta di HiddenMenu quando il percorso è disponibile. Con stato iniziale1, i casi verificati hanno gli stessi esiti della variante CMP1. [Codice e risultati](S33_Due_Set_CPU_Prima_Dopo_Confronto.md).

Ci sono due limiti concreti. Il valore 3 rimane visibile durante diverse istruzioni, quindi altri task o interrupt potrebbero leggerlo. Inoltre il prototipo riporta sempre 1: se prima c'era 2 o 3, quel valore precedente viene perso. Il test lo ha confermato con più stati iniziali.

Abbiamo anche preparato la [lista degli scrittori dello stato](S33_Lista_Scrittori_Stato_HiddenMenu.md): il setter è 0x129904 e la chiamata diretta originale verificata gli passa 1. La ricerca non esclude ancora scritture indirette.

Il prototipo non è ancora collegato a un firmware da installare e la prova si ferma prima del funzionamento del menu. **Non cambia il NO-GO al flash.**

## Scelta per il simulatore: 128 MiB

Abbiamo adottato la stima proposta di **128 MiB per il modello di laboratorio**. Questo significa 134.217.728 byte di spazio disponibile nel simulatore, senza cambiare i dati del firmware già caricati. Non significa che abbiamo scoperto quanta RAM possiede la Nikon.

Abbiamo confrontato memoria inizialmente sconosciuta e memoria inizialmente azzerata: **32 tentativi limitati di avvio e 72 casi isolati** mantengono gli stessi risultati del test precedente. L'avvio si ferma ancora sui registri hardware successivi; fornire più RAM non fornisce le risposte di quei dispositivi.

Per proseguire teniamo come riferimento il contenuto sconosciuto: iniziare tutto a zero potrebbe nascondere errori. I registri hardware rimangono separati dalla RAM. [Configurazione e prove](S33_Emulazione_RAM_128_MiB.md).

## Possiamo stimare la RAM cercando l'indirizzo più alto?

Abbiamo fatto la ricerca su **tutte le 6.125.576 righe dell'ASM**, verificando che rappresentino ancora i byte del firmware originale.

La mappa candidata dei programmi arriva a `0x0128D800`, circa **18,55 MiB dall'indirizzo zero**. Esistono anche basi di aree di lavoro molto più alte: una funzione restituisce fino a `0x0F7B0000`. Questo non significa che tutta la memoria fra zero e quell'indirizzo sia RAM installata.

Un piccolo blocco di memoria può essere raggiunto attraverso una finestra posta a un indirizzo alto. Inoltre alcuni numeri dell'ASM sono maschere, altri indirizzi sono registri hardware, e i puntatori possono essere calcolati durante l'esecuzione. Per questo il massimo trovato non dà un limite superiore affidabile della capacità fisica.

La ricerca è utile per costruire la mappa e cercare dove viene configurata la memoria. **Non giustifica riempire di zeri tutta quella fascia nell'emulatore**: l'arresto attuale riguarda registri hardware, il cui valore ha un significato. [Risultati completi e ipotesi](S33_Limiti_Indirizzi_e_Stima_RAM.md).

## Nuova prova: confrontate le due risposte del registro hardware

Abbiamo fornito al simulatore le due risposte che cambiano la scelta del programma. In entrambi i casi, i due firmware proseguono nello stesso modo: scelgono uno di due registri hardware da leggere dopo. Sono stati eseguiti **36 casi isolati e 16 tentativi limitati di avvio**.

Questo chiarisce un'altra parte del percorso, ma non dimostra che la risposta simulata corrisponda alla Nikon. Il programma si ferma ancora alla lettura hardware successiva. Non abbiamo trasformato tutti i registri sconosciuti in zeri.

Il prossimo punto è ricostruire cosa rappresentano i due registri successivi e come viene usato il loro risultato. Avvio completo e recupero restano aperti: **NO-GO al flash**. [Prove tecniche](S33_Registro_Hardware_Bit7_e_Avvio.md).

## Ultimo risultato: il problema della tabella era nel simulatore

La prova isolata ha confermato il sospetto: il vecchio simulatore faceva ripartire un ciclo anche quando il programma chiedeva di uscirne. Abbiamo corretto questo comportamento in una variante separata e verificato **24 casi isolati e 8 tentativi limitati di avvio**.

Entrambi i firmware ora superano la scansione della tabella. L'azzeramento della memoria resta corretto. Il nuovo arresto avviene quando il programma legge un registro hardware di cui non conosciamo ancora il valore e il comportamento sulla Nikon.

È un passo avanti concreto: non abbiamo dovuto inventare altra memoria per nascondere il problema. **Non abbiamo ancora visto un avvio completo, quindi il flash resta NO-GO.** I valori iniziali usati dal test sono ipotesi di laboratorio, non misure della fotocamera. [Prove e limiti](S33_Correzione_Ciclo_LP_e_Avvio.md).

## Avanzamento sull'avvio: corretto un limite del simulatore

Abbiamo corretto il modo in cui il simulatore legge i risultati dei confronti della CPU. Prima poteva leggere un valore vecchio o mancante. La correzione è stata controllata con96 casi sui flag,96 controlli su un altro registro e3 sequenze con il confronto reale.

Nei16 nuovi tentativi limitati di avvio, entrambe le varianti superano quel punto. Fornendo anche una base iniziale ipotetica per gli interrupt, il programma principale arriva a887.305passi prima di fermarsi. **Questo numero non è una percentuale di avvio completato e non significa che la fotocamera parta.**

Il nuovo arresto mostra una scansione di tabella che continua oltre il previsto. Potrebbe dipendere da come il simulatore gestisce l'uscita dai cicli: verifichiamo questo prima di riempire la memoria mancante di zeri. I valori iniziali ipotetici non sono letture della Nikon.

Il risultato favorevole è che abbiamo rimosso un limite concreto del modello. Il motivo per cui rimane il NO-GO è che avvio completo e recupero non sono ancora dimostrati. [Rapporto tecnico e prove](STATUS32_BOOT.md).

## Nuova prova: usare 3 soltanto per superare il controllo

Abbiamo provato sul computer questa sequenza: stato 3 → confronto del firmware CMP3 → stato subito riportato a1. **Nel tratto eseguito funziona:** il controllo lascia passare verso HiddenMenu anche se il valore in memoria è già tornato a1.

Il motivo è semplice: il processore ha già registrato il risultato del confronto. Cambiare dopo quel momento il byte in memoria non annulla quella decisione, purché si conservino correttamente i registri e il risultato del confronto.

Il 20 ottobre sono stati rieseguiti42 scenari:28 precedenti e14 del nuovo profilo. Nove dei14 provano davvero la sequenza temporanea; gli altri cinque provano separatamente eventi del menu con stato 1 già impostato. Nel perimetro confrontato i risultati coincidono con la variante CMP1/stato 1. Quando HiddenMenu manca e il marcatore NAND esiste, riportare lo stato a1 evita l'apertura del menu NAND che avviene lasciandolo a3.

**Questo è un risultato favorevole, ma non rende sicura l'installazione.** A cambiare il byte è il simulatore: non abbiamo ancora costruito e verificato una modifica del firmware che faccia la stessa cosa sulla Nikon. Restano da controllare gli altri task e gli interrupt, l'avvio completo, il funzionamento completo del menu e il recupero dopo un problema di aggiornamento. I servizi del filesystem usati qui ricevono risposte simulate.

Abbiamo anche ricontrollato chi scrive lo stato: la funzione trovata è `0x129904`; il chiamante diretto confermato `0xC5DE8` le passa 1. Questo non esclude altre scritture attraverso puntatori o percorsi non ancora ricostruiti.

## Verifica precedente: cosa dimostra un checksum corretto?

Il 20 ottobre abbiamo eseguito sul computer la vera funzione che controlla la somma del caricatore contenuto nel pacchetto:

| Input del test | Risposta di quella singola funzione |
|---|---|
| Caricatore originale | Controllo superato |
| Un bit del corpo cambiato | Controllo fallito |
| Due modifiche che si compensano nella somma | Controllo superato |
| Indirizzo d'ingresso modificato, corpo invariato | Controllo superato |
| Puntatore nullo | Controllo fallito |

**Cinque casi eseguiti e controllati, senza scrivere sulla fotocamera.** Questo mostra che una somma corretta non certifica da sola che il programma sia quello giusto o che possa partire. Gli altri controlli dell'aggiornamento restano distinti: non abbiamo provato che l'intero aggiornamento accetterebbe gli input alterati.

## Cosa serve prima di poter cambiare risposta

| Domanda | Risposta attuale |
|---|---|
| Sappiamo esattamente cosa cambia nei file? | Sì, per i due campioni locali |
| La modifica cambia il ramo previsto? | Sì, nei casi eseguiti |
| Abbiamo dimostrato avvio e uso completo del menu? | No |
| Sappiamo che boot e calibrazioni restano protetti durante l'aggiornamento? | Non ancora |
| Abbiamo un recupero verificato dopo mancato avvio o aggiornamento interrotto? | No |

Non assegniamo una percentuale di rischio: mancano dati per calcolarla. Il rischio concreto rimasto è ritrovarsi con una fotocamera che non parte e senza un metodo di recupero dimostrato.

## Prossimo lavoro e fonti

Il prossimo punto utile è capire il registro hardware che ora ferma l'avvio e confrontare le sue possibili risposte nel simulatore. La correzione del ciclo è stata verificata nel perimetro descritto. Riempire la RAM di zeri non basta: potrebbe soltanto nascondere letture di dati che sulla Nikon hanno altri valori. Restano da chiarire gli scrittori indiretti dello stato, gli effetti di interrupt e altri task durante il 3 temporaneo, e il collegamento fra accensione, copia fisica del caricatore e recupero. La decisione resta **NO-GO**.

- [Nuova prova sul checksum](BOOT_CHECKSUM_HELPER.md), con script e risultati riproducibili.
- [Confronto integrale dei due firmware](S33_Confronto_Completo_CMP1_CMP3.md).
- [Prove del menu e loro limiti](MENU_DIFFERENTIAL.md).
- [Avvio con decoder corretto](ALIAS_FIX_BOOT.md).
- [Aggiornamento e componenti riscritti](SD_UPDATE_RECOVERY_PATH.md).
- [Metadati e caricatore TBIB](recovery_reset_report.md).
- [Decisione tecnica e requisiti mancanti](FINAL_GO_NO_GO.md).

Nessun aggiornamento, comando USB/PTP o scrittura di memoria/SD della Nikon è stato eseguito per queste verifiche. I file firmware sono stati preservati.

## Continuazione — candidato MSDC predefinito, separato dal precedente

La nuova [modifica del default USB](S33_USB_MSDC_Predefinito_Candidato_Offline.md) ha un byte di codice diverso e quattro byte d’integrità. Le prove48scenari/288fasi confermano la scelta di descrittore e ramo MSDC con servizi esterni simulati. Questa variante deriva dal campione originale V1.1 e non contiene il controllo HiddenMenuSD già installato dall’utente. Tasti9/11, menu e interprete possono ancora riportarePTP; ordine completo avvio e scrittori indiretti restano aperti. Il delta inverso ricrea l’originale sul computer, senza dimostrare ripristino della macchina. Nessuna nuova installazione o prova di mass storage; NO-GO per questo nuovo candidato invariato.
