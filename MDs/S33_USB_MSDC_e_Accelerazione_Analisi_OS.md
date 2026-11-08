# USB MSDC e dati utili per ricostruire il sistema operativo

**Continuazione persistenza — 20 ottobre 2026:** [nuova ricerca](S33_HiddenMenu_Persistenza_MSDC_e_Inizializzazione_USB.md): resetOFF aggiuntivo aC5EEC, descrittori PTP/MSC collegati al selettore durante inizializzazione, guardia e interprete; 24setterRAM eBatGauge chiariti. Le precedenti formulazioni sul solo reset condizionale o sull’etichettaMSDC sono incomplete rispetto a questo checkpoint. Nessun salvataggio globale o massstoragehardware nuovo dimostrato.

**Uscita e conservazione,20 ottobre 2026:** [verifica dedicata](S33_HiddenMenu_Uscita_e_Conservazione_Impostazioni.md): ritornoDEBUG→root distinto dalla confermareset della radice. SetterMSDC soloRAM; nessuna procedura salva-tutto o conservazione alriavvio dimostrata. Non confermare reset per salvare.

20 ottobre 2026 — R0/R3/R4. **Fra le sette voci HiddenMenu, la pista concreta per una modalità USB legata alla scheda è DEBUG MODE → MSDC Card:OFF/ON.** Nuova verifica statica con11finestreGNU, tutte confrontate anche conMainCode.dmp fornito dall’utente. Non è una prova USB sul dispositivo e non dimostra accesso allaRAM.

[Script](../Python_Trace_Scripts/s33_trace_debug_msdc.py), [manifest](../Risultati/USB_MSDC/20261020T135027Z/verified_evidence.json), [GNU](../Risultati/USB_MSDC/20261020T135027Z/gnu_verified.txt). Gli originali e il dump sono ricontrollati invariati; strumentiGNU usati solo inlettura.

## Osservazione USB reale — 20 ottobre 2026

Dopo la richiesta di collegamento l’utente conferma esplicitamente che il display mostra **MSDC Card:ON**. La prima enumerazione dell’agente identifica **04b0:035d, NIKON DSC COOLPIX S33-PTP**, versione dispositivo1.10, High Speed480Mbps. Unica configurazione e unica interfaccia: classe6 Imaging, sottoclasse1, protocollo1 PTP; endpoint81/02 bulk e83 interrupt. `gphoto2 --auto-detect` vede USB PTP Class Camera suusb:003,022. Quindi in quella lettura la Nikon espone **PTP**, non un’interfaccia mass storage, anche conON riferito dall’utente. Non è dimostrato quando il selettore venga applicato o se la connessione osservata sia stata inizializzata prima del cambio.

Il disco119,1GiB già montato su `/run/media/jack/disk` appartiene al dispositivo **05e3:0764**, Generic MassStorageClass, distinto dalla Nikon. L’agente non lo ha montato né letto.

Durante la ripetizione destinata ai log, la Nikon risulta **assente** sia dai descrittori sia da sysfs/autodetect; un ulteriore `lsusb -d 04b0:` conferma assenza. Non si deduce la causa: cavo, stato della macchina e gestioneUSB non distinti. Le prime letture restano nei risultati strumenti della chat e sono trascritte nel manifest, senza spacciarle per rawlog salvati; i fileTXT conservati documentano la ripetizione senzaNikon.

[Evidenze e comandi riproducibili](../Risultati/Hardware/USB_MSDC_20261020T135646Z/verified_evidence.json), [script di sola enumerazione](../Risultati/Hardware/USB_MSDC_20261020T135646Z/reproduce.py). Nessuna sessionePTP, comando vendor, reset, letturaRAM o scrittura sulla fotocamera. Il controlloassert che richiedeva presenzaPTP al salvataggio non è passato perché la macchina era già assente: non è un errore nascosto né una prova stabile riuscita. Prossimo: ripetere enumerazione con collegamento stabile e stato display noto; accessoRAM e recupero restano non verificati.

## Percorso della voce MSDC

| Elemento | Riscontro nei byte |
|---|---|
| Menu | ID0x36, DEBUG MODE, descrittore0x987AF8, main0x7CFB94 |
| Voce | Indice36 su39, record0x987A14, dato0x88, testo inizialeMSDC Card:OFF |
| Dispatcher |0x7CFFB0, lookup del dato selezionato, tabella signed16 a0x7CFFFA |
| Entrata per dato0x88 |0x7D02EE, derivata come base+2×entry |
| Getter |0x138F70 legge il byte puntato dal pool0x138F78 |
| Selettore |0x366B9D |
| Setter |0x138F7C, scrittura byte a0x138F88 |
| Consumatori USB |0x13930C/0x1393F0 leggono base0x366B7C+33 e passano il valore a0x81DC38 |

La sequenza confronta il valore precedente con2, costruisce1 se era2 e2 negli altri casi, chiama ilsetter e rilegge. I pool0x7D0404/08 selezionano le stringhe aggiornate:

| Stato precedente | Nuovo valore | Testo visualizzato |
|---:|---:|---|
|2|1|MSDC Card:ON|
|1|2|MSDC Card:OFF|

Questa tabella deriva dalle istruzioniGNU verificate, non da una nuova emulazione o da un esperimento sul PC. La sola osservazione del nome sarebbe stata una pista debole; il collegamento alla variabile letta dal ramoUSB è il riscontro aggiuntivo.

L’etichettaMSDC Card suggerisce una modalità di archiviazione USB della scheda. **Supporto effettivamente esposto, descrittori USB, diritti e comportamento sul PC restano da osservare.** Non sono ancora ricostruiti il momento di applicazione della modifica, la reinizializzazione e la persistenza al riavvio. Non è una procedura pratica “attiva e riavvia” già verificata: il codice di avvio scrive a sua volta questo selettore e un riavvio potrebbe sostituire la scelta.

## File sulla SD e diagnostica del firmware sono capacità distinte

Il flag dei servizi diagnostici verificato in precedenza è **0x366B9F**, diverso dal selettoreMSDC **0x366B9D**. Il setter è0x138FB0; nel ramo0x139348 il valore1 abilita due chiamate di registrazione, dopo altre guardie. I percorsi noti che chiedono1 sono gli stati dei tasti logici9e11 durante inizializzazione e l’oggettointernoCalibrationID0x5C/evento4405.

**CalibrationID0x5C non è CALI.MENU ID0x26.** Quest’ultimo porta a calibrazione batteria, iris, pixel, ISO ealtro. Il collegamento pratico dal menu visibile all’oggetto5C non è dimostrato; non fornire combinazioni di tasti fisici dedotte dai soli numeri logici.

Avere una scheda accessibile come disco non implica leggere o scrivereRAM, accedere a un debugger, eseguire codice o usare comandi vendor. Nemmeno la registrazione statica di un handler prova che sia disponibile sulla connessione attuale. Il precedente controlloUSB inHiddenMenu non enumerava laNikon; non sono state svolte nuove proveUSB inquesta verifica.

## Come leggere le sette voci

| Voce | Utilità e collegamento USB verificato |
|---|---|
|INFO MENU|Versioni, identificativi e stato diagnostico. Nessun interruttoreUSB identificato inquesta analisi.|
|ERROR CODE|Errori e contesto diagnostico; non è stato collegato al selettoreMSDC.|
|CALI.MENU|Calibrazioni; oggetto diverso dalCalibration5C della pista diagnosticaUSB.|
|IQ DEBUG|IncludeLog Clock Settings e opzioni di esportazione dati immagine. Utili come piste, effetti da verificare singolarmente.|
|DEBUG MODE|ContieneMSDC Card ePerf Log. La prima è ora collegata al selettoreUSB;Perf Log non è una tracciaCPU già dimostrata.|
|NAND TOOL|Dump di programma, boot, parametri econfigurazione già raccolti; comprende anche scritture/cancellazioni. Non è necessario usarle per l’analisi attuale.|
|SKY TOOL|Test di acquisizione,SD egestione risorse. Non emerge daquesta verifica un’abilitazioneUSB.|

## Che cosa accelererebbe davvero la ricostruzione dell’OS

1. **SnapshotRAM runtime con contestoCPU e momento noto.** Possiamo correlare task, stack, code eventi, puntatori, oggetti attivi ebuffer con il codice. Un dump soltanto statico non dà questi valori correnti. Servirebbero almeno base/intervallo/ora logica dell’acquisizione ePC/SP/GP, senza inventare contenuto di zone non lette. Fra i14file attuali nessuno è identificato comeRAMruntime.
2. **Log correlati a operazioni precise.** Avvio, ingresso menu, scatto, salvataggio euscita, distinguendo cosa ha realmente eseguito la macchina. Perf Log eLog Clock Settings sono voci da studiare nel codice prima di attribuire formato, destinazione eassenza di effetti collaterali.
3. **Configurazione memoria/periferiche decodificata.** BFNSetting eNANDPartition ora forniscono dati reali. CollegareDDR_SIZE_ID0x120, impostazioniDDR/PLL e lettori delboot ai registri chiarirebbe il modello dell’emulatore. Non assumere che il valoreID sia già una capacitàRAM.
4. **Simboli, mappa del linker o sorgenti del medesimo build, se reperibili.** Darebbero nomi econfini alle funzioni. Non sono stati identificati inquesta verifica e non sono un requisito per proseguire con i dump disponibili.

La priorità concreta è studiare il percorsoMSDC e l’attivazione diagnostica separatamente, poi stabilire se un servizio effettivamente esposto offra lettureRAM. In parallelo logclock/configurazioneDDR possono ridurre i modelli ipotetici. Nessuna percentuale di accelerazione è stimabile dalle evidenze attuali.

## Controlli e prossimo passo

```bash
python3 Python_Trace_Scripts/s33_trace_debug_msdc.py
```

Verificati identità16payload, recordMSDC,39elementi, tabella signed16,11finestreGNU, selettore/pool/stringhe/callsite euguaglianza diogni finestra con ilMainCode fornito. Distinti i dueflag e i due oggettiCalibration. Nessuna modificaBIN, USB ocalibrazione e nessuna scrittura nelle cartelleGNU.

Prossimo punto: tracciare applicazione delselettore e descrittori/backend associati, poi confronto di enumerazione sulPC sotto condizioni esplicite. AccessoRAM, debugUSB e recupero non dimostrati; circa10% funzionaleAkeruOS invariato.

## Continuazione — modifica del default verificata offline

[Il candidato separato V1.1](S33_USB_MSDC_Predefinito_Candidato_Offline.md) cambia un byte di codice aC5EEA e quattro byte d’integrità.48scenari/288fasi eseguono il costruttore e lo store originale del descrittore, poi registrano il ramo backend selezionato. DefaultMSDC provato con override conservati; entrambi i tasti9/11 lo riportanoPTP. Nessuna nuova enumerazione USB o prova della SD come disco. Il file non combina la precedente patch HiddenMenuSD e resta NON_INSTALLARE; recupero fisico aperto.
