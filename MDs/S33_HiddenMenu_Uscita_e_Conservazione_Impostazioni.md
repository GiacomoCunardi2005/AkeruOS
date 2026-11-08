# HiddenMenu: uscita e conservazione delle impostazioni

**Continuazione persistenza — 20 ottobre 2026:** [nuova ricerca](S33_HiddenMenu_Persistenza_MSDC_e_Inizializzazione_USB.md): resetOFF aggiuntivo aC5EEC, descrittori PTP/MSC collegati al selettore durante inizializzazione, guardia e interprete; 24setterRAM eBatGauge chiariti. Le precedenti formulazioni sul solo reset condizionale o sull’etichettaMSDC sono incomplete rispetto a questo checkpoint. Nessun salvataggio globale o massstoragehardware nuovo dimostrato.

20 ottobre 2026 — R0/R3/R4. Richiesta: uscire da HiddenMenu conservando MSDC e altre opzioni. **Non è ancora dimostrata una procedura “esci e salva tutto”.** Sono distinti il ritorno fra schermate, il mantenimento dei valori RAM nella stessa accensione e il salvataggio persistente dopo spegnimento.

## Risultato verificato

| Operazione software | Percorso verificato | Limite |
|---|---|---|
| Indietro da DEBUG MODE, evento0480 | callback7CFF90 →1453E4(20,0), radice HiddenMenu | Il callback non contiene un commit; gli effetti transitivi del framework non sono tutti chiusi. |
| Indietro dalla radice, evento0480 | callback7CC88C →1453E4(84,0), ResetCameraConfirmMenu | Non è un semplice ritorno al modo fotografico. |
| Evento2180 nella conferma |806CA4 →C9D84(1,1),CBDF8,177030 →SetupMenu78 | Ramo di ripristino; non chiamarlo “salva”. Nessuna conferma inviata alla macchina. |
| Evento2700 nella conferma |806CD4: controllo percorso con suffisso\HiddenMenu e tasto logico8;20 oppure78 | Alternativa senza chiamata diretta aC9D84 nel callback. Tasto fisico/etichetta visibile non ancora mappati. |

Il ramo2700 chiama prima12B0DC: se ritorna nonzero apre78. Altrimenti costruisce il percorso, chiama12BBB8 con r1=1 e legge il byte di uscita: solo byte=1 e getter16F920(8) nonzero riportano a20; gli altri casi aprono78. Non assumere che questo controllo usi il nostro file `modifica.modifica`: il suffisso verificato è `\HiddenMenu`. Il valore di ritorno della sonda è conservato inr13, ma la biforcazione mostrata usa il byte di uscita. Aprire SetupMenu non prova ancora ritorno all’inquadratura, conservazione di ogni opzione o assenza di effetti transitivi.

L’evento2700 è presente anche in altre schermate, ma questo da solo non dimostra quale tasto o scritta lo generi sulla S33. La prossima prova pratica richiede riconoscere sul display la scelta alternativa alla conferma; non suggerire combinazioni numeriche di tasti o una conferma reset.

## MSDC: stato runtime, nessun salvataggio nel setter

`MSDC Card:ON` corrisponde a1 nel byteRAM366B9D;OFF a2. La routine138F7C..138F94 scrive soltanto quel byte, oltre a salvare/ripristinare il frame dello stack. Non contiene chiamate, commit aCameraParam o accessiNAND. Questo esclude un salvataggio persistente **in quella routine**, non tutti gli eventuali scrittori, callback o servizi successivi del firmware.

Nel payload dati del campione e nel MainCode fornito il byte iniziale vale2. Il ramo di inizializzazioneC5F1A passa2 al medesimo setter quando entrambi i tasti logici9 e11 sono nonzero; non è una scrittura incondizionata a ogni boot. Questi elementi impediscono di promettere cheON sopravviva al riavvio. Un eventuale ripristino successivo da archivio non è stato escluso globalmente.

Il callback di ritornoDEBUG→radice non azzera esplicitamenteMSDC. È ragionevole verificarne il mantenimento nella stessa accensione, ma non è stato eseguito un ciclo UI completo con osservazione della RAM. La precedente enumerazione reale PTP conON sul display non prova applicazione della modalitàmassstorage né persistenza: [USB e limiti](S33_USB_MSDC_e_Accelerazione_Analisi_OS.md#osservazione-usb-reale--20-ottobre-2026).

Le altre voci DEBUG/IQ/CALI possono avere contratti diversi: RAM, parametri persistenti, esportazione suSD o calibrazione. È stato chiesto all’utente l’elenco esatto dei nomi modificati. Non esiste in questa verifica una dimostrazione di “salva tutte le impostazioniHiddenMenu”; non creare patch o riscrittureNAND per ottenerla senza un nuovo progetto verificato.

## Nuovi file ClockSettings e PerfLog

Le copie ora fornite in `/home/jack/Documenti/` hanno gli stessi hash delle copie già archiviate e analizzate in [Clock/Perf](S33_ClockSettings_PerfLog_e_Avvio_Osservato.md). Sono stati ricontrollati entrambi gli originali e le copie archiviate, senza duplicare l’analizzatore.

ClockSettings espone12stati/180valori tutti zero di una tabella software; non misura frequenze. PerfLog contiene37eventi di avvio e2avvisi di etichette non definite: non è una traccia completaCPU o delle azioni inHiddenMenu e non registra un commit delle opzioniMSDC. Il rapporto già esistente contiene le verifiche storiche dettagliate; non sono state rieseguite qui le sue13finestreGNU o le prove successiveNAND/loader.

## Riproduzione e copertura

```bash
python3 Python_Trace_Scripts/s33_verify_hiddenmenu_exit_settings.py
```

[Evidenze](../Risultati/HiddenMenu_Uscita/20261020T172250Z/verified_evidence.json), [GNU](../Risultati/HiddenMenu_Uscita/20261020T172250Z/gnu_verified.txt). Esito `PASS_BOUNDED_EXIT_AND_MSDC_STORAGE_CHECKS`:8finestreGNU,24controlli di istruzioni, recordeventi e pool, valore inizialeMSDC e hash dei2log. Tutte le finestre e i dati controllati coincidono conMainCode.dmp;16payload verificati dagli helper. Firmware originale, dump e strumentiGNU ricontrollati invariati.

Si tratta di verifica statica; nessuna nuova emulazione UI, azione sulla fotocamera, flash o modificaGNU. Le prime finestre esplorative che attraversavano pool/dati sono state rifiutate dall’helper; quelle finali sono riancorate agli ingressi esatti. Il vecchio test dell’evento0480 resta storico, distinto daquesta verifica.

**Prossimo:** identificare la scelta visibile che genera2700 e seguire l’uscita daSetupMenu; per la conservazione dopo spegnimento servono i nomi delle altre opzioni e i rispettivi percorsi persistenti. Non confermare un ripristino per cercare di salvare. Circa10% funzionaleAkeruOS invariato; nessuna garanzia nuova di recupero.

## Continuazione: ramo di annullamento eseguito — 20 ottobre 2026

La richiesta successiva ha esteso la verifica dal solo disassemblaggio all’esecuzione del callback originale806CD4, con le sue istruzioni e la concatenazione stringhe32DE00 originali. [Script](../Python_Trace_Scripts/s33_test_hiddenmenu_cancel.py), [proveCPU](../Risultati/HiddenMenu_Uscita/CPU_20261020T173202Z/verified_evidence.json), [24casi](../Risultati/HiddenMenu_Uscita/CPU_20261020T173202Z/protocol_cases.json).

Sono simulati esplicitamente cinque servizi: prefisso delvolume12B0DC, sondaattributi12BBB8, gettertasto16F920, aperturaoggetto1453E4 e guardiaresetC9D84. L’aperturaoggetto è un registratore: **il framework UI e i suoi eventi di chiusura/ingresso non vengono eseguiti**. Stack, record del chiamante e valoriMSDC sono di laboratorio, non letti dalla macchina. Non è una nuova build del firmware o del simulatore.

Le24combinazioni incrociano esito prefisso0/1/FFFFFFFF, byteattributi0/1, statotasto8=0/1 eMSDC1/2. Risultati:2richieste20 e22richieste78; nessuna chiamatareset, stack ripristinato eMSDC invariato in tutti i casi. Nei casi con prefisso riuscito, la stringa attraversata è esattamente `B:\HiddenMenu`, costruita usando la concatenazione originale. Il caso reale può usare un prefisso diverso: `B:` è l’input simulato.

Ricontrollati113PC originali eseguiti controMainCode.dmp; il manifest conserva hash degliinput epatch solo nel fixtureCPU. Il primo tentativo si è fermato leggendo99F26C perché il payload5, che contiene la stringa, non era mappato; aggiunto il payload reale, senza riempimento fittizio. Il tentativofallito resta archiviato. La prova riuscita non dimostra residenzaUI completa, applicazioneUSB o salvataggio dopo spegnimento.

### Dal menu Impostazioni all’inquadratura

La callbackSetup8098B8 inoltra aldefault20E814, tabella3E8BB4. L’evento0200 è associato a20EA5C: seCAD5C restituisce1 eCAD30 non restituisce3, il codice chiede1453E4(1,0), oggettoCaptureLiveview secondo3F5904. Con altre condizioni può aprire7E oppure non aprire niente. Un controllo successivoCBA48 può inoltre inoltrare lo stesso evento aCaptureLiveview. **Non è quindi raccomandato come tasto d’uscita innocuo** senza conoscere il relativo pulsante e le conseguenze fotografiche. Il ramo è stato verificato staticamente, non eseguito nei24casi del callback2700.

### Quarto slot e limiti del pulsante fisico

La tabella comune77F69C..77F6BC associa580→631878,700→63195C,2180→631A38 e2700→631B14. Il gestore2700 usa slot3 (quarto) quando il layout non richiede un offsetdi pagina; in altre condizioni calcola lo slot dalla pagina. Questa è una corrispondenza di **slot logico**, non la prova che un determinato tasto fisico sia “No” nella conferma84. Non assegnare il tasto inferiore sinistro o altri pulsanti sulla sola base di questa tabella. La scansione lineare ha trovato anche istruzioni apparenti dentro dati; le prove finali usano finestre riancorate e non includono quei candidati come codice.

Il percorso pratico da cercare sul display è l’annullamento della richiesta di ripristino (eventuale voceNo/Annulla), senza confermare ilreset. L’associazione fra la scritta effettivamente mostrata e2700 resta da osservare. Non è un comando “salva tutto”: il mantenimento diMSDC è dimostrato solo nel callback isolato con servizi dichiarati, non dopo spegnimento o nell’intera transizioneUI.

### Quattro file aggiunti nella radice

Nuova verifica statica riproducibile estesa: [script](../Python_Trace_Scripts/s33_verify_hiddenmenu_exit_settings.py), [evidenze](../Risultati/HiddenMenu_Uscita/20261020T173302Z/verified_evidence.json),12finestreGNU/33controlliistruzioni, recordeventi e confronti integrali. Copie conservate nella cartella `fonti` delle evidenze; gli originali nella radice non sono stati spostati o cambiati.

| File | Contenuto/confronto |
|---|---|
|P1RES|11.691.542byte, identico all’intero payloadrisorse originale e all’intervalloNANDReserved[512:11692054]. Non nuove impostazioniRAM o archivioparametri.|
|NIKON001.DSC|512spazi, stesso hash della classificazione storica. Non contiene fotografie, impostazioni oistruzioni.|
|ClockSettings.csv|802byte, identico alCSV già analizzato;12stati/180zeri software.|
|PerfLog.txt|2.744byte, identico allog già analizzato;37marcatori, non tracciaUI delle modifiche.|

Una prima verifica esplorativa ha cercato ancheDUMPS/NIKON001.DSC, oggi assente in quella posizione. La verifica finale usa il file esplicitamente fornito nella radice e controlla tutti i suoi512byte; non ricrea vecchi percorsi. I contenuti non aggiungono una procedura di salvataggio.

**Prossimo utile:** collegare la scelta visibile d’annullamento a2700 e verificare il percorsoUI completo mantenendo la stessa accensione. Per il salvataggio persistente delle altre opzioni occorre il loro elenco; nessuna autorizzazione a reset, scrittureNAND o nuovo aggiornamento è dedotta da questa ricerca. Circa10% AkeruOS invariato.

## Continuazione: foto menu edetichettaREV

Le [23nuovefoto](S33_HiddenMenu_Hardware_Foto_e_Versioni.md#altre23foto-menu-operativi-e-stati-visibili--20-ottobre-2026) mostranoERRORCODE conREV:Dump2File & Exit eS2:Clear. Testo98425C,0480→7CD764→root20,chiusura4406→7CD688→export7CD784 ricontrollati nelMainfornito. Sono uscitaedump delsottomenuerrori,non uscita globale osalvataggioimpostazioni. Nessunafoto dellaconfermareset oNo/Annulla inquesta raccolta;non è superato illimitepratico delramo2700. Scriptstatico estesoe rieseguito:15finestre/36check,non nuoveproveCPU;queste ultime restano24con5servizisimulati.

## Continuazione: richiesta di formattazione nella schermata normale

L’utente riferisce un avviso di formattazione dopo alcuni pulsanti/scatto; rifiutandolo può spegnere. Non è ancora identificato dal testo il particolare oggetto UI. La voce «Switch Require formating» era soltanto fotografata: nessuna selezione riferita. La [nuova verifica](S33_Richiesta_Formattazione_Dopo_HiddenMenu.md) trova un percorso NAND in quella voce e un percorso normale candidato verso7B/Formatting4E, dipendente da stati del supporto. Non suggerire formattazione o reset per uscire/salvare; nessuna SD guasta, esclusione MSDC o responsabilità della patch dimostrata. Sei finestre/23 controlli statici appena eseguiti, nessuna nuova prova CPU/hardware.
