# S33 — MSDC predefinito: candidato offline e limiti verificati

20 ottobre 2026 — R0/R3/R4. Studio richiesto dall’utente: cambiare il default USB da PTP a MSDC conservando i backend Nikon, senza installare la modifica. Prosegue dal [rapporto MSDC e inizializzazione](S33_HiddenMenu_Persistenza_MSDC_e_Inizializzazione_USB.md).

**La modifica minima funziona nei percorsi di selezione provati:** a `0xC5EEA`, `mov_s r0,2` diventa `mov_s r0,1`. Dopo l’inizializzazione, i byte originali del costruttore scelgono il descrittore mass storage e il selettore backend chiama il ramo MSDC. Non occorre invertire i due consumatori USB per ottenere questo risultato locale.

È un **default modificato**, con gli override Nikon ancora operativi. Entrambi i tasti logici9/11 attivi riportano subito2; menu e interprete possono fare altrettanto. Sono controllati i quattro callsite attribuiti al setter, non dimostrata l’assenza globale di scritture tramite alias, copie o servizi annidati. Ordine reale di ogni tipo di avvio, enumerazione MSDC, disponibilità SD e recupero fisico rimangono aperti. Nessuna azione sulla macchina.

## Il file prodotto

- [BIN sperimentale, NON INSTALLARE](../Risultati/Firmware_sperimentali/USB_MSDC_Default/S33_USB_MSDC_DEFAULT_OFFLINE_NON_INSTALLARE.bin), [SHA-256](../Risultati/Firmware_sperimentali/USB_MSDC_Default/S33_USB_MSDC_DEFAULT_OFFLINE_NON_INSTALLARE.bin.sha256).
- Base: `OriginalSoftware_NikonS33_V1.1/firmware.bin`, 29.602.084byte, SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`.
- Candidato: stessi29.602.084byte, SHA-256 `af65ab0e66781c1a1036ab2349700e9d2110c6618738b02208da8b83c8813544`.
- È una variante separata del campione originale V1.1: **non contiene la precedente patch HiddenMenu con interruttore SD**. Il precedente candidato e i dump dell’utente non sono modificati.

Il valore iniziale dati a `0x366B9D` resta2. Cambia l’assegnazione eseguita in `0xC5EC0`; ciò serve proprio a superare quel reset successivo. Il collegamento reale deve comunque attraversare questa assegnazione prima di costruire la configurazione USB. Le prove seguono esplicitamente quell’ordine; non costituiscono tutti gli avvii del firmware.

| Offset nel contenitore | Prima | Dopo | Significato |
|---|---:|---:|---|
| `0x000002` | `4A` | `48` | word XOR del pacchetto |
| `0x0480D6` | `37` | `36` | somma RHIR del payload0 |
| `0x0482AE` | `DD` | `DC` | somma KHIR |
| `0x0482B2` | `22` | `23` | complemento KHIR |
| `0x0609A2` | `02` | `01` | CPU `0xC5EEA`, immediato di `mov_s r0` |

Sono **cinque byte diversi nell’intero contenitore**, di cui uno nel codice. L’istruzione di due byte passa da `02 D8` a `01 D8`. Tutti i16 checksum payload, KHIR/complemento e XOR sono controllati. Parser, sezioni e dimensioni coincidono; payload1–15, TBIB, P1RES e resto del file sono identici. I descrittori e i due backend USB sono invariati nel candidato pubblicato.

## Riproduzione ed evidenze

```bash
python3 Python_Trace_Scripts/s33_test_msdc_default_candidate.py
```

- [Script](../Python_Trace_Scripts/s33_test_msdc_default_candidate.py), [indice ultimo controllo](../Risultati/USB_MSDC_Default/latest.json).
- [Manifest del controllo riuscito](../Risultati/USB_MSDC_Default/20261020T202244Z/verified_evidence.json), [delta integrale e reversibilità](../Risultati/USB_MSDC_Default/20261020T202244Z/container_delta.json).
- [Disassemblaggio dell’istruzione dal payload candidato](../Risultati/USB_MSDC_Default/20261020T202244Z/candidate_instruction.log), [15 finestre originali riancorate](../Risultati/USB_MSDC_Default/20261020T202244Z/gnu_verified.txt).
- [48 scenari e sei fasi ciascuno](../Risultati/USB_MSDC_Default/20261020T202244Z/cpu_cases.json), [stub dichiarati](../Risultati/USB_MSDC_Default/20261020T202244Z/fixture_patches.json), [scrittori noti e limiti dell’inventario](../Risultati/USB_MSDC_Default/20261020T202244Z/known_overrides.json).

Esito `PASS_OFFLINE_DEFAULT_SELECTION_NO_GO_FLASH`: 24 scenari originali e24 candidati, ciascuno con sei fasi; totale288 fasi. Sono usati sei valori iniziali del selettore (`0/1/2/5/6/255`) e tutte le quattro combinazioni booleane dei tasti logici9/11. Due esecuzioni GNU terminano con exit0, rispettivamente54.479 e53.849 istruzioni nel profiler. Controllati330PC originali distinti, più l’istruzione modificata dichiarata, e il ripristino dello stack a ogni fase.

Gli strumenti sono quelli esistenti, usati in sola lettura. Nessun builder GNU o file di configurazione GNU modificato. Gli intermedi e le copie di laboratorio restano nei risultati. La prova precedente dei sei scenari MSDC e la scansione dei16payload sono riutilizzate come evidenze storiche con hash controllato, senza dichiararle rieseguite da questo comando.

## Descrittori: eseguito il costruttore e lo store originale

Nel test viene eseguito il corpo originale `0x139120..0x13926E`, compreso il ramo che legge `0x366B7C+0x21` e sceglie il descrittore. Sono originali anche `0x81DBA4→0x190C3C` e lo store del puntatore configurazione a `0x3680A4`, osservato dopo ogni costruzione:

| Selettore letto | Puntatore scritto | Interfaccia nei byte del descrittore |
|---:|---|---|
| 2 | `0x3900F0` | classe06, sottoclasse01, protocollo01: PTP |
| 1 | `0x3901B0` | classe08, sottoclasse06, protocollo50: mass storage |

Il test non si limita a selezionare un puntatore dal lato Python. Le istruzioni del firmware lo caricano e lo scrivono nella tabella RAM. I descrittori sono verificati integralmente per le rispettive lunghezze39/32byte e per i campi d’interfaccia.

## Backend e guardia

Sono eseguiti `0x138E9C`, il corpo originale `0x138EFC` e il selettore `0x139658`. Il primo imposta la guardia `0x366BB2` prima di chiamare gli altri. Gli ingressi dei backend `0x1394E0`/`0x13959C` sono sostituiti da registratori nel solo laboratorio: registrano rispettivamente2/1. I loro corpi non inizializzano davvero USB in questa prova.

Due richieste consecutive con guardia iniziale0 producono una sola chiamata backend; guardia1 blocca la ripetizione. Nel codice reale il padre `0x13901C` contiene lo store che azzera quella guardia a `0x139092`. Il suo intero ciclo non viene eseguito qui; le successive ripartenze del test impostano esplicitamente guardia0 come precondizione di laboratorio.

| Fase dello scenario | Riscontro |
|---|---|
| 0: inizializzazione → descrittori → due richieste backend | default originale2; candidato1, salvo entrambi i tasti attivi; una sola chiamata backend |
| 1: toggle menu → ricostruzione diretta descrittori → richieste backend | selettore e descrittore cambiano; guardia1 conserva il backend precedente |
| 2: guardia0 di laboratorio → richieste backend | backend riallineato al selettore, una nuova chiamata |
| 3: helper interprete con parametro1 → costruzione → guardia0 → backend | selettore2, descrittore e ramo PTP |
| 4: helper interprete con parametro0 → costruzione → guardia0 → backend | selettore1, descrittore e ramo MSDC |
| 5: nuova inizializzazione → costruzione → guardia0 → backend | il rispettivo default è reimposto, con override dei tasti ancora valido |

La fase1 è una sequenza interna predisposta dal test, **non un effetto automatico del toggle UI**: il toggle non chiama il costruttore. Mostra perché cambiare il byte dopo una configurazione già costruita non basta per applicare coerentemente una nuova modalità. Non è una procedura di disconnessione o riconnessione fisica verificata.

## Override controllati

| Scrittore attribuito | Comportamento conservato |
|---|---|
| `0xC5EEC` | dopo la modifica passa1 al setter `0x138F7C` |
| `0xC5F1A` | passa2 quando entrambe le interrogazioni dei tasti9/11 sono nonzero; abilita anche il flag diagnostico distinto tramite `0x138FB0` |
| `0x7D02FC` | toggle DEBUG: precedente2→1, altrimenti→2 |
| `0x80D61C` | helper di USBDevModeSwitch: parametro esattamente1→2, negli altri rami→1 |

Il collegamento interprete nome/indice `0x6E` e dispatcher è nel [rapporto precedente](S33_HiddenMenu_Persistenza_MSDC_e_Inizializzazione_USB.md). Qui viene eseguito l’helper, non l’interprete completo né uno script SD. Non viene inventata una sintassi o una procedura per invocarlo sulla macchina.

Nel candidato,18 scenari della prima fase scelgono MSDC e6 scelgono PTP per l’override di entrambi i tasti; tutti i24 originali scelgono PTP in quella fase. I numeri9/11 sono identificatori logici: nessuna combinazione fisica è dimostrata.

**Limite dell’audit degli override:** la ricerca precedente delle parole LE/ARC e delle chiamate lineari nei16payload conserva candidati; sono attribuiti e verificati questi quattro callsite del setter. Restano da analizzare scritture tramite base+offset, copie della struttura `0x366B7C`, callback indirette, servizi d’inizializzazione simulati e ordine dei diversi avvii. Non è lecito chiamare questo un inventario completo di qualunque scrittura futura.

## Portata del modello

Il corpo completo di `0xC5EC0` viene percorso, con i rami dei tasti. Sono però simulati20 servizi esterni, la lettura dei tasti, la sorgente seriale, i campi temporali, lo stato USB, i backend e la continuazione UI. Il manifest elenca ogni sostituzione. La seriale di laboratorio è `12` e i campi temporali sono zero; non sono valori letti dalla fotocamera. Il toggle entra dal proprio case con frame di laboratorio.

L’esecuzione verifica quindi **scelta, store e flusso locale**, non un boot integrale, le side effect di tutte le chiamate annidate o un dispositivo MSDC funzionante. Nel pacchetto pubblicato non ci sono gli stub: il Main0 eseguito dal test deriva dal nuovo contenitore, poi soltanto la copia di laboratorio riceve le sostituzioni dichiarate.

I tentativi falliti precedenti sono conservati: percorso errato del modulo checksum, collisione di nome fra stub e buffer seriale, formato diverso dell’annotazione GNU. Sono corretti nell’allestimento del verificatore; non erano difetti del firmware e non sono stati aggirati modificando altri opcode nel candidato.

## Recupero: reversibilità del file e condizioni prima del flash

La patch inversa del delta ricostruisce byte per byte il campione originale e il suo SHA-256. Questo è un **rollback del file sul computer**. Non garantisce che la Nikon possa accettare o riscrivere quel file dopo un problema.

Prima di qualunque installazione rimangono queste condizioni verificabili:

| Condizione | Prova attuale | Cosa manca |
|---|---|---|
| Identità e rollback offline | delta completo, checksum, ricostruzione esatta dell’originale | nulla per la sola trasformazione del file |
| Compatibilità con l’updater residente | nessuna nuova esecuzione dell’updater in questo studio | percorso e controlli della versione realmente residente, inclusa eventuale reinstallazione |
| Trasporto di ripristino indipendente dal nuovo USB Main | TBIB immutato nel pacchetto | ingresso raggiungibile se Main non avvia o USB non enumera; originalità del TBIB non prova che non venga riscritto |
| Copia BootCode recuperabile | analisi scanner/loader nei rapporti R4 | ROM/reset, selezione e sopravvivenza delle copie dopo interruzione |
| Dati specifici della macchina | dump forniti preservati e analisi NAND/ECC già documentata | backup fisico completo e ripristino verificato di calibrazioni/metadati |
| SD esposta in modo coerente | scelta del descrittore mass storage provata offline | gestione del supporto, proprietà del filesystem e corretta enumerazione sul dispositivo |

Riferimenti: [opzioni di recupero](RECOVERY_OPTIONS.md), [scanner e limite al reset](recovery_reset_report.md), [loader NAND dai dump](S33_NAND_P1IDSTR_Blocchi_Boot_e_Handoff_TBIB.md), [sicurezza spiegata](S33_Sicurezza_Flash_Spiegata_Semplice.md). Sono fonti locali lette, non nuove prove di recupero. L’osservazione hardware già registrata è PTP con ON riferito dall’utente, poi assenza della macchina; non è una prova MSDC riuscita.

**Decisione attuale: candidato offline verificato nella portata descritta, NO-GO per l’installazione.** La richiesta corrente autorizza lo studio e il file sperimentale, non USB/PTP/reset/scritture RAM/flash/SD sulla fotocamera. Nessun nuovo canale di recupero viene promesso.

## Continuazione

Prima di ampliare la modifica, seguire i servizi che preparano `0x366B7C` e i suoi alias/copie, poi l’ordine `0xC5EC0 → costruzione USB → backend` nei diversi ingressi di avvio. L’override dei tasti è già dimostrato; va conservato come comportamento esplicito del candidato a un solo default. Per una futura verifica sul dispositivo restano recupero e proprietà SD. La ricerca sul salvataggio di tutte le altre impostazioni è un ramo distinto. Circa10% funzionale AkeruOS invariato.

## Continuazione — significato di USBDEVMODE e struttura

Il [chiarimento richiesto sugliMD](S33_USBDevModeSwitch_Identita_e_Scritture_Struttura_USB.md) attribuisce USBDEVMODE a USBDevModeSwitch, non al flag diagnostico.808prove CPU su setter locali e helper confrontano tutti i64byte della struttura; gli altri campi provati non sovrascrivonoMSDC. È inoltre collegata la creazione di ComMgrTask tramite138E4C, prima del defaultC5EEA: attesa evento1 poi13901C. Restano da seguire produttori e tempi della notifica; non è ancora dimostrato l’ordine di ogni avvio. Il candidato e il suo hash sono invariati, senza nuova installazione.

## Continuazione — notifica e guardia condizionale, 20 ottobre 2026

Il [nuovo rapporto ComMgr](S33_ComMgr_Notifica_USB_Ordine_e_Guardia_Condizionale.md) aggiunge 156 casi originali con servizi esterni simulati: il backend precede la notifica; stato grezzo 1/3 invia evento applicativo4109, gli altri provati pubblicano ComMgr02100001/bit1, anche con errore backend. Il reset locale della guardia139092 è saltato dal ramo139084 quando entrambi i predicati1399D8/1399FC sono nonzero. 139CF4 è un registratore, quindi i suoi effetti reali sulla guardia restano aperti. La matrice precedente del candidato imponeva l’ordine descrittori→backend e il reset delle fasi successive: non prova l’intero avvio. Nessun BIN o hardware modificato. Proseguire su4109, predicati e ordine task/default prima di concludere sul comportamento globale.

## Continuazione — evento 4109 e callback, 20 ottobre 2026

Il [rapporto successivo](S33_USB_Evento_4109_Coda_Default_e_Callback_Guardia.md) verifica606casi: accodamento/pop originali, default scelto dal test con quattro richieste UI e coda piena senza inoltro, mentre138EFC restituisce l’esito backend. Non è un’esecuzione di WindowMgr o dell’oggetto corrente. I predicati1399D8/FC leggono i byte366BA1/A2;139CF4 chiama il callback366B90 registrabile da13A1A4, inizialmente nullo. Servono routing reale4109, registrazionecallback e scrittoriA2, quindi ordine task/default. Candidato e hardware invariati, NO-GO confermato.

## Continuazione — UI57 e callback conservato, 20 ottobre 2026

La [verifica successiva UI57](S33_USB_UI57_Ingresso_Callback_PTP_e_Ordine_LoadLater.md) aggiunge328casi: evento440E/arg1 dell’oggetto57 richiede il backend con guardia; ingresso4405 contiene un altro controllo del selettore a224660. Nel profiloC86CC!=10/CB5A8=1/1398E8=0,PTP registraD1870 in366B98,MSDC salta il setter e conserva il precedente; non è un azzeramento. ConC86CC=10 il setter è saltato perentrambi.366B98 è distinto da366B90. Staticamente il callbackC6234 che raggiungeC5EC0 è registrato in365618 e chiamato dal coordinatore Load Later dopoC5910, prima dei gruppi successivi; concorrenza e attivazione dell’oggetto57 non provate. Servono produttori440E,usi callback e ordine avvio. Candidato e hardware invariati.

## Continuazione — trigger UITimer originale, 20 ottobre 2026

La [verifica del timer UI57](S33_USB_Timer_UI57_Registrazione_Scadenza_e_Limiti.md) esegue24casi con registrar,tasktimer,lettorecampo14503C,dedup,coda,pop e cancellazione originali. Timer1 viene registrato solo conwordoggetto+18zero;tabellapiena impedisceallocazione senza controllo delritornoUI,39vocioccupate consentono timer1ma non4. Clockzero/passo minimo50 euscitacontesto laboratorio non sono scheduler o tempo fisico. Dopopop iltest sceglie esplicitamente callback57;8casi raggiungono backend simulato. Servono attivazione/creazione57 eprovenienzacampo+18 rispetto aldefault LoadLater. BIN e hardware invariati.

## Continuazione hardware — installazione riferita e PTP, 20 ottobre2026

L’utente riferisce installazione del candidatoMSDC con messaggio completato e accensione manuale prima delcavo. La [nuova osservazione hardware](S33_USB_MSDC_Default_Installazione_Riferita_e_PTP_Hardware.md) conserva10campioni PTP06/01/01 senza discoNikon; non è stato riletto il codice flash/runtime. I precedenti risultati restano prove locali, non dimostrazione diMSC operativo. Prossimo confronto: collegamento da spenta;nessun altroflash/reset/formattazione per questa osservazione.
