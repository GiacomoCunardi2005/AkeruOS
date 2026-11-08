# NAND dal PC: parser, buffer privato e contenitore offline

> **Superato: difetto trovato nel contenitore qui discusso.** Il candidato52f8714d…bc9ac9 e i precedenti con offset spostati sono esclusi: i caricamenti differiti usavano ancora offset fissi originali. I test qui restano validi soltanto nel loro ambito. Leggere la [correzione e le nuove prove](S33_NAND_PC_Offset_Differiti_Corretti_e_Client_Linux.md).

21 ottobre 2026 — R0/R3/R4. Il nuovo handler RAW è collegato ed eseguito offline agli indirizzi del candidato; esiste un contenitore completo con integrità verificata. **NON INSTALLARE: l’obiettivo resta attivo.** Non è ancora provato l’accesso fisico oltre22MiB né un aggiornamento pronto per la fotocamera.

## Fotocamera rilevata di nuovo

Alle08:55UTC la Nikon è ricomparsa come bus003/device033. [Dieci campioni](../Risultati/Hardware/MSDC_Default/20261021T085557Z/observation.json):04b0:035d, prodottoS33-MSDC, interfaccia08/06/50, driverusb-storage, sda e sda1, nessun errore. Il disco misura23.068.672byte=45.056settori/22MiB; sda1 èvfat montata dal sistema a`/run/media/jack/disk`. Questa raccolta sostituisce come stato corrente l’assenza delle08:20UTC, conservata come osservazione distinta. Non dimostra SD assente o hash della flash.

Sono state lette enumerazione, descrittori cached, sysfs e metadati Linux. Nessun settore, comando vendor, aggiornamento o scrittura sulla fotocamera è stato eseguito.

## Controllo della lunghezza prima della copia CDB

Il parser originale820C00 copia`CBW[14]&31` verso il bufferCDB da16byte del chiamante. Il nuovo [controllo assembly](../S33-sections/usb_nand_readonly/cbw_length_guard.s) accetta soltanto il byte completo1..16, prima della copia. Il collegamento sostituisce4byte a820C88: lettura della lunghezza e maschera. Le lunghezze valide riprendono a820C8C; quelle invalide tornano da820C96 col codice02100102 già usato dal parser perCBW invalido. La gestioneBOT degli errori resta originale.

[Verificatore](../Python_Trace_Scripts/s33_verify_usb_bot_readonly.py), [prove agli indirizzi candidati](../Risultati/USB_SCSI/Accesso_NAND_PC/bot_main_extension_latest.json): **256 valori di lunghezza** verificati, nessuna copia fuori dal buffer, canarini eSP preservati. Le transazioni complete includono rifiuti per0,17,31,32,255. La normale INQUIRY Nikon conCDB6 resta funzionante e restituisce4MP-CARD. Nessuna modifica alla lista dei controlli direzione820E26.

## Handler reale e buffer privato

[akrn_scsi.c](../S33-sections/usb_nand_readonly/akrn_scsi.c) collega il nucleoC e il wrapperNikon. Controlla direzione esattamenteIN, LUN0, CDB16, identità con laCBW corrente, lunghezza2112 e residuo coerente. Geometria, coordinate, magic/versione/riservati restano controllati dal wrapper e dal nucleo. Il lettore è25F428; l’invio è1908DC. Errori o invii incompleti produconoCSWfallito, con residuo aggiornato senza sottrazioni fuori limite. Le informazioni sense usano5/24 per richieste invalide e3/11 per errori del percorso di lettura, come i valori dei gestori originali controllati.

Il buffer è un array privato di528word, **2112byte**, incluso nell’estensione dell’immagine caricata. Non punta alla risorsa1E Nikon. È una scelta di durata:1394B0(1) rilascia1E tramite12A738 senza azzerare il campoUSB+34; una query o un vecchio puntatore non garantiscono il possesso dopo la chiusura. Non serve ampliare lo stack del task con una paginaRAW.

Il supporto freestanding [runtime.c](../S33-sections/usb_nand_readonly/runtime.c) fornisce soltanto memset, richiesto dalle inizializzazioni aggregate generate dal compilatore. Le build usano`-mno-sdata`; non richiedono un nuovo valoregp.

**Chiarimento della geometria:** il campo del contesto è ora`expected_blocks_per_chip`. Il confronto verifica il profilo configurato del driver, non una misura fisica indipendente. Il nuovo handler si aspetta stride512,64pagine e2048+64byte; profili incompatibili vengono rifiutati, inclusi quelli oltre il limite di riga16bit o con cicloindirizzo aggiuntivo non supportato. La precedente richiesta di una conferma fisica esterna era un vincolo prudenziale del prototipo, non una prova già disponibile o un requisito dell’utente. La capacità fisica effettiva e il runtime della fotocamera restano da riscontrare: i512blocchi non diventano una nuova misura hardware.

## Collegamento agli indirizzi del candidato

| Oggetto | Intervallo/indirizzo CPU |
|---|---|
| Estensione payload0 |35BC00..35CE00 escluso,4608byte/9settori |
| Nucleo |35BC00 |
| HandlerFF |35BD40 |
| Buffer privato |35C0A4..35C8E4 escluso |
| ControlloCDB |35CC00 |
| Hook parser |820C88,4byte |
| PuntatoreFF |9A3460→35BD40 |
| DefaultMSDC conservato |C5EEA:02D8→01D8 |

Il payload0 originale termina a35BC00; il successivo inizia a360800. L’estensione proposta vi rientra geometricamente e viene inclusa nella copiaMain del test. **Questo non prova che l’intervallo sia libero da accessi calcolati, risorse runtime o alias.** Codice e buffer restano collocazione sperimentale finché residenza e proprietà non sono stabilite.

Comando eseguito:

```bash
python3 Python_Trace_Scripts/s33_verify_usb_bot_readonly.py --main-extension
```

Esito: **30 transazioni complete e256prove del parser**, exit0. CBW→parser→dispatcher→handlerC→wrapperC→25F428 originale→invio→CSW. Prima e ultima pagina, NANDnonpronta, geometrie inattese, campoLUN riservato, lunghezzaFFFFFFFF, erroriNAND/USB e invio corto sono controllati. Lo stack è preservato e l’immagine non cambia fuori dal buffer privato; guardia finale intatta. I dati del primo blocco sono interleaved512+16, gli altri2048+64.

Mutex, controller, attesa, trasferimenti dati/spare, USB ed eventi sono recorder di laboratorio. I byte delle pagine sono pattern, non nuove lettureNAND. Non sono provati scheduler, concorrenza reale, DMA/cache o avvio. [Test del wrapper nativiASan/UBSan eARC](../Risultati/USB_SCSI/Accesso_NAND_PC/raw_adapter_20261021T085303Z/verified_evidence.json) rieseguiti dopo il chiarimento del contesto.

## Contenitore completo, integrità soltanto

[Builder riproducibile](../Python_Trace_Scripts/s33_build_nand_pc_offline.py), [manifest corrente](../Risultati/USB_SCSI/Accesso_NAND_PC/container_latest.json), [contenitore NON INSTALLARE](../Risultati/USB_SCSI/Accesso_NAND_PC/container_20261021T090006Z/S33_NAND_PC_RAW_OFFLINE_NON_INSTALLARE.bin).

- 29.606.692byte; SHA256`52f8714dcb9612dec0c6af9363309364de305a9f4eb761edfc9ff92b63bc9ac9`.
- Payload0 esteso; solo payload4/5 modificati perhook/puntatore. Gli altri13payload, TBIB e P1RES sono identici agli originali.
- Offset dei15payload successivi aggiornati di9settori. Preservati anche i due gap da512byte prima dei payload2/12, il record d’ingresso16 e la codaTBM.
- Verificate16somme, somma/complementoKHIR, XORdelcontenitore, descrittori esterni e rollback esatto al file originale. Le sostituzioni dei servizi usate dalla CPU **non sono incluse nel contenitore**.
- La capacità logicaMain nei dump è19.267.584byte; ilTBM nuovo17.619.968byte lascia1.647.616byte. Il confronto è vincolato all’hash del dump e alla mappaP1 già ricostruita: **capienza della vista logica, non ancora accettazione del writer/updater**.

La CPU ha eseguito copie con lo stesso nuovo codice/hook/indirizzi e servizi sostituiti. Il contenitore conI/O originale non è stato avviato sulla fotocamera. Un checksum corretto non rende sicuro il flash.

## Continuazione

1. Stabilire proprietà e durata di35BC00..35CE00, inclusi eventuali scrittori calcolati e consumo dei descrittori estesi nel loader.
2. Seguire i controlli di dimensione e il writer dell’updater perTBM/P1RES rilocati, con le9unità aggiunte; la capienza logica da sola non basta.
3. Completare il clientPC e la verifica d’integrità delle pagine reali quando è disponibile un percorso hardware autorizzato; USB, NAND e recupero fisici non sono simulabili come se fossero già riusciti.

L’obiettivo resta accesso effettivo al restoNAND o aggiornamento pronto da installare. Il candidato attuale restaNO-GO; circa10% funzionaleAkeruOS invariato.

## Continuazione — updater e caricatore eseguiti offline

Il [rapporto successivo](S33_NAND_PC_Updater_Loader_e_Azzeramento_Iniziale.md) verifica XOR/header, limite del validatoreMain, writer entro capacità con backend registratore e caricamento/checksum del Main ampliato. Estensione preservata anche nell’azzeramento iniziale; durata successiva e recupero restano aperti. USB09:12UTC conferma22MiB con breve assenza e nuova enumerazione, senza diagnosi della causa.
