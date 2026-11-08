# NAND dal PC: API delle regioni e configurazione successiva

21 ottobre 2026 — R0/R3/R4. Verificate **111 sequenze delle API originali più quattro scenari**, **12 casi di configurazione registri** e **tre casi che uniscono inizializzazione delle regioni e configurazione successiva**. Nel tratto integrato sono preservati i byte reali dell'estensione candidata. Nessuna nuova collisione trovata in questi percorsi; recupero fisico, DMA/cache/alias e avvio completo restano aperti. **Il BIN rimane NON_INSTALLARE.**

## Prove riproducibili

- [API regioni](../Python_Trace_Scripts/s33_verify_nand_pc_region_api.py), [manifest](../Risultati/USB_SCSI/Accesso_NAND_PC/region_api_cpu_20261021T135940Z/verified_evidence.json), [111 sequenze](../Risultati/USB_SCSI/Accesso_NAND_PC/region_api_cpu_20261021T135940Z/api_cases.json).
- [Configurazione successiva](../Python_Trace_Scripts/s33_verify_nand_pc_post_region_registers.py), [manifest corrente](../Risultati/USB_SCSI/Accesso_NAND_PC/post_region_cpu_20261021T140525Z/verified_evidence.json), [12 casi](../Risultati/USB_SCSI/Accesso_NAND_PC/post_region_cpu_20261021T140525Z/register_cases.json), [tre casi integrati](../Risultati/USB_SCSI/Accesso_NAND_PC/post_region_cpu_20261021T140525Z/integrated_cases.json), [unico confine sostituito](../Risultati/USB_SCSI/Accesso_NAND_PC/post_region_cpu_20261021T140525Z/laboratory_patches.json).
- [Precedente disposizione delle111regioni](S33_NAND_PC_Regioni_RAM_Applicative_e_Limite_Installazione.md), [resolver e creazione SD](S33_NAND_PC_TBIB_Resolver_e_Creazione_Dispositivo_SD.md).

```bash
python3 Python_Trace_Scripts/s33_verify_nand_pc_region_api.py
python3 Python_Trace_Scripts/s33_verify_nand_pc_post_region_registers.py
```

Motore GNU di base fissato dal runner, senza modifiche ai sorgenti o agli strumenti. Firmware canonico e input confrontati per hash. La prima prova usa lo snapshot inizializzato precedente, validando nuovamente tutte111sestuple prima dell'esecuzione. Le prove dei registri usano Main0/Main1 canonici con il solo confine dichiarato sostituito. Nessun accesso alla fotocamera, SD o NAND.

## Apertura, chiusura e interrogazione non ridispongono le regioni

I wrapper originali sono `12A71C`→apertura `1EF7F8`, `12A738`→chiusura `1EF8BC`, `12A748`→interrogazione `1EF920`. Prima del test i callback a oggetto+32/+36 vengono azzerati con i setter originali `12A764/12A76C`; nello snapshot iniziale del laboratorio quei campi eranoA5. Questo è un contesto esplicito senza callback, non una lettura della RAM della macchina.

Per ognuno dei111record vengono eseguiti query, apertura, seconda apertura, chiusura, seconda chiusura e query finale. Le due query restituiscono le sestuple attese; l'apertura restituisce base/dimensione, la seconda apertura `01D00002`, la seconda chiusura `01D00008`. Le operazioni valide ritornano0. L'ID2F duplicato continua a risolvere il record45. Stack e intera immagineMain1 finale confrontati: il ciclo non cambia base, dimensione, indice o altri byte.

Quattro scenari aggiuntivi verificano:

- aperturaID13, rifiutoID1A sovrapposto con `01D00003`, poi chiusura13 e apertura1A riuscita;
- ID E8 fuori dal limite, `01D00004`;
- ID E7 entro il limite ma senza record, `01D00005`;
- oggetto non pronto, `01D00001`.

Gli errori lasciano intatti gli output di base/dimensione. Il conflitto registra gli ID1A/13 a oggetto+48/+52; il confronto finale dell'oggetto ammette soltanto questi campi e l'azzeramento esplicito dei callback. L'estensione è preservata. I callback non nulli possono eseguire altro codice: non sono coperti e non vengono dichiarati innocui.

Queste prove delimitano le API esaminate; non sono un inventario completo di qualunque scrittura indiretta alla tabella. Anche una nuova chiamata all'inizializzatore con parametri diversi è distinta da queste operazioni.

## Il servizio177488: configurazione di registri, non prova di un altro pool

Il precedente test delle regioni sostituiva `177488`. Il corpo originale chiama il getter di indirizzo `2696F4`, poi il configuratore `269754` per gli indici0 e1; con argomento esattamente1 include anche l'indice2. I tre indirizzi originali sono:

|Indice|Indirizzo del getter|Limite dimensionale nel getter269730|
|---:|---|---|
|0|0F794000|3800|
|1|0F798000|7180|
|2|0F7A0000|D200|

Il getter di revisione è `1F0A6C`: usa il byte cached a423F04 e il campo alto della word423F08; può avviare una discovery quando il byte è zero. Nel test il byte viene posto1 e la revisione0/1/2 è fornita esplicitamente. Non si deduce da ciò la revisione fisica della Nikon.

La revisione1 raggiunge `2C57C0`; le altre due provate raggiungono `2C5970`. Entrambi i corpi originali aggiornano halfword nell'area `0FE6…`. Il solo servizio sostituito è **177FA8**, che registra gli argomenti prima di quelle scritture: le chiamate attese sono `(1,3,0C)`, `(1,3,30)` e, se richiesto, `(1B,3,0C)`. Non viene attribuito a questo servizio simulato un effetto hardware.

I12casi combinano tre revisioni, inclusione o meno dell'indice2 e celle MMIO inizialmente00/A5. L'intera immagine di0x5000byte aFE60000 viene confrontata, inclusi i byte che devono rimanere invariati. Sono controllati valori degli indirizzi, maschere delle letture/modifiche/scritture e selezione dei registri. Main0/Main1, stack ed estensione restano invariati nel test isolato.

Il modello MMIO conserva soltanto i valori scritti in RAM. **Non simula risposte del controller, trasferimenti, attivazione DMA o traduzione fisica degli indirizzi.** Gli indirizzi restituiti dal getter non vengono trasformati in una nuova prova di memoria libera o di assenza di alias.

## Tratto integrato con i byte del candidato

I tre nuovi casi integrati eseguono `C768C→C63D8→12A6E4→1EF6C0/1EF688`, poi il **177488 originale** e la configurazione registri. È originale anche **13A954**, il riempimento che nella prova precedente era un recorder. Rimane sostituito soltanto177FA8; revisione cached e celle MMIO sono input di laboratorio.

Per ogni revisione0/1/2:

- tutte111regioni coincidono col riferimento; minimo441F94=01BF9800;
- riempimenti originali delle code5A e guardieA5 coincidono;
- registri finali coincidono col caso isolato corrispondente;
- il flag365625 diventa1, il ritorno è0 e lo stack è preservato;
- i4608byte effettivi del record17 del candidato, mappati in35BC00..35CE00, restano identici.

Il codice dell'handler non viene invocato in questo tratto. Preservarne i byte è distinto dal provarne il funzionamento USB, già testato separatamente con altri confini simulati. Non è un boot completo.

Le esecuzioni precedenti140059Z e140302Z restano storiche. L'ultima140525Z corregge anche l'etichetta di provenienza del manifest: `269754` è il configuratore, `1F0A6C` il getter della revisione. I loro snapshot non vengono riscritti.

## Recupero SD: nuovo confine fisico identificato, sola analisi statica

Le [finestre originali TBIB](../Risultati/USB_SCSI/Accesso_NAND_PC/post_region_cpu_20261021T140302Z/tbib_sd_static_windows.txt) e il [record verificato](../Risultati/USB_SCSI/Accesso_NAND_PC/post_region_cpu_20261021T140302Z/tbib_sd_static_evidence.json) collegano il backend:

```text
01002BE4 →010028A0 →010113FC →0100BC54(5,3,C00)
 →010258A4 →010257C8 →01009D38
```

Il record canale5 a0104374C è **8byte: baseLE32 e due maschereLE16**, rispettivamente0FE80098,AAA0,5550. A01009D48 viene letto l'halfwordFE80098;01009D54 lo riscrive,01009D58 leggeFEF000C, segue un ciclo33iterazioni e una rilettura. Prima servono sincronizzazioneIRQ e un contesto kernel valido. Una discovery della revisione può inoltre leggereFEF0020 lungo il percorso condizionale. Non sono accessi hardware eseguiti da noi.

Il backend attende prima tramite01013808(400000)→010038C8. In caso di errore della fase01002938, conserva lo status inr16, imposta output[3]=1 ed esegue cleanup; non viene assegnato al byte il significato fisico «scheda assente». Il mount può propagare l'errore del creator, ma un errore del rilascio può prevalere. Il lettorefile0100125C normalizza qualunque mount nonzero a8 prima di aprire il file. Questi collegamenti sono **statici**, non ulteriori casi CPU o una procedura di recupero verificata.

## Decisione corrente

Sono ora delimitati anche i percorsi originali successivi all'assegnazione delle regioni e le API di apertura/chiusura/query nel contesto provato. Restano altri pool/scrittori, callback non nulli e possibili alias/DMA/cache; sul recupero restano controller, temporizzazione, mount/FAT e handoff fisici. Il pacchetto richiede ancora il percorsoBoot invariato e un errore può seguire modifiche già effettuate.

Il candidatoSHA256 `0bb25fd6603488e30d41ac6ad96f4fe4e8fe5e838deda7cfc7e9c6ab7cb324e9` resta invariato **NON_INSTALLARE**. Non è stato prodotto un duplicato presentato come installabile. Obiettivo controllo sicurezza e BIN pronto ancora aperto; nessun avvio/fotoAkeruOS, circa10% funzionale invariato.

Prossimo: collegare i restanti pool e scrittori al loro intervallo effettivo, verificare registrazione/usi dei callback e chiudere mount/handoff con stato conservato. Le risposte del controllerSD identificate richiedono evidenza fisica o un modello esplicitamente limitato; ulteriori ritorni fixture non dimostrerebbero il recupero della macchina.
