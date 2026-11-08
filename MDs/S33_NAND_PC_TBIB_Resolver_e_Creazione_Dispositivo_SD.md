# NAND dal PC: resolver TBIB e creazione del dispositivo SD

21 ottobre 2026 — R0/R3/R4. Il resolver originale è verificato in **141 casi CPU**; una nuova prova di **12 casi CPU** collega risoluzione di `B:`, creazione del dispositivo e callback SD. Queste prove distinguono namespace, creazione e stato del supporto. **Non provano un recupero fisico e non rendono il candidato installabile.**

## Fonti e riproduzione

- [Resolver](../Python_Trace_Scripts/s33_verify_nand_pc_tbib_namespace.py), [manifest dei 141 casi](../Risultati/USB_SCSI/Accesso_NAND_PC/tbib_namespace_20261021T103943Z/verified_evidence.json), [casi e stati](../Risultati/USB_SCSI/Accesso_NAND_PC/tbib_namespace_20261021T103943Z/namespace_cases.json). Esecuzione preesistente, ritrovata nel progetto e riutilizzata; tutti gli hash degli input correnti coincidono. Non è stata attribuita a una nuova esecuzione.
- [Creazione SD](../Python_Trace_Scripts/s33_verify_nand_pc_tbib_sd_init.py), [manifest dei 12 nuovi casi](../Risultati/USB_SCSI/Accesso_NAND_PC/tbib_sd_init_20261021T134213Z/verified_evidence.json), [risultati](../Risultati/USB_SCSI/Accesso_NAND_PC/tbib_sd_init_20261021T134213Z/sd_init_cases.json), [tre confini sostituiti](../Risultati/USB_SCSI/Accesso_NAND_PC/tbib_sd_init_20261021T134213Z/laboratory_patches.json).
- [Lettore file precedente](S33_NAND_PC_Lettore_File_TBIB_Record17_e_Limite_Status.md), [selezione delle sorgenti](S33_NAND_PC_TBIB_Guardia_Produttore_e_Selezione_Fallback.md).

```bash
python3 Python_Trace_Scripts/s33_verify_nand_pc_tbib_namespace.py
python3 Python_Trace_Scripts/s33_verify_nand_pc_tbib_sd_init.py
```

Motore GNU di base fissato dal runner; nessuna nuova build o modifica GNU. La prima nuova esecuzione non ha superato la preparazione Podman per il filesystem della sandbox; la prova riuscita è quella indicata sopra, eseguita dopo autorizzazione fuori dalla sandbox. Firmware originale, sorgenti GNU, strumenti e input confrontati per hash prima/dopo. Nessun comando alla fotocamera.

## Risoluzione del volume e stato

`0102007C` copia il prefisso fino al primo `:` in un buffer locale e richiama `0101FFD0`. Quest'ultimo scorre la tabella `010421CC`, passo `0x150`, confrontando il prefisso a offset **30 decimali / 0x1E**. Record0: `A:`/`DEVNAND:`; record1: `B:`/`DEVSD:`. Il lookup è sensibile alle maiuscole. Anche un path completo viene risolto dal suo prefisso; `DEVSD:` non è un prefisso volume accettato dalla tabella provata.

Quando trova il record, scrive il suo indice sia all'output del chiamante sia alla word globale `010415F8`, **prima** di valutare lo stato. L'indice1 non è dunque un certificato di disponibilità SD.

| Predicato, nell'ordine originale | Ritorno |
|---|---|
| byte record+0x4B esattamente1 | 0 |
| byte+0x48 zero | 01A00040 |
| byte+0x49 esattamente1 | 01A00010 |
| word+0x50 zero e word+0x58 zero | 01A00030 |
| word+0x50 zero e word+0x58 nonzero | 01A0001B |
| word+0x50 nonzero e word+0x58 nonzero | 0 |
| word+0x50 nonzero, word+0x58 zero, word+0x4C zero | 01A00035 |
| word+0x50 nonzero, word+0x58 zero, word+0x4C nonzero | 01A0001A |

La matrice eseguita usa valori0/1 per i sei campi:128combinazioni sui due namespace. I confronti «esattamente1» derivano dalle istruzioni originali, non da una matrice esaustiva dei byte. Gli altri13casi coprono prefissi/path, maiuscole, assenza `:`, limite della copia e argomenti nulli. Il chiamante mount `01008394` accetta localmente ritorno0 oppure `01A00030` e prosegue: lo stato iniziale statico non richiede già un dispositivo creato.

## Creazione e dispatch SD eseguiti

La nuova prova risolve prima `B:` con `0102007C`, poi esegue `010203F0` e il dispatcher `0102EE24`. Quest'ultimo legge l'indice globale e seleziona il campo callback+0x2C della tabella. Per `B:` raggiunge **01002E74**, wrapper originale che chiama **01002BE4** con dispositivo numerico0. Questo0 è l'argomento del driver SD, non l'indice volume TBIB1.

Restano originali resolver, creator, dispatcher, wrapper SD e interrogazione `01020108`/`010200D0`. Sono sostituiti soltanto:

| Confine | Comportamento della fixture |
|---|---|
|01018438|allocazioni separate da40,44,32byte; fallimento selezionato per richiesta|
|0100C1D8|registrazione dei rilasci|
|01002BE4|registra dispositivo/output, fornisce cinque byte di stato e un ritorno configurato|

Non sono eseguiti controller, GPIO, alimentazione, scheda, allocatore reale o l'intero mount. Gli oggetti della fixture sono distinti e inizialmente zero. Non costituiscono un modello della memoria fisica.

| Caso | Creazione | Rilasci e pubblicazione |
|---|---|---|
|successo|0|nessun rilascio; pubblica l'oggetto32byte al record+0x50|
|record+0x50 già nonzero|01A00010|nessuna allocazione/callback; conserva il puntatore|
|prima allocazione fallita|01A00006|nessun rilascio/puntatore|
|seconda allocazione fallita|01A00006|rilascia l'oggetto40byte|
|terza allocazione fallita|01A00006|rilascia40byte, poi44byte|
|errore backend1234|1234|rilascia32byte,40byte,44byte; non pubblica|
|uno dei cinque byte di stato nonzero, backend ritorna0|0|pubblica; interrogazione successiva restituisce un errore|

Nei successi sono confrontati anche i collegamenti fra oggetto32byte, oggetto44byte e area40byte di stato; il campo nome dispositivo punta al `DEVSD:` originale. Stack preservato in tutti12casi.

## Creazione riuscita e stato del supporto restano distinti

`01020108` controlla prima byte record+0x4A. Con il valore iniziale1, tenta la query `010200D0`. In questi casi il callback record+0x44 resta nullo, quindi la query ritorna `01A00001` e il chiamante usa i byte già contenuti nell'oggetto di stato creato.

L'ordine dei controlli è byte3,4,2,1,0. Un byte nonzero produce rispettivamente `01A00044`, `01A00045`, `01A00043`, `01A00042`, `01A00041`; tutti zero producono0. I cinque casi singoli e il caso con più byte nonzero verificano questo ordine. In tutti questi casi il creator aveva già restituito0: il suo successo non implica assenza di errori del supporto. Non vengono assegnati significati fisici ai cinque byte.

Non è dimostrato che l'intero mount faccia esattamente questa query nello stesso stato o che un errore venga ignorato fino al caricamento del file. La prova isola i contratti locali e non attribuisce alla macchina una sequenza non eseguita.

## Stato e passo successivo

Il percorso statico e CPU `B:`→indice1→callbackSD→driver0 è ora collegato. Restano il corpo fisico01002BE4 e i suoi servizi, la registrazione e apertura manager/FAT, l'intero mount e il successivo handoff. Nessuna procedura di tasti/avvioSD o recupero certificata.

Candidato invariato SHA256 `0bb25fd6603488e30d41ac6ad96f4fe4e8fe5e838deda7cfc7e9c6ab7cb324e9`, vecchio52f8714d escluso. Durata dell'estensione, integrità USB/NAND fisica e recupero restano requisiti aperti prima di un aggiornamento pronto. **NON INSTALLARE; obiettivo attivo, circa10% funzionale AkeruOS invariato.**

## Continuazione — gestore regioni RAM

La [prova successiva](S33_NAND_PC_Regioni_RAM_Applicative_e_Limite_Installazione.md) delimita positivamente111regioni applicative mediante esecuzioneCPU. Non certifica recupero o disponibilitàfisicaSD: i requisiti aperti di questo rapporto restano.
