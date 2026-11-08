# NAND dal PC: regioni RAM applicative e limite dell'installazione

21 ottobre 2026 — R0/R3/R4. **Tre casi CPU sul gestore originale passati:** tutte le111regioni della tabella applicativa risultano sopra `01BF9800`, separate dall'estensione proposta `[35BC00,35CE00)`. È una nuova delimitazione positiva del rischio RAM; non dimostra tutti gli scrittori, gli alias, il DMA o il recupero fisico. **Candidato invariato NON_INSTALLARE, obiettivo aperto.**

## Prove e input

- [Verificatore](../Python_Trace_Scripts/s33_verify_nand_pc_ram_regions.py), [snapshot eseguito](../Risultati/USB_SCSI/Accesso_NAND_PC/ram_regions_cpu_20261021T135003Z/verifier_snapshot.py).
- [Manifest e111regioni](../Risultati/USB_SCSI/Accesso_NAND_PC/ram_regions_cpu_20261021T135003Z/verified_evidence.json), [due confini sostituiti](../Risultati/USB_SCSI/Accesso_NAND_PC/ram_regions_cpu_20261021T135003Z/laboratory_patches.json), [finestre GNU originali](../Risultati/USB_SCSI/Accesso_NAND_PC/ram_regions_cpu_20261021T135003Z/gnu_verified.txt).
- [Traccia ingresso inizializzazione](../Risultati/USB_SCSI/Accesso_NAND_PC/ram_regions_cpu_20261021T135003Z/boot_chain.trace), [ingresso diretto](../Risultati/USB_SCSI/Accesso_NAND_PC/ram_regions_cpu_20261021T135003Z/direct_same_layout.trace), [errore successivo](../Risultati/USB_SCSI/Accesso_NAND_PC/ram_regions_cpu_20261021T135003Z/post_init_error.trace).
- [Intervalli dichiarati già verificati](../Risultati/USB_SCSI/Accesso_NAND_PC/extension_interval_audit.json), [caricamenti differiti](S33_NAND_PC_Offset_Differiti_Corretti_e_Client_Linux.md), [resolver e creazione SD](S33_NAND_PC_TBIB_Resolver_e_Creazione_Dispositivo_SD.md).

```bash
python3 Python_Trace_Scripts/s33_verify_nand_pc_ram_regions.py
```

Si usa GNU di base, senza nuove build o modifiche ai suoi sorgenti. Le immaginiMain0/Main1 provengono dai payload Nikon canonici; il candidato viene identificato per hash. Nell'area aggiunta viene messa una sentinellaA5: **questo test non esegue il nuovo handler**. I test del suo codice e del loader restano prove separate, collegate nei rapporti precedenti. La prima preparazione nella sandbox è fallita prima della CPU per Podman; le esecuzioni fuori dalla sandbox `135002Z` e `135003Z` sono entrambe riuscite. Per coordinamento sovrapposto sono state eseguite due copie; qui si pubblica `135003Z`, conservando l'altra come storica. Nessuna azione hardware in entrambe.

## Catena originale e tabella

La chiamata a `C768C` restituisce il limite software **10000000**. Il percorso `C63D8→12A6E4→1EF6C0`, con risolutore `1EF688`, usa la tabella **3766F4**. La posizione della chiamata nel coordinatore è `C5D6A/C5D6E`; la prova comincia dal getter e dal successivo ingresso, senza eseguire l'intero coordinatore o lo scheduler.

La tabella contiene111record da24byte, seguiti da un terminatore24byte zero. SHA256 dell'insieme112record:

```text
e86ae222280be8621ba8033688618a8694182e4ae08b69985743fb8eb14d8993
```

I sei campi sono ID, parent, stato, base, dimensione, allineamento. Il calcolo di base eseguito è `align_down(parent_base - dimensione, allineamento)`, con allineamento4 per tutti i record di questo campione. ParentE9 usa il limite superiore software; le altre dipendenze sono risolte attraverso la tabella degli indici. L'ID2F duplicato viene risolto al record45, ultimo dei due, come nel codice originale. Non si sostituisce questa scelta con una deduplicazione.

La prova confronta le111sestuple risultanti, tutte le232celle dell'indice a `441FA0`, count111 nell'oggetto `441F68`, flag di inizializzazione e minimo registrato a **441F94=01BF9800**. Il minimo appartiene al record78, ID83, parent82, dimensioneA000. Il valore `10000000` è configurato dal software: non è una misura indipendente della RAM fisica.

## Scritture controllate e casi

Il servizio `13A954` è sostituito da un registratore che esegue un byte-fill locale. Il codice originale richiede96riempimenti, su78indirizzi distinti:256byte di5A in coda al limite del parent per le regioni sufficientemente grandi. Gli argomenti, tutti i byte scritti e le guardieA5 circostanti vengono confrontati. Non sono riempimenti integrali delle regioni e non costituiscono una prova del corpo originale di13A954.

`177488` è una fixture di ritorno che registra gli argomenti. È il secondo e ultimo confine sostituito. L'area oggetto e l'estensione partono daA5; i soli intervalli di coda necessari al test sono mappati esplicitamente.

| Caso | Ingresso | Risultato |
|---|---|---|
|boot_chain|C768C→C63D8|ritorno0,111regioni e indice attesi; flag365625=1|
|direct_same_layout|12A6E4 con top10000000/tabella3766F4|stessa disposizione, output minimo01BF9800|
|post_init_error|C768C→C63D8,177488 restituisce12345678|errore propagato, flag365625=0, disposizione già assegnata|

Tutti e tre preservano stack e sentinella dell'estensione; zero fault del simulatore. Il terzo caso non autorizza a considerare l'inizializzazione annullata: l'errore finale segue già l'assegnazione completa delle regioni. Le finestre di apertura/chiusura `1EF7F8/1EF8BC` sono incluse come evidenza statica, **non sono ulteriori casi CPU**.

## Valutazione di sicurezza aggiornata

Questa tabella applicativa e le sue scritture iniziali verificate non invadono l'estensione. Si aggiunge ai precedenti riscontri sui16payload, sul primo azzeramento, sul poolkernel dichiarato e sui sette trasferimenti differiti. Non basta ancora per attribuire l'area all'estensione per tutta la vita della macchina: restano API che possono cambiare disposizione, altri allocatori, scrittori calcolati e accessi DMA/cache/alias.

| Requisito del nuovo BIN | Evidenza corrente | Limite ancora aperto |
|---|---|---|
|contenitore e offset coerenti|checksum, descrittori, offset differiti e rollback locale verificati|non è un flash o un recupero fisico|
|caricamento del record17|loader settori e file eseguiti con fixture|handoff e I/O fisico non provati|
|durata dell'estensione|intervalli noti più111regioni ora eseguite|non ancora tutti gli scrittori/runtime|
|updater|writer/preparatori, confronto, retry e dispatch eseguiti con backend registratori/modelloRAM|scritturaBoot e commit fisici; errori dopo modifiche parziali|
|recupero alternativo|guardie, routing, lettore file, resolver e dispatchSD verificati offline|controllerSD, mount/FAT, condizioni fisiche e avvio alternativo|
|lettura NAND dal PC|protocollo e client verificati offline|integrità USB/NAND reale e handler installato non provati|

Il pacchetto continua a richiedere il percorsoBoot anche se il suo contenuto è invariato. Non esiste ancora una prova di recupero della macchina in caso di fallimento durante l'aggiornamento. Non viene creato un duplicato rinominato «installabile» per sostituire queste verifiche.

Candidato SHA256 `0bb25fd6603488e30d41ac6ad96f4fe4e8fe5e838deda7cfc7e9c6ab7cb324e9` invariato; il contenitore ricreato a104016Z ha gli stessi byte di quello092600Z, entrambi ancora NON_INSTALLARE. Vecchio52f8714d escluso. Nessun flash, scritturaSD/NAND o avvio/fotoAkeruOS: circa10% funzionale invariato.

Prossimo: API che modificano le regioni e rimanenti pool/scrittori dell'intervallo; sul recupero seguire il backendSD01002BE4 e il mount completo fino ai lettori, mantenendo separati ingressi fisici e fixture. Obiettivo controllo sicurezza e BIN pronto ancora aperto.

## Continuazione — API e configurazione successiva

La [prova successiva](S33_NAND_PC_API_Regioni_e_Configurazione_Successiva.md) esegue query/apertura/chiusura e collega il tratto successivo177488 con i byte reali del candidato. Nei tre casi integrati anche13A954 è originale;177FA8 e celleMMIO restano di laboratorio. Recupero fisico e tutti gli altri scrittori ancora aperti.
