# NAND: ECC dei dati e limite degli errori nell’export raw

20 ottobre 2026 — R0/R3/R4. Dopo la [ricostruzione dei sette export](S33_NAND_Mappa_Logica_e_Ricostruzione_Integrale_Export.md), è ora verificato anche il codice ECC presente nei record: **tutti i151.040settoriECC dei295gruppi mappati coincidono con il calcolo indipendente**. Nessuna correzione dei dati è stata necessaria per ottenere questi confronti.

L’exporter raw ha però un limite distinto: non propaga il codice di ritorno di ogni lettura. Questo impedisce di usare il solo successo dell’esportazione come certificazione dell’acquisizione completa.

## Evidenze riproducibili

- [Script](../Python_Trace_Scripts/s33_verify_nand_ecc_and_raw_status.py), [indice corrente](../Risultati/Dump_fotocamera/NAND_ECC/latest.json).
- [Evidenze](../Risultati/Dump_fotocamera/NAND_ECC/20261020T160539Z/verified_evidence.json), [scansione ECC completa e differenze](../Risultati/Dump_fotocamera/NAND_ECC/20261020T160539Z/ecc_scan.json), [sei finestre GNU](../Risultati/Dump_fotocamera/NAND_ECC/20261020T160539Z/gnu_verified.txt).
- [2.105 casi di correzione](../Risultati/Dump_fotocamera/NAND_ECC/20261020T160539Z/correction_cases.json), [caller CPU completo](../Risultati/Dump_fotocamera/NAND_ECC/20261020T160539Z/all_corrections.s), [traccia del campione](../Risultati/Dump_fotocamera/NAND_ECC/20261020T160539Z/sample_corrections.trace).
- [Caller al confine del ritorno raw](../Risultati/Dump_fotocamera/NAND_ECC/20261020T160539Z/raw_status_boundary.s), [traccia](../Risultati/Dump_fotocamera/NAND_ECC/20261020T160539Z/raw_status_boundary.trace).
- [Fonti pubbliche conservate con hash](../Risultati/Dump_fotocamera/NAND_ECC/fonti/source_manifest.json), [sorgente Linux v6.1](../Risultati/Dump_fotocamera/NAND_ECC/fonti/linux_v6.1_ecc-sw-hamming.c), [documentazione completa RST](../Risultati/Dump_fotocamera/NAND_ECC/fonti/linux_v6.1_nand_ecc.rst).

Comando effettivamente eseguito:

```bash
python3 Python_Trace_Scripts/s33_verify_nand_ecc_and_raw_status.py
```

Esito `PASS_NAND_ECC_SCAN_AND_ORIGINAL_CORRECTION`. Conservati sorgente dello script, caller, file iniziali e copie mutate di laboratorio, comandi e log. Ricontrollati gli input del checkpoint precedente, inclusi i14dump, il firmware e le identità degli strumenti. GNU e originali intatti; nessun comando alla fotocamera.

## Confronto indipendente e provenienza

La [documentazione primaria Linux sull’ECC NAND](https://www.kernel.org/doc/html/v6.1/driver-api/mtd/nand_ecc.html) descrive la parità su blocchi256byte e il codice Hamming a3byte. È stato conservato il [calcolatore Linux v6.1](https://github.com/torvalds/linux/blob/v6.1/drivers/mtd/nand/ecc-sw-hamming.c), selezionando l’ordine SmartMedia dei byte. Il collegamento alla Nikon è dimostrato dai confronti sul dump e dal codice firmware; non è assunto dal solo nome dell’algoritmo.

Il fileC originale ha SHA-256`c6594d99c530df9c4b19851bbbc29119d2be20ee8317e3c7ab9ed337bda321e4`. La documentazioneRST ha SHA-256`3be8591803b1db141ee950ee27268911e29cf589a59eef95b530d7b47ad58821`. Entrambi hanno URL e data di acquisizione nel manifest e restano disponibili per le prossime analisi. Ricerca/lettura effettuate con la skill [Firecrawl](</home/jack/.local/share/codex-secondo/home/plugins/cache/openai-curated-remote/app-6a314a73f8ac819195b0d55e36b9c609/2.5.0/skills/firecrawl/SKILL.md>).

Il verificatore estrae soltanto il calcolatore puro e le sue tabelle, sostituisce gli include kernel per la compilazione host e conserva licenza GPL e attribuzione. Compila una libreria nella cartella del risultato, fuori dagli alberi GNU; registra anche l’identità del compilatore host. Non installa dipendenze e non esegue il resto del driver Linux.

## Dove sono i due codici ECC per ogni512byte

Il codice Nikon`0x25F2B8` legge due metà da256byte. I codici calcolati vanno rispettivamente alle aree software`0x50F514` e`0x50F520`. I confronti`0x25CCA0` usano tre byte per ogni metà.

Per ogni settore512byte, il segmento spare corrispondente è16byte:

| Byte nello spare16 | Uso verificato |
|---|---|
|6/7 e11/12|Due copie del tag logico già decodificato|
|13..15|ECC della prima metà256byte|
|8..10|ECC della seconda metà256byte|

L’ordine delle due metà è verificato, non dedotto dall’ordine crescente degli offset. La pagina ordinaria contiene quattro settori512byte e quattro segmenti spare16byte. Nei primi8record del file, BootNAND/BFN e tabelle impiegano invece il layout interleaved512+16: lo scanner usa quel layout soltanto per questa regione già identificata.

## Scansione dell’intero file NANDP1

Controllati tutti i20.736record, cioè **165.888calcoli da256byte**:

| Copertura | Risultato |
|---|---:|
|Primi8record, formato speciale|64coincidenze|
|Record ordinari|165.696coincidenze|
|Record ordinari, differenze|128|
|Totale coincidenze|165.760|
|Settori nei295gruppi mappati|151.040, tutti coincidenti|

Le128differenze sono tutte nei primi4record di ciascuno dei gruppi fisici esportati6,100,200e263:32per gruppo. I dati e i codici memorizzati lì sonozero; il calcolatore dà`FFFFFF`, diverso da`000000`. Questi gruppi non contribuiscono alla mappa logica usata per i sette export.

È lo stesso pattern anomalo già catalogato, ora caratterizzato anche rispetto all’ECC. Non basta per decidere se derivi da marcatura fisica, scelta software o un esito dell’acquisizione: chiamarli automaticamente «quattro bad block guasti» supererebbe la prova disponibile. I restanti settori dei gruppi con dati azzerati e spareFF sono coerenti con il codice atteso per i dati letti, ma restano fuori dalla mappa.

La coerenzaECC è un controllo d’integrità indipendente utile. Non dimostra che siano state acquisite tutte le aree del chip o che un successivo programmatore NAND possa ripristinarle con gli stessi marcatori.

## Correttore Nikon eseguito con errori di laboratorio

La funzione originale`0x2E566C` confronta codice memorizzato e calcolato, ricava la posizione dell’errore quando possibile e modifica il buffer o i byteECC. Il test usa un campione reale256byte dall’inizio MainCode e crea copie corrotte:

- 1caso integro: ritorno0, nessuna modifica.
- 2.048casi, uno per ogni possibile bit dati del campione: ritorno1 e ripristino esatto dei256byte.
- 24casi, uno per ogni bit dei3byteECC memorizzati: ritorno2 e ripristino del codice memorizzato, dati intatti.
- 32coppie di errori dati distinti: ritorno3, senza una falsa correzione del buffer.

Sono2.105casi in un’unica esecuzione:260.500istruzioni del profiler, exit0 e nessun fault. Una seconda esecuzione tracciata ripete4casi rappresentativi, senza sommarli come copertura aggiuntiva. Tutti i file risultanti sono confrontati con i byte finali previsti; gli input iniziali sono conservati separatamente. Solo le copie di laboratorio sono mutabili.

Questo prova tutte le posizioni del singolo errore **su quel campione**, più le classi aggiuntive indicate. Non prova la correzione di ogni combinazione di errori multipli. Il wrapper`0x2E571C`, verificato staticamente, traduce gli esiti0/1/2in successo e l’esito non correggibile in`0x01B00014`; il confronto preliminare`0x25CCA0` usa`0x01B0000F` per una differenza nei codici. Non sono automaticamente codici USB/PTP disponibili all’utente.

## Il limite del ritorno dell’exporter raw

Nella funzione`0x1ED37C`, il ciclo chiama il lettore raw`0x25F428` a`0x1ED410`. Subito dopo, a`0x1ED416`, carica l’indice pagina in`r0`, sovrascrivendo il codice restituito dalla lettura. Avanza il puntatore di2112byte e continua. In quel tratto non trasferisce il codice in`r15`, che conserva lo stato separato del percorso di sincronizzazione. Alla fine scrive la lunghezza nominale nel parametro d’uscita.

Dodici proveCPU eseguono **le istruzioni originali dopo il ritorno**, con3indici pagina e4valori di ritorno predisposti dal caller: il codice in`r0` viene perso, il cursore avanza e lo stato conservato resta invariato. Il lettore e l’intero exporter non sono eseguiti in queste12prove; è un test del confine e non una nuova simulazione del controller.

La conseguenza del flusso statico è concreta: il successo nominale e la lunghezza del file raw non garantiscono da soli che ogni lettura interna abbia restituito successo. Questo non annulla i confronti byte/ECC appena ottenuti; precisa quale garanzia manca quando un’area resta anomala o non mappata.

## Continuazione per AkeruOS

R4 dispone ora di mappa, ricostruzione logica e riscontroECC dei dati usati, con gli errori e i limiti separati. Non è ancora una procedura di recupero fisico dimostrata. R3 può basarsi sui byte controllati per seguire i loader, senza correggere o azzerare silenziosamente regioni dubbie.

Prossimo: passare dal TBIB ai descrittori TBM/risorse realmente conservati nel dump e seguire caricamento, checksum e residenza; resta da chiarire anche chi aggiorna il campoP3. Nessuna modifica hardware o nuova allocazione AkeruOS; circa10% funzionale invariato.

## Continuazione — dai byte verificati ai gruppi Main, 20 ottobre 2026

[Identificati i caricamenti C2/C3/C4 e Resource](S33_Gruppi_C2_C3_C4_Risorse_e_Segnali_Caricamento.md): sette triplette corrispondono ai payload TBM2/3/4/5/6/7/9 del Main fornito. Il riscontro checksum è del verificatore host; il lettore Main studiato non controlla il checksum RHIR in quel tratto. 48 casi con servizi simulati precisano notifiche parziali ed errori ignorati. Prossimo: consumatori dei bit, ownership e caricamenti10/11–15; il recupero fisico resta aperto.
