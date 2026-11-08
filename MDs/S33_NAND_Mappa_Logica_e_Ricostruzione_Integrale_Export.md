# NAND: mappa logica e ricostruzione integrale dei sette export

20 ottobre 2026 — R0/R3/R4. **BootCode, MainCode, NANDReserved, entrambe le Calibration ed entrambe le CameraParam sono ricostruiti byte per byte da NANDP1.** La divergenza della prima proiezione era dovuta alla traduzione dei blocchi logici. Le code non assegnate sono restituite come FF dal lettore Nikon: non richiedono di trovare un blocco fisico pieno di FF nella stessa posizione.

Questo risultato supera la precedente ricostruzione parziale MainCode/Reserved. Non certifica una procedura di ripristino fisico, l’ECC o l’intero contenuto del chip.

## Prove e riproduzione

- [Script riproducibile](../Python_Trace_Scripts/s33_reconstruct_nand_logical_partitions.py), [indice corrente](../Risultati/Dump_fotocamera/Partizioni_Logiche/latest.json).
- [Evidenze](../Risultati/Dump_fotocamera/Partizioni_Logiche/20261020T155718Z/verified_evidence.json), [mappa logico/fisico](../Risultati/Dump_fotocamera/Partizioni_Logiche/20261020T155718Z/logical_to_physical.json), [sette partizioni e blocchi](../Risultati/Dump_fotocamera/Partizioni_Logiche/20261020T155718Z/partition_mapping.json).
- [Export ricostruiti](../Risultati/Dump_fotocamera/Partizioni_Logiche/20261020T155718Z/ricostruiti/), [campi NANDPartition](../Risultati/Dump_fotocamera/Partizioni_Logiche/20261020T155718Z/partition_text_fields.json), [dieci finestre GNU](../Risultati/Dump_fotocamera/Partizioni_Logiche/20261020T155718Z/gnu_verified.txt).
- [Caller CPU](../Risultati/Dump_fotocamera/Partizioni_Logiche/20261020T155718Z/metadata_and_unmapped.s), [traccia CPU](../Risultati/Dump_fotocamera/Partizioni_Logiche/20261020T155718Z/metadata_and_unmapped.trace), [log](../Risultati/Dump_fotocamera/Partizioni_Logiche/20261020T155718Z/metadata_and_unmapped.log).

Comando eseguito dalla radice:

```bash
python3 Python_Trace_Scripts/s33_reconstruct_nand_logical_partitions.py
```

Esito `PASS_COMPLETE_LOGICAL_PARTITION_EXPORT_RECONSTRUCTION`. I confronti coprono tutti i **40.501.248 byte** dei sette export, senza scegliere i blocchi cercando il contenuto atteso. La mappa viene decodificata prima dai metadati raw e i dump logici sono usati soltanto per il confronto finale.

I test CPU usano GNU originale fissato per hash: **304 casi**, 21.518 istruzioni del profiler, exit0, nessun fault o load/store MMIO. Copertura:295 ID osservati,2forme invalide,2disaccordi di un bit tra copie,3codifiche,1estrazione dimensioni e1lettura non mappata. Le istruzioni eseguite nel payload Main sono ricontrollate contro MainCode.dmp; le finestre e le11etichette del formatter coincidono col firmware fornito. Verificati gli input del checkpoint precedente, inclusi i14dump e gli strumenti GNU. Nessuna modifica a originali, toolchain, sorgenti o installazioni; nessun builder eseguito.

## Perché concatenare i blocchi fisici falliva

NANDP1 contiene324gruppi di64record da2112byte. Per i gruppi delle partizioni, ogni record porta2048byte dati più64byte aggiuntivi, organizzati in quattro segmenti da16byte. Il blocco iniziale BootNAND/BFN conserva il formato speciale già documentato e non passa per questa regola generale.

Gli ID logici non seguono l’ordine dei gruppi nel file. Esempi:

- L’inizio MainCode, logico165, è nel gruppo fisico esportato146.
- L’inizio Reserved, logico16, è nel gruppo285; la sequenza prosegue oltre la fine della porzione contigua e riprende nei gruppi bassi liberi dalla stessa numerazione logica.
- La seconda Calibration usa i gruppi16,17,18,144: la quarta parte non è adiacente alle prime tre.

Per questo la precedente proiezione coincideva con MainCode fino a`0x6C0000`, poi incontrava il gruppo200 senza il tag richiesto; il blocco logico successivo è nel201. Reserved coincideva per`0x4C0000`, poi il blocco successivo si trovava nel gruppo4. La ricostruzione attuale segue gli ID, non salta indiscriminatamente gli zeri e non applica una semplice rotazione del file.

## Metadati logici nei64byte aggiuntivi

In ogni segmento16byte, gli offset6/7 e11/12 contengono due copie della stessa word, in ordine high byte, low byte. Nel campione pulito:

```text
word = 0x1000 | (ID_logico << 1) | bit_parità
bit_parità = popcount(0x1000 | (ID_logico << 1)) & 1
ID_logico = (word & 0x0FFF) >> 1
```

La codifica produce parità complessiva pari. Ad esempio il tag`0x114B` identifica165 e`0x1020` identifica16. Ogni primo record valido contiene otto copie concordanti del tag: due per ciascuno dei quattro segmenti.

L’encoder originale`0x25CF10` costruisce la word a partire dall’indice logico e usa il contatore di bit`0x29DEA8`; la CPU verifica tre codifiche rappresentative, inclusa165. Il decoder originale`0x25CE58` legge le due copie, controlla prefisso e gestisce alcuni disaccordi. Sono eseguiti tutti i295tag osservati e due casi con un bit modificato in una sola copia.

Il parser offline è intenzionalmente più ristretto: ammette solo tutte le copie concordanti, prefisso`0x1` e parità corretta. Nel ramo con copie uguali il firmware non esegue necessariamente il controllo di parità: non si generalizza quindi il filtro offline a tutta la semantica Nikon. I due casi di disaccordo provano il recupero dell’ID in quei casi, **non una correzione ECC dei2048byte dati**.

Nei295gruppi mappati sono controllati tutti i18.880record:18.832hanno tag coerenti e48sono interamenteFF, inclusi dati e spare. Non sono accettati record incoerenti sostituendoli con dati di altri dump.

## La lookup table è prevista dal codice Nikon

La routine`0x25C5E4` inizializza una tabella di halfword a`0x50E9C0` con il valore non assegnato`0xFFFF`. Nel tratto`0x25C6BC..0x25C6EE`, dopo la decodifica dei metadati, scrive il gruppo fisico nella voce indicizzata dall’ID logico. Le routine`0x25C87C` e`0x25C8F0` leggono questa tabella per iniziare o proseguire una lettura logica.

Questa è la base software della traduzione. Nel laboratorio non sono eseguiti l’intero inizializzatore con controller, la scansione hardware o la risoluzione di copie concorrenti. I295ID puliti osservati sono univoci: non servono decisioni inventate su quale copia scegliere. L’indirizzo`0x50E9C0` è un oggetto Nikon, non RAM libera per AkeruOS.

La vista ricostruita copre312slot logici, gli ID0..311 richiesti dal layout delle partizioni; non è la dimensione intera dell’oggetto LUT. L’inizializzatore riempie2000byte a partire da`0x50E9C0`, fino a`0x50F190`, cioè1000halfword. Nella vista richiesta mancano0,161..164e300..311. Lo slot0 non viene trattato come una normale partizione: il primo stadio/BFN ha il proprio formato. Gli altri16slot mancanti appartengono alle code dei due export maggiori.

## Le sette ricostruzioni

Gli inizi e i conteggi vengono dalle halfword della tabella P1IDSTR. I nomi sotto corrispondono ai file forniti; l’identità di due contenuti non dimostra da sola un recupero automatico fra le copie.

| Export | Primo ID logico | Blocchi da128 KiB | Gruppi iniziali osservati | Blocchi finali non mappati |
|---|---:|---:|---|---:|
|BootCode|1|3|1,2,3|0|
|Calibration|6|4|12,13,14,15|0|
|Calibration_2|10|4|16,17,18,144|0|
|CameraParam|14|1|10|0|
|CameraParam_2|15|1|123|0|
|NANDReserved|16|149|285,286,287…|4|
|MainCode|165|147|146,147,148…|12|

Tutti i byte coincidono, comprese le codeFF. Restano vere anche le identità già verificate: MainCode contiene il TBM del candidato installato; BootCode contiene il TBIB originale; Reserved contiene il P1RES originale.

Per ciascun blocco mappato si prendono64record del gruppo fisico e se ne concatenano i2048byte dati. Per una voce non mappata si applica il comportamentoFF del lettore, verificato separatamente sotto. Non vengono riscritti NANDP1 o i file dell’utente: i nuovi artefatti sono nella cartella `ricostruiti/` del risultato.

## Le code FF sono una risposta del lettore

Nel percorso originale`0x1ECB0C`, il campo del blocco corrente uguale a`0xFFFF` seleziona il ramo che riempie il buffer con`0xFF`. La lunghezza è data dal numero di unità512byte per pagina. La prova esegue l’intera funzione con il sentinelFFFF e un descrittore di laboratorio che indica4unità: ottiene2048byteFF, ritorno0 e guardie prima/dopo intatte, senza chiamare il controller.

La ricostruzione usa questo contratto per161..164diReserved e300..311diMain:16blocchi, complessivamente2 MiB. Il confronto finale conferma che gli export forniti hanno esattamente queste code. È un risultato logico: non prova che esistano sedici blocchi fisici cancellati corrispondenti agli slot.

GNU usa file mappati condivisi. La modifica del test rimane in `ff_buffer_lab.bin`, una copia sintetica costruita con byteA5 e verificata a fine prova. I dump originali non sono mappe scrivibili della CPU.

## NANDPartition: unità e limite del campo P3

L’esportatore`0x30026C` ottiene una vista dal getter`0x16F3A4`. Quest’ultimo legge dieci halfword dalla P1IDSTR; per le cinque dimensioni principali applica uno shift3, cioè×8. Un blocco logico128 KiB viene così espresso in8unità da16 KiB: è la spiegazione nel codice dell’unità trovata in precedenza dal rapporto tra dimensioni e file.

Sono raccordati i tre registri, le cinque dimensioni, ProductID`0x6113` e PartitionVer`0x1009`. I nomi delle11righe e gli offset letti dal formatter sono verificati nei pool del MainCode.

**`uwSize_P3Partition` è un caso separato.** Il formatter legge la halfword+20, ma il corpo del getter controllato scrive solo+0..+18. La prova CPU preimposta+20a`0xA5A5` e dimostra che il getter lo lascia intatto. Quindi lo0nel file resta un valore osservato di quel campo software, non una prova autonoma di assenza o dimensione della partizioneP3. Gli altri eventuali scrittori non sono ancora ricostruiti.

## Copertura e questioni aperte

L’inventario dei324gruppi distingue295tag puliti,24gruppi interamenteFF, quattro gruppi con dati semprezero e sparezero nei primi4record/FF nei60successivi, più il gruppo iniziale speciale. Questi quattro gruppi sono6,100,200e263. Il pattern è documentato senza chiamarlo automaticamente «bad block fisico»: il risultato di acquisizione e gli stati del driver restano da chiarire. Il ciclo di export raw osservato avanza anche senza utilizzare il codice di ritorno della lettura per fermarsi, quindi la causa di eventuali dati anomali richiede altre prove.

Per R4 la corrispondenza dei sette export è ora completa e riproducibile. Non è ancora completa la certificazione di acquisizione, ECC, tutte le partizioni del chip, programmazione NAND o recupero. Per R3 sono note ulteriori strutture Nikon e dipendenze del loader, senza nuove allocazioni AkeruOS.

Prossimo: comprendere l’esito delle letture raw e gli spare/errori, trovare gli scrittori del campoP3 e raccordare il caricamento TBM/risorse ai servizi usati dalla futura applicazione. L’ownership dei buffer, l’avvio del nuovo task e il ciclo fotografico restano obiettivi separati e aperti; circa10% funzionale invariato.

## Continuazione: ECC e status raw — 20 ottobre 2026

Il [nuovo controllo ECC](S33_NAND_ECC_Integrita_e_Limite_Errori_Export_Raw.md) copre tutti i165.888settori del file:151.040nei gruppi mappati sono tutti coerenti;128differenze restano nei record azzerati di quattro gruppi non mappati.2.105casi CPU del correttore passati. Il ritorno di ogni lettura raw non viene propagato dall’exporter:12prove al confine del ritorno e riscontro statico, non simulazione completa. Fonti primarie Linux archiviate; nessun dump corretto o hardware modificato. Prossimo: loaderTBM/risorse e residenza.
