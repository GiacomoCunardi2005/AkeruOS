# NAND: P1IDSTR, ricostruzione BootCode e passaggio al TBIB

20 ottobre 2026 — R0/R3/R4. La tabella `P1IDSTR` dei dump è ora raccordata al loader del primo stadio: i blocchi indicati ricostruiscono **tutti i393.216byte di BootCode.dmp**. Il codice originale, avviato nel laboratorio dopo il trasferimento, verifica il corpo e raggiunge davvero l’ingresso TBIB`0x01000000`. Il contesto prima del trasferimento e l’avvio completo restano aperti.

## Prove riproducibili

- [Script](../Python_Trace_Scripts/s33_verify_nand_boot_table_handoff.py), [indice corrente](../Risultati/Dump_fotocamera/NAND_Loader/latest.json).
- [Evidenze](../Risultati/Dump_fotocamera/NAND_Loader/20261020T154447Z/verified_evidence.json), [mappa blocchi e copie](../Risultati/Dump_fotocamera/NAND_Loader/20261020T154447Z/block_mapping.json), [sei finestre GNU](../Risultati/Dump_fotocamera/NAND_Loader/20261020T154447Z/gnu_verified.txt).
- [BootCode ricostruito](../Risultati/Dump_fotocamera/NAND_Loader/20261020T154447Z/bootcode_reconstructed.bin), [tabella estratta](../Risultati/Dump_fotocamera/NAND_Loader/20261020T154447Z/p1idstr_mmap.bin).
- [Caller dei test helper](../Risultati/Dump_fotocamera/NAND_Loader/20261020T154447Z/table_helpers.s), [traccia helper](../Risultati/Dump_fotocamera/NAND_Loader/20261020T154447Z/table_helpers.trace).
- [Caller handoff](../Risultati/Dump_fotocamera/NAND_Loader/20261020T154447Z/post_transfer_handoff.s), [traccia handoff](../Risultati/Dump_fotocamera/NAND_Loader/20261020T154447Z/post_transfer_handoff.trace).

Comando effettivamente eseguito dalla radice:

```bash
python3 Python_Trace_Scripts/s33_verify_nand_boot_table_handoff.py
```

Esito `PASS_NAND_BOOT_TABLE_AND_CONDITIONAL_HANDOFF`. Il primo programma esegue4controlli della firma, il calcolo del numero blocchi e il checksum dell’intero corpoTBIB:352.325istruzioni del profiler, exit0, nessun fault. Il secondo esegue il percorso originale checksum→salto:351.972istruzioni, ingressoTBIB raggiunto, poi arresto esplicito descritto sotto. Nessun load/storeMMIO eseguito nei due casi.

Ricontrollati gli input fissati dal [checkpoint DDR precedente](S33_BootNAND_DDR_ID_Dimensione_e_Checksum.md), compresi i14dump, originale V1.1 e strumenti GNU. Sono riusati il runner e il compilatore di probe esistenti; nessun builder GNU eseguito. Originali, installazioni, sorgenti e toolchain intatti. I file mappati dalla CPU sono copie nei risultati; le mutazioni per i test della firma vengono ripristinate e tutti i file mappati sono confrontati col contenuto iniziale a fine prova.

## Le24copie della tabella

Nei quattro record BFN identici, basi raw`0x2100`,`0x2940`,`0x3180`,`0x39C0`, si trovano sei copie ciascuno della stessa tabella244byte. I primi e gli ultimi8byte sono `P1IDSTR\0`; l’ultima firma parte a offset`0xEC`, cioè236.

Le posizioni delle24copie sono verificate nel JSON. Per ogni base record`b`, la posizione è:

```text
b + j*528 + 10 + k*256
j = 1,2,3; k = 0,1
```

È una descrizione del layout osservato **in quei record**, non una regola globale per rimuovere ECC da tutta la NAND. Il classificatore aveva già trovato un impacchettamento particolare512/528 per gli8192byte BootNAND iniziali; i blocchi BootCode selezionati sotto corrispondono invece a2048byte dati per record2112.

Nel codice `0x0F8006D4`, dopo controlli sul controller, cinque halfword vengono scartate e122halfword vengono copiate nel buffer tabella:10byte più244byte. Le chiamate all’helper`0x0F8006AC` confrontano la firma all’inizio e a+236. Il codice e le dimensioni concordano con i dati. La routine di confronto è eseguita nel test con le due firme valide, poi con una modifica a ciascuna firma:2uguaglianze e2differenze riconosciute.

Non è dimostrato che le24copie siano indipendenti sul dispositivo, né un percorso di fallback tra tutte le copie. Nel tratto studiato un confronto errato porta alla segnalazione, non è stata ricostruita una selezione robusta delle copie.

## Il contratto del TBIB nella tabella

I quattro campi consecutivi coincidono esattamente con i primi16byte di BootCode.dmp:

| Offset tabella | Valore | Uso verificato nel loader |
|---:|---:|---|
|`0xB4`|`0x01000000`|Indirizzo del corpo|
|`0xB8`|`0x00044BBC`|Lunghezza corpo:281.532byte|
|`0xBC`|`0xF3F78173`|Somma attesa del corpo|
|`0xC0`|`0x01000000`|Punto d’ingresso|

Le halfword da+8 contengono inizialmente1,2,3,4,5, poi0. Il calcolo di capienza seleziona i primi tre valori per questo campione; la presenza di4e5 non prova che siano copie di recupero.

Il loader`0x0F801140` legge dal BFN gli offset+88 e+92:6e`0x20000`. Il primo scala l’ID blocco nella prima pagina con uno shift6; il secondo è usato nel calcolo del numero di blocchi. I dati sono coerenti con64record per blocco e2048byte dati per record, cioè128 KiB. BFN+84 vale64, coerente col medesimo conteggio.

Il numero letto dal codice è:

```text
ceil((lunghezza_corpo + 32) / dimensione_blocco)
= ceil((0x44BBC + 32) / 0x20000)
= 3
```

L’offset+32 è quello del codice, senza sostituirlo con la dimensione16byte dell’header. Il probe esegue le istruzioni originali di preparazione e il divisore`0x0F801D24`; il risultato è3. Il primo indirizzo di destinazione è invece base_corpo−16=`0x00FFFFF0`, così l’header letto dalla NAND precede il corpo che deve iniziare a`0x01000000`.

## Tre blocchi, corrispondenza integrale

| ID | Primi record raw | Offset NANDP1 | Destinazione candidata | Dati |
|---:|---:|---:|---:|---:|
|1|64|`0x21000`|`0x00FFFFF0`|`0x20000`byte|
|2|128|`0x42000`|`0x0101FFF0`|`0x20000`byte|
|3|192|`0x63000`|`0x0103FFF0`|`0x20000`byte|

Per ciascun blocco si concatenano i primi2048byte di64record con stride2112. Il risultato393.216byte coincide **interamente** con BootCode.dmp, compreso il padding finale. Il corpo da+16, lungo`0x44BBC`, coincide già con il TBIB originale della V1.1 e ha la somma attesa. La ricostruzione è eseguita sui file; la CPU non simula il trasferimento NAND né interpreta gli altri64byte di ciascun record.

La geometria è supportata per questo percorso e questi blocchi. Non è una certificazione di tutta la NAND, degli eraseblock fisici, della gestione bad block o della proiezione completa MainCode/Reserved. Le corrispondenze parziali di questi ultimi nel [rapporto generale](S33_Classificazione_Dump_Fotocamera.md) rimangono limiti aperti.

## Verifica CPU del salto originale

Il caller fornisce un puntatore di laboratorio alla tabella e l’immagine già ricostruita. Entra a`0x0F801444`, cioè dopo il trasferimento. Da qui i byte originali:

1. Caricano base, lunghezza, checksum edentry dalla tabella; la lettura di entry è nel delay slot del salto a`0x0F80148C`.
2. Chiamano l’helper originale`0x0F800350` su tutto il corpoTBIB.
3. Confrontano la somma con`0xF3F78173` e prendono il ramo di successo.
4. Scrivono`0x0FC00000` inAUX`0x18`.
5. Eseguono`j [r13]` e raggiungono`0x01000000`.

La traccia mostra sia il salto sia istruzioni originali del TBIB. Il TBIB imposta`sp=0x010D716C`, sottrae16byte e chiama`0x0103AE88`; il primo push tenta una scrittura4byte a`0x010D7158`. Il laboratorio non fornisce lo stackTBIB a quell’indirizzo e il motore si ferma esattamente lì. Questo arresto è ora un’asserzione del verificatore.

**Non è un brick o un guasto osservato sulla fotocamera.** Non è stato aggiunto uno stack o un valoreMMIO per continuare senza prima stabilirne provenienza e proprietà. Il successo condizionale riguarda checksum e handoff a immagine già caricata, non l’esecuzione del controller, la ROM, la selezione della copia o il boot completo.

## Continuazione per AkeruOS

R4 dispone ora di una catena concreta tra configurazione, lista blocchi, header del boot e ingressoTBIB, ricavata dai nuovi dump. R3 può raccordare lo stato lasciato dal primo stadio al TBIB, senza scegliere un ingresso isolato a caso. Questo non assegna RAM al nuovo programma e non dimostra recupero dopo modifiche.

Prossimo: decodificare i campi di partizione rimanenti e il formato consumato dal managerNAND MainCode, quindi spiegare le divergenze delle proiezioni MainCode/Reserved e la copertura del dumpNANDP1. Il passaggio TBIB→Main resta da raccordare con stato conservato e controlli reali; gli esperimenti precedenti che iniziavano direttamente alTBIB restano contesti distinti. Nessun aumento dell’avanzamento fotografico AkeruOS.

## Continuazione: ricostruzione logica completa — 20 ottobre 2026

La [mappa logica dai metadati NAND](S33_NAND_Mappa_Logica_e_Ricostruzione_Integrale_Export.md) supera il limite delle proiezioni parziali: tutti i7export sono ricostruiti byte per byte,40.501.248byte totali.295IDunivoci negli spare e16slot finali FF secondo il lettore verificato;304casi CPU. La semplice concatenazione fisica resta una proiezione errata per MainCode/Reserved. Non è una certificazione di ECC, chip intero o recupero. P3nel testo non viene aggiornato dal getter. Prossimo: esiti lettura raw/P3 e loaderTBM/risorse.
