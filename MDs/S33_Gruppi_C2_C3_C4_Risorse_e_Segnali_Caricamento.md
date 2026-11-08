# S33 — C2, C3, C4, risorse e segnali di caricamento

20 ottobre 2026 — R0/R3/R4. Continuazione di [ClockSettings/PerfLog](S33_ClockSettings_PerfLog_e_Avvio_Osservato.md), [handoff TBIB→TBM](S33_Passaggio_TBIB_TBM_e_Ingresso_CPU.md) e [integrità NAND](S33_NAND_ECC_Integrita_e_Limite_Errori_Export_Raw.md). L’utente conferma che PerfLog e DUMPS provengono dallo stesso avvio. Nessun accesso alla fotocamera in questa verifica.

Le sigle del PerfLog sono ora collegate a sette payload TBM: **C2=2/3, C3=4/5, C4=6/7, Resource=9**, con indici a partire da zero. C3 e C4 notificano anche il completamento della prima lettura, prima di iniziare la seconda. Il marcatore End non controlla l’esito della notifica o del rilascio della sincronizzazione. Questa distinzione serve a scegliere un futuro punto di cooperazione per AkeruOS senza scambiare un evento parziale per disponibilità completa.

## Fonti e riproduzione

- [Verificatore](../Python_Trace_Scripts/s33_trace_loaded_groups_and_perf.py).
- [Evidenze del controllo riuscito](../Risultati/Dump_fotocamera/Gruppi_Caricamento/20261020T161808Z/verified_evidence.json), [indice ultima esecuzione](../Risultati/Dump_fotocamera/Gruppi_Caricamento/latest.json).
- [Mappa dei gruppi, offset, destinazioni e hash](../Risultati/Dump_fotocamera/Gruppi_Caricamento/20261020T161808Z/group_mapping.json), [otto finestre GNU](../Risultati/Dump_fotocamera/Gruppi_Caricamento/20261020T161808Z/gnu_verified.txt).
- [48 casi con chiamate attese e ritorni osservati](../Risultati/Dump_fotocamera/Gruppi_Caricamento/20261020T161808Z/protocol_cases.json), [185 PC originali eseguiti e controllati contro MainCode](../Risultati/Dump_fotocamera/Gruppi_Caricamento/20261020T161808Z/executed_original_pcs.json).
- [Sei sostituzioni dichiarate del solo laboratorio](../Risultati/Dump_fotocamera/Gruppi_Caricamento/20261020T161808Z/laboratory_trampolines.json). La copia Main0 modificata è un supporto del test, **non un firmware da installare**.

```bash
python3 Python_Trace_Scripts/s33_trace_loaded_groups_and_perf.py
```

Esito `PASS_GROUP_MAPPING_AND_CONDITIONAL_PROTOCOL`: quattro gruppi, sette triplette, checksum dei sette payload, otto finestre, 48 casi, 7.788 istruzioni nel profiler del test, exit0 e nessun fault. I 40 input registrati sono ricontrollati prima/dopo, inclusi firmware, dump, prove precedenti, strumenti e sorgenti GNU pertinenti. I 16 payload originali sono verificati dagli helper esistenti. I byte originali studiati, compresi gli helper di ritorno eseguiti, coincidono con MainCode fornito dall’utente; il candidato installato differisce altrove.

## Quali byte vengono richiesti

Offset e dimensioni sono byte nel TBM conservato all’inizio di MainCode, non offset nella NAND raw. Le destinazioni sono argomenti del loader nel firmware analizzato, non nuove aree libere o allocazioni per AkeruOS.

| Gruppo / ingresso | Indice TBM | Offset | Dimensione | Destinazione |
|---|---:|---:|---:|---:|
| C2 `0xC5910` | 2 | `0x376600` | `0x69E00` | `0x5FE800` |
| C2 | 3 | `0x3E0400` | `0x11B200` | `0x669800` |
| C3 `0xC59AC` | 4 | `0x4FB600` | `0x100200` | `0x796800` |
| C3 | 5 | `0x5FB800` | `0x10BE00` | `0x897800` |
| C4 `0xC5A50` | 6 | `0x707600` | `0x1BB400` | `0x9A3800` |
| C4 | 7 | `0x8C2A00` | `0x6A00` | `0xC67800` |
| Resource `0xC5AF4` | 9 | `0x8C9A00` | `0x290600` | `0xC8F800` |

Ogni tripletta del pool coincide con offset, dimensione e base del manifest; il contenuto richiesto coincide integralmente con il payload e la somma word LE del descrittore. Tutti e sette i record sono di tipo0. I record di tipo1 sono invece 0, 1 e 8, già associati al caricamento iniziale nel rapporto TBIB; il record16 di tipo2 contiene l’ingresso `0xBB540`. Non è un diciassettesimo payload.

**Load Resource si riferisce qui al payload TBM9.** La firma P1RES ricostruita da NANDReserved appartiene a un altro oggetto. Questo risultato non ricostruisce ancora il caricamento del payload10 o la residenza alternativa dei payload11–15 a base condivisa `0x01044800`.

## Il confronto con il PerfLog reale

| Gruppo | ID Start / End | Start | End | Differenza nelle unità stampate |
|---|---|---:|---:|---:|
| C2 | `0xB80038` / `0xB80039` | 363281 | 508697 | 145416 |
| C3 | `0xB8003A` / `0xB8003B` | 515686 | 684936 | 169250 |
| Resource | `0xB8003E` / `0xB8003F` | 684936 | 892974 | 208038 |
| C4 | `0xB8003C` / `0xB8003D` | 1202789 | 1347167 | 144378 |

Le etichette e gli ID sono quelli già decodificati dall’export dello stesso avvio. La scala runtime resta aperta: nessuna conversione nuova in secondi o frequenze fisiche. Nel flusso statico `0xC58C8` l’ordine è C2, callback opzionale, C3, Resource, chiamata `0x159128`, C4, richiesta evento `0x80`. Il chiamante non confronta i ritorni dei quattro wrapper fra queste fasi; la sola sequenza delle chiamate non certifica propagazione completa degli errori.

## Lettore comune e selezione della sorgente

I wrapper registrano Start con `0x12CAD4`, poi chiedono la sincronizzazione `0x1593AC(0x00300008,0)`. Un ritorno nonzero termina il wrapper senza letture né End. Dopo l’acquisizione leggono il byte `0x928`, cioè base letterale `0x900` più40:

- `0x10`: chiamano `0x159550(0,0)`.
- `0x20`: il getter `0xC76C4` restituisce la stringa `B:\TBM_SK501.BIN` a `0x377DB8`, poi chiamano `0x159550(path,0)`.
- Altri valori: saltano la configurazione, usando il contesto precedente non ricostruito qui.

`0x159550` scrive soltanto puntatore e offset base nel contesto `0x3672A4`. Il lettore `0x159558(offset,lunghezza,destinazione)` aggiunge l’offset base. Con puntatore nullo usa `0x23F08C` con selettore6 e traduce il ritorno zero in successo booleano1. Con puntatore non nullo segue open/seek/read/close, controllando gli esiti di apertura, posizione e quantità letta; sul percorso finale il ritorno di close non è usato per decidere il booleano di successo. Correzione 27 ottobre 2026: se offset effettivo o lunghezza è zero, il codice salva `1` nel campo di stato e restituisce **0** (fallimento), senza chiamare il backend; questi casi non erano selezionati dalle sette triplette del campione. Vedi [verifica GUI](S33_GUI_Base_JPEG_e_Lettore_20261027.md).

Il ramo è quindi identificato staticamente; **il valore runtime di `0x928` non è presente nei dump forniti**. I test impostano esplicitamente tre valori di laboratorio, senza attribuirne uno alla macchina. Il lettore studiato non confronta il checksum RHIR di questi sette payload; i checksum verificati sul computer provano l’identità dei byte analizzati, non un controllo runtime automaticamente eseguito.

## Segnali intermedi, finali e percorsi d’errore

| Gruppo | Sequenza delle richieste a `0x158CBC` sull’evento `0x42700002` |
|---|---|
| C2 | maschera `0x04` dopo entrambe le letture riuscite |
| C3 | `0x08` dopo payload4; `0x10` dopo payload5 |
| C4 | `0x20` dopo payload6; `0x40` dopo payload7 |
| Resource | nessuna richiesta evento nel proprio wrapper |

Il riferimento evento è distinto dall’identificatore di sincronizzazione `0x00300008`. Le richieste avvengono prima del rilascio `0x1594A4`; il servizio reale, i task risvegliati e la concorrenza non sono eseguiti nel test.

Se la prima lettura fallisce, il wrapper tenta il rilascio ed esce senza End. Se fallisce la seconda, C3 ha già richiesto `0x08` e C4 ha già richiesto `0x20`, ma manca il rispettivo segnale finale. C2 non ha ancora richiesto `0x04`. Il fallimento della richiesta evento non impedisce la lettura successiva o End; anche il ritorno del rilascio non viene confrontato prima di End.

Nel contesto esplicito delle prove, con profiler e rilascio normali che restituiscono zero, i wrapper ritornano zero sia dopo successo sia dopo fallimento della lettura: **il ritorno finale non è il booleano del lettore**. Per capire la disponibilità dei servizi servono quindi anche i consumatori dei bit, le eventuali cancellazioni e i percorsi di recupero.

## Cosa è stato eseguito e cosa resta simulato

Il test conserva i quattro wrapper, i loro pool, il getter del percorso e gli helper originali di ritorno. Sostituisce soltanto sei ingressi di servizio in una copia isolata di Main0: profiler, acquisizione, configurazione lettore, lettura, notifica evento e rilascio. Gli stub registrano gli argomenti e restituiscono valori scelti dal caso. Non trasferiscono payload, non aprono file e non sincronizzano task.

Per C2/C3/C4: due modalità × sei esiti (successo, errore acquisizione, prima lettura, seconda lettura, notifica, rilascio), più un caso modalità0. Per Resource: due modalità × quattro esiti pertinenti, più modalità0. Totale48. Sono confrontati numero, ordine e argomenti significativi delle chiamate; il ritorno del wrapper viene conservato. Sono controllati i byte presso185PC originali effettivamente eseguiti. Questa copertura condizionale non è un boot, un test dei backend o una misura della macchina.

I tentativi precedenti restano conservati: una doppia mappa a `0x900` si sovrapponeva alla mappa bassa ELF; le prime mappe corte degli stub non coprivano il prefetch di8byte del decoder GNU all’ultima istruzione. Corretto esclusivamente l’allestimento del test: usa la mappa ELF già esistente e padding nelle copie stub. Nessuna istruzione dei wrapper o sorgente GNU è stata modificata per aggirare un errore.

## Continuazione per AkeruOS

Seguire i consumatori dell’evento `0x42700002`, distinguendo bit parziali/finali, attese, cancellazioni e proprietà dei dati. Poi collegare il payload10 e gli overlay11–15 ai loader e al loro ultimo uso prima di scegliere memoria o ingresso per AkeruOS. Restano aperti scala temporale runtime, checksum dei caricamenti differiti, ownership, gestione completa degli errori e recupero fisico. Il circa10% funzionale rimane invariato: nessun avvio o fotografia della nuova applicazione.

## Continuazione — Load Later e consumatori verificati

Il [rapporto sul protocollo](S33_Load_Later_Attese_Bit_Persistenti_e_Limite_Ready.md) identifica il task Load Later, il consumatore parziale08 e gli helper finali80.790prove con operazioni bit originali,3072predicate,6iterazioni limitate e8coordinatori con letture simulate. Il segnale80 compare anche con errore; Resource fallito lascia tutti i bitFC come nel successo. Preparazione e richieste sono distinte: i bit persistenti non hanno una generazione implicita. Prossimo: payload10/overlay11–15, ownership ed errori; nessun trasferimento o scheduler reale eseguito.
