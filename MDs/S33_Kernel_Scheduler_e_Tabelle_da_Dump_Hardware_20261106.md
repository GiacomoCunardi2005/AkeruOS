# Mappa dello scheduler e delle tabelle del kernel dal dump hardware

6 novembre 2026. Mappa ricavata da `Risultati/Dump_fotocamera/MEMDUMP_20261106/MEMDUMP.BIN` ([analisi](S33_MEMDUMP_Analisi_Dump_Hardware_20261106.md)), letta con script Python a partire dai layout già documentati ([bootstrap](S33_Bootstrap_Kernel_e_Pool_Iniziale.md), [stack e contesto](S33_Task_Stack_Contesto_e_GP.md), [attesa e risveglio](S33_Dumper_RAM_SD_Scadenza_Risveglio_e_Progress_Originali.md), [vettori](S33_Timer1_Callback_Differiti_Dispatch_Kernel.md)). Tabella completa dei task: `Risultati/Dump_fotocamera/MEMDUMP_20261106/task_table.csv`. Il dump è un'istantanea non atomica: i valori sono di un solo istante e possono essere incoerenti fra loro.

## Oggetto kernel `K = 0x1800` (puntatore in `[0x369348]`)

| Campo | Valore osservato | Significato |
|---|---|---|
| `K+0x1C` | `0x5291C` | task corrente = TCB di MEMDUMP |
| `K+0x34` / `+0x38` | `362` / `0` | tempo del kernel in tick (64 bit); la frequenza reale del tick non è misurata |
| `K+0x4C` / `+0x50` / `+0x54` | `0xAF9C` / `0x38D9C` / `2` | lista temporizzata: testa UITimer, coda CapMgrTaskVFSetting, 2 nodi |
| `K+0x22C` / `+0x230` / `+0x238` | `0` / `0xF` / `0x285C` | tabella vettori: indici 0..15, puntatore alla tabella |
| `K+0x46C` / `+0x470` / `+0x474` | `0x372A54` / `0x373CB4` / `85` | lista globale di oggetti kernel (semafori, eventi): contatore 85 |

## Code ready

Una coda circolare per priorità, 16 byte ciascuna: **testa(prio) = `0x27AC − 16·prio`**, verificata sulle priorità 1, 4, 5, 11, 17, 19, 20, 80 e 101 (campo `TCB+0x1C`). Priorità minore = più urgente (Timer Task = 1, idle = 101). Al momento del dump le code non vuote sono due: **priorità 19** con il solo TCB `0x5291C` (MEMDUMP, in esecuzione) e **priorità 101** con `_mqx_idle_task`. Gli altri task erano in attesa.

## Formato del TCB (confermato sul dump)

| Offset | Contenuto |
|---|---|
| `+0x08` | stato (`0x2` pronto, `0x3`, `0x42B`/`0x42D` attesa evento o semaforo, `0x52D` attesa evento con scadenza, `0x102`) |
| `+0x10` / `+0x14` / `+0x18` | cima stack T, contesto salvato F, limite basso |
| `+0x1C` | testa della coda ready della priorità |
| `+0x30` | lista waiter dell'oggetto su cui attende |
| `+0x54` | puntatore al template (indice, entry, stack, priorità, nome, attributi, parametro, timeslice) |
| `+0x5C` | scadenza in tick (word bassa) |
| `+0x6C` | attributi |
| `+0xBC` | nodo del task nella lista waiter dell'evento |

## Tabella vettori (16 voci, 12 byte: handler, riservato, argomento)

Voci 0 e 1 e 11–15 puntano al gestore predefinito `0x319018` con il numero di indice come argomento. Gestori specifici: vettore 2 `0x16DAF0`, 3 `0x29F740`, 4 `0x2640E0`, 5 `0x264198`, 6 `0x264250`, 7 `0x146104`, 8 `0x2643E0`, 9 `0x264308`, 10 `0x264498`.

## Task (49 TCB reali, ordinati per priorità)

| Task | TCB | Entry | Prio | Stato | Stack | Usato (byte) |
|---|---|---|---:|---|---|---:|
| Timer Task | `0x7c9c` | `0xb2538` | 1 | `0x42b` | `0x800` | 264 |
| LensCtrl | `0x3cb9c` | `0x14661c` | 3 | `0x42d` | `0x800` | 1232 |
| Recorder Still Task | `0x1571c` | `0x12e720` | 4 | `0x52d` | `0x1000` | 544 |
| Audio FIFO R/W | `0x39f1c` | `0x1605bc` | 4 | `0x42d` | `0x1000` | 248 |
| VIS Exec Task | `0x1ae9c` | `0x15c068` | 5 | `0x42d` | `0x1000` | 336 |
| CapMgrTaskVFSetting | `0x38d9c` | `0x14a644` | 5 | `0x52d` | `0x1000` | 2640 |
| Video Compress and Decompress | `0x46c9c` | `0x1626fc` | 5 | `0x42d` | `0x1800` | 240 |
| MCUCTRL_Task | `0x10e9c` | `0x15a80c` | 6 | `0x42d` | `0x800` | 248 |
| GainAdjust Task | `0x19d1c` | `0x15b1dc` | 7 | `0x42d` | `0x1000` | 240 |
| HDRVIS Exec Task | `0x1c01c` | `0x15b364` | 8 | `0x42d` | `0x1000` | 272 |
| TDNR Task | `0x1e31c` | `0x15c938` | 8 | `0x42d` | `0x1000` | 536 |
| HDR Map Task | `0x1f49c` | `0x15b520` | 9 | `0x42d` | `0x1000` | 248 |
| GTE Task | `0x2291c` | `0x15d004` | 9 | `0x42d` | `0x1000` | 440 |
| HDR Tone Task | `0x2061c` | `0x15b71c` | 10 | `0x42d` | `0x1000` | 248 |
| SCL0 Task | `0x23a9c` | `0x15dbf8` | 10 | `0x42d` | `0x1000` | 256 |
| SCL1 Task | `0x24c1c` | `0x15deb0` | 10 | `0x42d` | `0x1000` | 248 |
| CapMgrTask | `0x33c1c` | `0x14a4c4` | 10 | `0x42d` | `0x5000` | 248 |
| AuxTask | `0x1229c` | `0x15968c` | 11 | `0x42d` | `0x1000` | 3368 |
| LVhwirp Task | `0x2179c` | `0x15b8d0` | 11 | `0x42d` | `0x1000` | 256 |
| DACS_Task | `0x2d8dc` | `0x1599c4` | 11 | `0x2` | `0x1000` | 1336 |
| DACS_Third_Task | `0x32a9c` | `0x159c98` | 11 | `0x42d` | `0x1000` | 240 |
| AuxTask3 | `0x1459c` | `0x1596e4` | 12 | `0x42d` | `0x1000` | 640 |
| Recorder Video LV Disp Task | `0x1689c` | `0x1638d8` | 14 | `0x42d` | `0x1000` | 256 |
| SoundResPlayTask | `0x3c21c` | `0x1627c0` | 15 | `0x42d` | `0x800` | 248 |
| GEN LDC LUT Task | `0x1d19c` | `0x15c4e8` | 16 | `0x42d` | `0x1000` | 512 |
| UITimer | `0xaf9c` | `0x149228` | 17 | `0x102` | `0x800` | 432 |
| WindowMgr | `0x861c` | `0x15af0c` | 18 | `0x42b` | `0x2800` | 1768 |
| UIAux | `0xb91c` | `0x15b06c` | 19 | `0x42d` | `0x5400` | 280 |
| Load Later | `0x3d51c` | `0xc5830` | 19 | `0x42d` | `0x2800` | 664 |
| MEMDUMP | `0x5291c` | `0xe99efc` | 19 | `0x52d` | `0x8000` | 1608 |
| Take still inside Video | `0x17a1c` | `0x1637bc` | 20 | `0x42d` | `0x1000` | 280 |
| PacketIRPTask | `0x25d9c` | `0x160090` | 20 | `0x42d` | `0x2800` | 232 |
| ImgMgrReviewTask | `0x4419c` | `0xafa08` | 20 | `0x42d` | `0x1000` | 624 |
| MountSort_Storage_Task | `0x5059c` | `0xc7c14` | 20 | `0x3` | `0x1000` | 2104 |
| AuxTask2 | `0x1341c` | `0x1596b8` | 21 | `0x42d` | `0x1000` | 304 |
| PacketIRPTask2 | `0x2871c` | `0x1600c0` | 21 | `0x42d` | `0x1000` | 232 |
| ImgMgrIRPTask | `0x3fe9c` | `0x15a478` | 21 | `0x42d` | `0x2800` | 240 |
| ImgMgrIRPTask2 | `0x4281c` | `0x15a51c` | 22 | `0x42d` | `0x1800` | 240 |
| ImgMgrJPEGTask | `0x4531c` | `0x15a764` | 23 | `0x42d` | `0x1800` | 232 |
| Video File R/W  | `0x4861c` | `0x162734` | 26 | `0x42d` | `0x1800` | 240 |
| Audio File R/W | `0x3b09c` | `0x1606b0` | 27 | `0x42d` | `0x1000` | 248 |
| BatCharge_Task | `0x1191c` | `0x167054` | 28 | `0x42d` | `0x800` | 256 |
| ComMgrTask | `0x49f9c` | `0x138e20` | 29 | `0x42d` | `0x2000` | 240 |
| NCTFAFTask | `0x4c11c` | `0x167734` | 29 | `0x42d` | `0x1000` | 272 |
| FILE_REVIEW_SORT_Task | `0x4ec1c` | `0x136490` | 29 | `0x42d` | `0x1800` | 3576 |
| Recorder Still LVAUX Task | `0x18b9c` | `0x13091c` | 30 | `0x42d` | `0x1000` | 240 |
| DPOFMrkSortTask | `0x4d29c` | `0x163574` | 30 | `0x42d` | `0x1800` | 320 |
| RTOSINIT | `0x2edc` | `0x167a20` | 80 | `0x3` | `0x2800` | 2392 |
| _mqx_idle_task | `0x2b5c` | `0x2f6c3c` | 101 | `0x2` | `0x200` | 184 |

Altre strutture simili trovate dalla ricerca (`0x3FC94`, `0x3FCDC`, `0x3FD20`, `0x158FF0`, `0x423718`, `0x47CC20`, `0x5DACE8…`) sono copie del template o falsi positivi e non sono nella tabella. Lo stack usato è la distanza dalla cima al primo punto non più riempito di `katskats` (soglia al momento del dump, non il massimo storico stretto).

## Cosa dice sul nostro task

- MEMDUMP è l'unico task della priorità 19 in coda ready: stava eseguendo. Lo stato `0x52D` e la scadenza `387` (tick correnti `362`) sono residui di un'attesa evento con timeout dalla quale è stato svegliato dall'evento (la scrittura SD), prima della scadenza. Compatibile con `phase = 3` dell'adapter (dump catturato durante la scrittura).
- Priorità 19 coincide con `Load Later` (`0x3D51C`); stack di MEMDUMP usato 1584 byte su 32768.
- La scadenza 387 è in tick di kernel come il tempo 362: la frequenza del tick non si ricava da questo istante. Resta da misurare.

## Limiti

- Un solo istante, dump non atomico; i campi di stato dei task non in esecuzione sono affidabili, quelli del task in corso sono spesso residui.
- Lista globale: la camminata da `K+0x46C` segue 27 nodi su 85 dichiarati; non ho risolto il formato dei nodi. Niente di quanto sopra la richiede.
- Tabella vettori: gestori osservati, non nominati. La mappa vettori ↔ periferiche non è fatta.
- Gli stati `0x3`, `0x102` e `0x35` non sono tutti attribuiti.
- Solo `[0, 0x0104074C)`: strutture oltre non sono viste.

**Prossimo:** nominare i gestori dei vettori, risolvere i nodi della lista globale e confrontare con un secondo dump (altro istante). Nessuna operazione su hardware.

Stato reale della GUI (finestre, messaggi, timer): [dettaglio](S33_GUI_Stato_Reale_da_Dump_Hardware_20261106.md).
