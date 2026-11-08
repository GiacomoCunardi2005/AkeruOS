# MEMDUMP versione 6: intervallo scelto `[0x0F600000, 0x0F700000)` (offline, NON INSTALLARE)

6 novembre 2026. Priorità 6 del `goal.txt`: preparare, separato dalla GUI, un dump mirato della RAM alta. Basato sul [v5 con handle esclusivo](S33_MEMDUMP_Versione5_Handle_Esclusivo_20261106.md) e sulla [decisione](S33_GUI_Prima_Schermata_AkeruOS_e_Decisione_Dump_20261106.md). **Non installato né copiato su SD; nessun accesso alla fotocamera.** L'intervallo è di **1 MiB esatti** (`0x0F700000 − 0x0F600000 = 0x100000`: il calcolo del rapporto originale era corretto) e contiene il piano OSD osservato (`0x0F688400`, vedi [integrazione manager](S33_GUI_Integrazione_Manager_Nikon_e_Validazione_muludw_20261106.md)).

## Candidato

[firmware.bin v6](Risultati/Firmware_sperimentali/MEMDUMP/OFFLINE_NON_INSTALLARE_20261106T183614975474Z//firmware.bin), SHA-256 `9b00a67aa3b473c27f10f49af47d4a74f9bcb86dcec87703041c35c2170bc879`, 29.602.084 byte, 1058 byte cambiati in 5 regioni (hook `0xC58EE`, due call site `0x16ED84/0x16ED98`, guardia, Resource), ripristino dell'originale verificato. Firma versione 6 (rifiuta i Resource v3/v4/v5).

Cosa cambia rispetto alla v5:

- **Adattatore** (`AkeruOS/nikon_v11_memdump_held_range.c`): le richieste del diagnostico restano controllate come prima (256 byte, poi `0x100`/`0x0104064C`), ma la seconda scrittura usa come sorgente **`0x0F600000`** e lunghezza **`0x100000`**. Asserzioni a compilazione: l'intervallo deve stare in `[0x0F600000, 0x0F700000)`; start o fine fuori fascia (per esempio `0x0FE00000`, la riserva MMIO) **non compilano** (provato).
- **Task** (`nikon_v11_memdump_worker_range.c`): scrive su **`B:\MEMHI.BIN`** (creazione esclusiva) per non scontrarsi con un `MEMDUMP.BIN` esistente; l'adattatore scrive sull'handle già aperto, senza dipendere dal nome.
- Il file sarebbe di **256 + 1.048.576 byte**. Il primo segmento (256 byte) è quello del diagnostico originale; il secondo è l'intervallo scelto.

## Verifiche offline

| Verifica | Esito |
|---|---|
| Test host con ASan/UBSan (`AkeruOS/tests/nikon_v11_memdump_range_test.c`): primo segmento invariato, sostituzione sorgente/lunghezza della seconda, terza chiamata rifiutata, richieste diverse rifiutate, conteggio corto, errore di scrittura propagato, altro task inoltrato, nome diverso rifiutato | PASS |
| Stessi 9 casi compilati per ARC700 ed eseguiti nel simulatore GNU (`s33_verify_memdump_held_adapter.py --range`, evidenza `Risultati/Runtime_Kernel/MEMDUMP_Range_Adapter/20261106T183632732149Z/`) | PASS (scrittura e I/O sono fixture) |
| Regressione dell'adattatore v5 (`s33_verify_memdump_held_adapter.py`) | PASS |
| Builder: checksum dei 16 blocchi, perimetro del delta, ripristino dell'originale, call site `bl 0x12BD5C` riconosciuti | PASS |
| Compilazione con intervallo fuori fascia | respinta (come voluto) |

## Non verificato (impedisce l'installazione)

- La **lettura sequenziale** di tutto `[0x0F600000, 0x0F700000)` su hardware: che il firmware scriva a quegli indirizzi e che il test memoria del boot li tocchi (a passi di 1 MiB) **non prova** che una lettura sequenziale completa non causi errori di bus o altri effetti.
- Il percorso integrato (hook + task + FAT con sorgente reale in RAM alta) non è stato eseguito: il test P-code integrato della v5 usa una RAM sintetica che non include quella fascia.
- La scrittura del file da 1 MiB su SD reale, la durata, gli errori di volume pieno e il recupero.
- Un dump non atomico: il piano OSD cambia mentre viene letto.

Prima di qualsiasi installazione servono il consenso esplicito dell'utente e una procedura di recupero decisa insieme. **NON INSTALLARE.**
