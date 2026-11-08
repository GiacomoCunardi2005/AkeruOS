# NAND dal PC: verifica indipendente di journal/parziali e confronto con i dump noti

21 ottobre 2026 — R0/R3/R4, continuazione del [client dump di blocchi](S33_NAND_PC_Client_Dump_Blocchi_Doppia_Lettura_e_Parziali.md). Implementato il **verificatore indipendente** richiesto come prossimo passo lato PC: `s33_verify_nand_pc_dump_journal.py` non esegue il client né riusa i suoi percorsi, ma rilegge soltanto gli artefatti lasciati da un'acquisizione (manifest, diario, raw/parziale) e **ricomputa ogni affermazione dai byte**. Tutti i dieci artefatti degli scenari offline esistenti risultano coerenti; sette manomissioni deliberate vengono tutte rifiutate; un fixture costruito da record reali di `NANDP1.dmp` viene ritrovato allineato nei dump noti; il dump doppio del LUN MSDC viene riverificato per intero. Nessun hardware, nessuna scrittura, candidato invariato NON_INSTALLARE.

## File e riproduzione

- [Verificatore](../Python_Trace_Scripts/s33_verify_nand_pc_dump_journal.py), [evidenza](../Risultati/USB_SCSI/Accesso_NAND_PC/pc_dump_journal_20261021T160631Z/verified_evidence.json), [indice latest](../Risultati/USB_SCSI/Accesso_NAND_PC/pc_dump_journal_latest.json).
- Input verificati in sola lettura: scenari [pc_dump_20261021T143223Z](../Risultati/USB_SCSI/Accesso_NAND_PC/pc_dump_20261021T143223Z/verified_evidence.json), [LUN interno](../Risultati/Hardware/MSDC_Default/LUN_interno_20261021T155624Z/journal.json), `DUMPS/NANDP1.dmp`, `DUMPS/MainCode.dmp`, `DUMPS/NANDReserved.dmp`, `DUMPS/BootCode.dmp`.

```bash
python3 Python_Trace_Scripts/s33_verify_nand_pc_dump_journal.py                 # autotest offline completo
python3 Python_Trace_Scripts/s33_verify_nand_pc_dump_journal.py CARTELLA        # verifica una singola acquisizione
python3 Python_Trace_Scripts/s33_verify_nand_pc_dump_journal.py CARTELLA --compare-known
```

## Cosa ricomputa il verificatore

Per ogni cartella di acquisizione, senza eseguire il client:

- **Manifest**: costanti del profilo driver (2112 byte/pagina, 64 pagine/blocco) ridichiarate in modo indipendente; range entro chip0..255/blocchi0..511; `pages_written` uguale al numero di righe del diario; `bytes_written` uguale a pagine×2112; `pages_expected` uguale a blocchi×64.
- **Diario**: coordinate che coprono esattamente il range richiesto in ordine lineare, senza salti né duplicati; offset contigui; per ogni riga lo SHA-256 ricomputato dal file raw alla posizione dichiarata coincide con quello registrato; il file raw non è più lungo del diario né più corto di `bytes_written`.
- **Stato**: `COMPLETE_DOUBLE_READ_LOCAL_FILE_VERIFIED` richiede `dump.raw` presente, `dump.raw.partial` assente, sha256 del manifest uguale all'hash ricomputato dell'intero file e pagine scritte uguali alle attese; `FAILED` richiede il parziale preservato, assenza del file finale, coordinate di errore uguali all'ultima pagina completata o alla successiva attesa; `RUNNING` viene esplicitamente segnalato `INCOMPLETE_RUNNING`, mai accettato come finale; `FAILED_BEFORE_ACQUISITION` richiede zero pagine e nessun file raw.

## Copertura delle prove eseguite

|Gruppo|Esito|
|---|---|
|10 artefatti degli scenari offline esistenti (2 completi, 7 falliti, 1 pre-acquisizione)|tutti coerenti; ogni hash di pagina ricomputato; contenuto sintetico ricalcolato per intero dal verificatore|
|7 manomissioni su copie: byte capovolto nel raw, hash diario contraffatto, riga rimossa, coordinate invertite, `pages_written` gonfiato, parziale troncato, FAILED ribattezzato COMPLETE|tutte e 7 rifiutate con AssertionError; la copia intatta resta valida; manifest RUNNING segnalato incompleto|
|Confronto con dump noti: fixture da 128 record unici reali di `NANDP1.dmp` (record 63..190)|verifica artefatti superata; tutte le 128 pagine ritrovate allineate in NANDP1 ai record attesi; byte casuali mai abbinati|
|Riverifica LUN MSDC reale: `read1.img`/`read2.img` 23.068.672 byte|sha256 ricomputati uguali al diario (`06a12253…`), 22 chunk da 1 MiB identici ai valori registrati, due letture identiche; VBR LBA55 e slice JPEG **assenti** da NANDP1/Reserved/MainCode/BootCode|

La ricerca nei dump noti usa l'indice dei record allineati per NANDP1 (unico export con stride 2112 integrale, 20.736 record indicizzati) e la ricerca substring negli altri tre export su un campione di pagine: un riscontro prova identità di byte, non la posizione fisica in NAND.

## Limiti

- Verifica artefatti, non acquisizione: trasporto USB, device e firmware restano non provati qui.
- Il fixture NANDP1 è costruito offline, non è una lettura dalla fotocamera; le sue coordinate sono etichette del fixture.
- Il confronto substring è campionato (16 pagine per cartella); l'indice allineato è invece esaustivo.
- Nessun nuovo dump, nessuna scrittura su input, GNU e hardware intatti; BIN `0bb25fd6…cb324e9` invariato NON_INSTALLARE.

## Continuazione

Lato PC lo strumento è pronto per validare qualunque futura acquisizione hardware, compreso il confronto con i dump noti. Il passo decisivo del ramo resta il **nuovo export MainCode** (Dump2File da HiddenMenu, operazione utente sulla fotocamera) per stabilire quale immagine è avviata: senza di esso l'accesso al resto NAND via handler RAW del candidato resta non dimostrato. Alternativa offline utile: proseguire le verifiche di residenza/mount/handoff del candidato già indicate nei checkpoint RAM/API. Circa 10% invariato, goal "accesso al resto NAND dal PC" aperto.
