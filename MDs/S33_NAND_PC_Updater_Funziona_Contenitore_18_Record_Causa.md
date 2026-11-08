# NAND dal PC: l'updater funziona — il contenitore a 18 record è la causa dei fallimenti

21 ottobre 2026 — R0/R3/R4. **Esperimento di controllo deciso**: dopo il verdetto del [export](S33_NAND_PC_Export_Ottobre21_Flash_Mai_Aggiornata.md), il BIN MSDC-default `af65ab0e…` (5 byte diversi, struttura e dimensione **identiche all'originale**: 16 record, 29.602.084 byte) è stato installato dalla radice della SD ed **è entrato in esecuzione**: la fotocamera ora si enumera come **NIKON DSC COOLPIX S33-MSDC, interfaccia 08/06/50**, con disco `4MP-CARD` da 22 MiB (sdc1 vfat). HiddenMenu non si apre, come previsto: quel BIN non ha la patch del file.

## Cosa questo prova

|Fatto|Conclusione|
|---|---|
|BIN a struttura originale installato e attivo|**l'updater funziona**: posizione radice ✓, procedura utente ✓, commit ✓|
|BIN a 18 record/29.606.692 byte (`0bb25fd6`) mai comparso nella flash|il rifiuto riguarda la **struttura del contenitore** (record17 aggiunto e/o dimensione), non il contenuto|
|Ricostruzione da zero del candidato RAW (builder PASS)|il BIN consegnato era corretto e riproducibile: non un problema di file|

Storia coerente: l'unico aggiornamento persistito prima d'ora (candidato SD `ce504526`, 16 record, dimensione originale, installato il 20 ottobre mattina) aveva anche lui struttura originale. Tutti i tentativi con contenitori modificati (18 record) sono falliti silenziosamente.

## Piano: candidato RAW v2 a 16 record

Il servizio RAW (handler + guard + buffer privato 2112 byte = 4.608 byte totali) va collocato **dentro uno spazio inutilizzato di un payload esistente**, con byte sostituiti sul posto: nessun record aggiunto, nessun offset spostato, dimensione originale. Analisi di residenza eseguita sulle sequenze di zeri dei payload (classificazione pcl/limm/straddle):

|Regione|Dimensione|Riferimenti statici reali|Valutazione|
|---|---|---|---|
|**payload9 `[0xe99d14, 0xe9b928)`**|**7.188 byte**|**0**|**scelta**: payload Resource, caricato dal gruppo Resource/C4 prima dell'operatività USB; le 4 word grezze erano straddle di encoding|
|payload6 `[0xa1b94e, +32806)`|32.806|1 (0xa20000, paginata)|riserva|
|payload1 `[0x3bd28c, +5028)`|5.028|5 (bordo iniziale usato: 0x3bd290, 0x3bd2cc)|rischio medio|
|payload1 `[0x393447, +24137)`|24.137|~49 ai bordi|rischio alto|

Passi del build v2 (tutti offline, riusando la catena esistente):
1. Ricompilare handler C + guard CBW per il nuovo indirizzo (dentro la regione scelta, allineato);
2. hook `0x820C88` in payload4 e byte `C5EEA` in payload0: invariati (già in stile «patch sul posto»);
3. slot `9A3460` → nuovo indirizzo dell'handler;
4. buffer privato nella stessa regione (il buffer viene riscritto per intero a ogni transazione: l'inizializzazione non è necessaria);
5. contenitore ricostruito con somme/checksum/XOR e **16 record/dimensione originale**, poi l'intera suite di verifiche esistente (BOT, parser, loader, updater, dispatch) rieseguita;
6. residuo da chiarire come per l'estensione: scrittori runtime della regione scelta (canarie e sweep della stessa qualità).

## Stato della macchina e limiti

- In esecuzione: `af65ab0e` (MSDC-default). USB da spenta = MSDC 22 MiB: comodo per ogni futura sonda RAW. La patch `modifica.modifica` non è attiva (menu non apre): per riavere il menu basta reinstallare il candidato SD (struttura originale, già provato due volte).
- L'updater accetta struttura originale ma i suoi controlli interni non sono mappati: il rifiuto dell'18° record resta una diagnosi per esclusione, non un meccanismo dimostrato.
- Candidato `0bb25fd6` superato come formato; resta NON_INSTALLARE; nessun recupero fisico dimostrato (R4). Circa 10% invariato; goal «accesso al resto NAND dal PC» aperto e ora con percorso chiaro.

## Parametri esatti del build v2 (ricognizione completata, 21 ottobre sera)

- Produttore del servizio: `s33_verify_usb_bot_readonly.py --main-extension --original-raw-body --bounded-parser --linked-handler` — **`CODE=0x35bc00` è cablato alla riga ~73**: da parametrizzare per il nuovo indirizzo. Layout dipendente: guard = `CODE+0x1000`, handler = `CODE+0x140`, buffer = `CODE+0x4A4`, estensione totale `0x1200` (4.608 byte).
- Vincolo della regione payload9 `[0xE99D14, 0xE9B928)` (7.188 byte): `CODE` deve stare in `[0xE99D14+marzone, 0xE9A728]` perché `CODE+0x1200` non superi la fine della sequenza di zeri; proposta `CODE=0xE99E00` → guard `0xE9AE00`, handler `0xE99F40`, buffer `0xE9A2A4`, fine `0xE9B000`, margini 0xEC/0x928.
- Assembler di handler/guard: `S33-sections/usb_nand_readonly/` (akrn_read.c, nikon_raw_read.c, akrn_scsi.c, runtime.c, cbw_length_guard.s) con `arc-elf32-*` e `handler.ld` generato (parametri già nella pipeline).
- Container: estendere `s33_build_nand_pc_offline.py` con la modalità v2: **patch in place di payload9** ai byte della regione (offset file = `BS[9].offset + (CODE - BS[9].base)`), niente record17, 16 record, dimensione originale 29.602.084; ricalcolo checksum payload9, somme KHIR, somma/complemento header, XOR; hook `0x820C88` e byte `C5EEA` come nel candidato attuale; slot `0x9A3460` → `handler` nuovo.
- Verifiche da rieseguire: BOT originale con il nuovo CODE, parser 256 lunghezze, loader/updater/dispatch con il contenitore v2, e canarie della regione payload9 (stesso schema dell'estensione).
