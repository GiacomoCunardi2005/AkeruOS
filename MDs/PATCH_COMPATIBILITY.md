# Integrità patch e compatibilità

**Aggiornamento comparativo successivo, 19 ottobre 2026.** Il [rapporto corrente](S33_Confronto_Completo_CMP1_CMP3.md) confronta integralmente entrambi i listati: quattro byte diversi, una sola istruzione; controlli di integrità validi. Le [50 prove di boot](COMPARE_BOOT.md) hanno le stesse tracce nei confini registrati, con 8 arresti comuni del modello; i [40 casi di comportamento](COMPARE_BEHAVIOR.md) delimitano la differenza del selettore e il requisito del registro volumi. Non dimostrano avvio completo o recupero; NO-GO invariato. Usare i nuovi manifest per i sorgenti e log rigenerati: quelli precedenti conservano la provenienza storica.

19 ottobre 2026, R4. **Integrità matematica confermata; accettazione updater e avvio modificato non dimostrati.** Campione analizzato V1.1, macchina V1.0 secondo i log storici. Nessun trasferimento di indirizzi V1.1 alla macchina V1.0.

## Verifiche eseguite in questa sessione

`python3 S33-sections/safety_audit_codex/run_audit.py` riusa il verificatore esistente, senza modificare i due input. [Risultato completo](evidence/patch_audit.json), [log](../S33-sections/safety_audit_codex/evidence/run_audit.log), [manifest](verified_evidence.json).

| Input | Byte | SHA-256 |
|---|---:|---|
|OriginalSoftware_NikonS33_V1.1/firmware.bin|29602084|1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39|
|S33-sections/firmware_HIDDENMENU_RHIR_KHIR_OFFLINE_NOT_FLASH.bin|29602084|932281f89b840a45dc1b050dac52d5250f040ea6576b94696b55f3b93e123f1c|

Confronto byte per byte dell'intera lunghezza: esattamente quattro differenze.

| Offset file | Originale→patch | Ruolo |
|---|---|---|
|0x480D6|37→35|Somma payload00 nel record RHIR|
|0x482AE|DD→DB|Somma header RHIR nel KHIR|
|0x482B2|22→24|Complemento della somma KHIR|
|0xCFEAE|83→81|`cmp_s r0,3→cmp_s r0,1` a VA 0x1353F6|

TBM/RHIR inizia a `0x480B8`, record a `0x480C8`, payload00 a `0x482B8`, KHIR a `0x482A8`. Il word a `0x480C0` è `0x04611342`. Non confondere questi offset con indirizzi CPU. I 16 payload originali corrispondono integralmente ai file e hash del [manifest TBM](../S33-sections/TBM_blocks/manifest.json); record16/tipo2 non è un diciassettesimo payload.

Le 16 somme RHIR sono valide su entrambi gli input: somma parole LE32 modulo 2^32, non CRC32. Solo quella di payload00 cambia `0x9237C054→0x9235C054`. KHIR copre `[TBM,TBM+0x1F0)`: `0x21DDCB41/0xDE2234BE→0x21DBCB41/0xDE2434BE` (somma/complemento). TBIB invariato, corpo lunghezza `0x44BBC`, checksum `0xF3F78173` valido. Nessun hash/firma crittografica di autenticazione dell'intero pacchetto è stato validato; SHA-256 qui identifica i campioni.

La decodifica GNU e i 14 step Ghidra della sola istruzione sono nuovi e riusciti: [risultati](EMULATION_RESULTS.md). La patch sposta il confronto di uguaglianza da stato3 a stato1; non rende l'apertura incondizionata e rimuove l'uguaglianza per stato3 nel primo ramo. Restano sonde file/attributi, manager UI e hook.

## Updater: prove statiche precedenti consultate

Questa sezione riusa finestre esistenti, non dichiara di aver eseguito l'updater:

- [Validatore 0x12AEA0](../S33-sections/analysis_codex/evidence/0012aea0_rhir_validator.txt): capienza selettore6, magic RHIR e identità header+8 confrontata con getter `0xC7694`, pool `0xC7698=0x04611342`. Chiamata `0x1ED914` a `0x12AF16`, confronto checksum record a `0x12AF1A..1E` nel ramo tipo1.
- [Somma 0x1ED914](../S33-sections/analysis_codex/evidence/001ed914_sum_words.txt): parole32 con arrotondamento `(len+3)>>2` e allineamento pointer in basso a4. Lunghezze dei payload multipli di4.
- [Loader/parser 0x12A794](../S33-sections/analysis_codex/evidence/0012a794_update_load_validate.txt): callback conservata in r19; main `0x12A9FC`, boot `0x12AA3C`. Non è prova che il percorso normale di aggiornamento SD coincida con l'ingresso del NAND Tool.
- [Checksum 0x12B060](../S33-sections/analysis_codex/evidence/0012b060_package_checksum.txt): XOR parole32; il seguito [updater SD](SD_UPDATE_RECOVERY_PATH.md) ha ora risolto gli argomenti nel ramo V2.0: file+4 e lunghezza−4. Entrambi i campioni soddisfano il confronto col primo word `0xBD4A9BF9`.
- [Callback](../S33-sections/analysis_codex/evidence/0012a9fc_update_callbacks.txt) e [backend](../S33-sections/analysis_codex/evidence/0012ad58_update_write_backends.txt): main→`0x12AD58→0x1EEA4C` con selettore6; boot→`0x12AE00→0x1EEA4C` con selettore0, dopo ricerca INFO/sentinella `0x55AAAA55`. Sono percorsi di possibile scrittura persistente, non validatori completi di compatibilità.

## Versioni, boot e interruzione

L'aggiornabilità ufficiale dell'originale e il recupero sono trattati in [RECOVERY_OPTIONS.md](RECOVERY_OPTIONS.md), con fonti Nikon. Anche un eventuale supporto ufficiale V1.0→V1.1 non autorizza inferenze sull'accettazione del binario modificato. Non sono ricostruiti integralmente controllo versione/modello, firma/trailer, mappa fisica delle scritture, comportamento del boot ROM e gestione dell'alimentazione durante aggiornamento.

I quattro byte diversi nel pacchetto **non significano quattro byte scritti in flash**. L'updater può riscrivere unità più grandi: l'estensione effettiva e le regioni preservate richiedono prova. TBIB uguale nel file non dimostra che venga saltato dall'updater o che il bootloader residente resti recuperabile.

Un'interruzione dopo modifica di codice o metadati di avvio potrebbe lasciare un'immagine incoerente: rischio plausibile, senza transazione atomica, doppio slot o rollback dimostrati nel perimetro studiato. Non è dimostrato che ogni interruzione provochi brick, né che un nuovo inserimento SD lo risolva. Per questo compatibilità, calibrazioni preservate e recupero restano requisiti aperti, anche con checksum validi.

## Seguito corrente: UI pubblica e BootCode

La [ricostruzione successiva](SD_UPDATE_RECOVERY_PATH.md) identifica il dispatcher pubblico `0xBC3F8`, la registrazione per basename e il raccordo ai writer già noti. Il contenitore include TBIB/TBM/P1RES: non si può assumere che il BootCode invariato non venga riscritto. Ricostruite selezione0/6, formule delle basi/capienze e dipendenze dai dati runtime; non gli intervalli fisici o le copie superstiti. Il candidato fallback nel TBIB non prova recovery preservato. Le nuove verifiche sono riproducibili nel runner complessivo e nel suo manifest.
