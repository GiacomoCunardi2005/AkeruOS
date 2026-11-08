# NAND dal PC: candidato v2 a 16 record costruito e verificato

21 ottobre 2026 — R0/R3/R4. **Candidato v2**: servizio RAW (handler + guard CBW + buffer privato 2112 byte) inserito **sul posto** nella regione zero di payload9 `[0xE99D14,0xE9B928)`, **16 record, dimensione originale 29.602.084** — la struttura che l'updater della fotocamera ha dimostrato di accettare. BIN `S33_NAND_PC_RAW_V2_NON_INSTALLARE.bin`, SHA-256 `39bdefdf9a00948463f528fc11aec36da17b5599f16340be45eacec8c369b6e4`, [evidenza](../Risultati/USB_SCSI/Accesso_NAND_PC/container_v2_20261021T200046Z/verified_evidence.json).

## Cosa contiene

- payload9: handler a `0xE99F40` (code da `0xE99E00`), guard parser a `0xE9AE00`, buffer privato `0xE9A2A4`, dentro la regione con zero riferimenti statici (analisi pcl/limm/straddle);
- payload0: byte MSDC-default `C5EEA` (come il candidato precedente);
- payload4: hook 8 byte a `0x820C88` verso il guard (come prima);
- payload5: slot `0x9A3460` → `0xE99F40`;
- **12 payload su 16 invariati**; nessun offset spostato; nessun record aggiunto.

## Verifiche eseguite

|Prova|Esito|
|---|---|
|Suite BOT al nuovo indirizzo (30 casi CPU + 256 lunghezze parser)|PASS ([evidenza](../Risultati/USB_SCSI/Accesso_NAND_PC/bot_v2_extension_20261021T195520Z/verified_evidence.json))|
|Container: 16 record, dimensione originale, checksum/KHIR/XOR, roundtrip parser|PASS|
|Rollback: ripristino regione+patch ricompone l'originale byte per byte|PASS esatto|
|Integrazione dispatch dal candidato reale (31 casi, slot e handler dai byte del BIN v2)|PASS ([evidenza](../Risultati/USB_SCSI/Accesso_NAND_PC/bot_candidate_dispatch_20261021T200058Z/verified_evidence.json))|
|Copia su SD (radice + firmware/)|hash verificato `39bdefdf…`|

## Limiti onesti (NO-GO pre-install rimane)

- **Canarie runtime della regione payload9 non ancora eseguite**: la residenza si fonda sull'analisi statica (zero riferimenti) e sulla natura di buco in un payload Resource; i percorsi che potrebbero scrivere lì a runtime (calcolati/DMA) non sono stati testati come fatto per l'estensione.
- Loader/updater/dispatch NON rieseguiti col contenitore v2 (le suite esistenti puntano al 18 record; la ripetizione col v2 è lavoro residuo).
- Recupero fisico non dimostrato (R4). L'installazione sulla macchina resta decisione dell'utente con i rischi documentati.

## Prossimo protocollo

1. (Opzionale ma consigliato) rieseguire loader/updater/dispatch col v2 + canarie payload9.
2. Installare v2 (BIN già sulla SD), riavvio, collegare USB.
3. Se USB = MSDC 22 MiB → sonda RAW dal PC: 2112 byte = handler attivo → dump a blocchi del resto NAND = **goal**.

## Rigenerazione richiesta — 23 ottobre 2026

[Nuova consegna](S33_NAND_PC_BIN_Rigenerato_20261023.md): stesso hash e contenuto della build v2 storica, verifica contenitore e rollback rieseguita. Nessuna nuova validazione hardware o autorizzazione tecnica al flash; NON_INSTALLARE resta lo stato del file.
