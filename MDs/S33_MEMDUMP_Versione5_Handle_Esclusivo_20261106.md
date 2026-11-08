# MEMDUMP versione 5: handle esclusivo integrato nel firmware.bin

6 novembre 2026. Il [firmware.bin versione 5](../Risultati/Firmware_sperimentali/MEMDUMP/OFFLINE_NON_INSTALLARE_20261106T164839522756Z/firmware.bin), SHA-256 `a0e4a4eeb6a4744cc462c8678e8903b9f372787350d2ea3bd992919942446948`, 29.602.084 byte, è **NON INSTALLARE**. Integra l'adapter dell'handle esclusivo che la versione 4 non conteneva ([storia](S33_MEMDUMP_Firmware_Offline_20261106.md), [diagnostico](S33_MEMDUMP_Verifica_20261106.md)). Originale V1.1 immutato. Nessuna fotocamera, NAND o SD usata.

## Cosa cambia rispetto alla v4

- Il task apre `B:\MEMDUMP.BIN` con `0x12DBFC` e **tiene l'handle aperto**: niente chiusura e riapertura, quindi la finestra di collisione della v4 non c'è più (nel modello).
- Registra handle e task corrente (`akeru_memdump_held_attach`, task da `[0x369348]+0x1C`) e chiama il diagnostico originale `0x16ED40`.
- Le due chiamate a `0x12BD5C` dentro `0x16ED40`, a `0x16ED84` e `0x16ED98`, sono due `bl` riscritti verso `akeru_memdump_held_site` nel Resource. Per il task proprietario scrive sull'handle con `0x12DE3C` (controlla nome, selettore, ordine e conteggio completo). Per ogni altro task inoltra al `0x12BD5C` originale.
- A fine diagnostico: detach e close dell'handle. Versione firma 5 (la guardia rifiuta i Resource v3/v4).

Sorgenti: `AkeruOS/nikon_v11_memdump_worker_held.c`, `nikon_v11_memdump_held_site.c`, `nikon_v11_memdump_boot_guard_v5.c`, più `held.c`, `held_scope.c`, `task_current.c` già esistenti. Builder: `Python_Trace_Scripts/s33_build_memdump_held_offline.py`.

Delta: 1052 byte in 5 regioni (hook `0xC58EE`, due call site, guardia `0x35BB20`, Resource `0xE99E00` da 1068 byte), più checksum. Il builder controlla che i due call site originali siano proprio `bl 0x12BD5C`, i checksum dei 16 blocchi, il perimetro del delta e la ricostruzione inversa dell'originale.

## Prova (P-code Ghidra, FAT sintetica)

`python3 Python_Trace_Scripts/s33_verify_memdump_held_v5.py --hook` ([evidenza](../Risultati/Runtime_Kernel/MEMDUMP_Held_V5_Hook_Large_FAT/20261106T165131357231Z/evidence.json)): il banco carica il blocco 0 e il Resource **del candidato v5**, entra due volte nel call site `0xC58EE`, esegue guardia, payload e task. Risultato: file `MEMDUMP.BIN` di 17.041.228 byte, 1041 cluster, scritture 256 e 17.040.972 byte con `file_error=0`, nessuna chiamata al vecchio wrapper, una sola chiusura, `fsck.fat -n` riuscito, primi 710.656 byte attesi e 11.124.736 byte coincidenti con la memoria emulata al momento della DMA. Probe: `ProbeMemdumpHeldV5LargeFat.java`; `ProbeMemdumpLargeFat.java` ha ora `expectedWrites()` (default 2, v4 invariato).

## Limiti

- Hook, scheduler, FAT, geometria, DMA, RAM e identità del task sono fixture o modellati. Il rivale concorrente non è stato ripetuto sul firmware v5: era provato solo sull'adapter separato.
- Il dump copre solo `[0, 0x0104074C)`, circa 16,25 MiB (6,4% dei 256 MiB configurati). Mappa fisica non nota.
- Non provati: boot, tick e scheduler reali, SD fisica, proprietà e scrivibilità di Resource e guardia, stack da `0x8000`, `[0x369348]+0x1C` come task corrente, close in caso di errore, il file non è atomico.
- Se il diagnostico fallisce, resta un `MEMDUMP.BIN` parziale o vuoto.

**NON INSTALLARE**; nessuna operazione su hardware.

Risultato su hardware, 6 novembre 2026: [primo dump RAM sulla fotocamera](S33_MEMDUMP_Primo_Dump_Hardware_20261106.md).

Versione 6 con intervallo scelto: [dettaglio](S33_MEMDUMP_v6_Intervallo_Scelto_Offline_20261106.md).
