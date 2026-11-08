# Stima RAM 256 MiB e profilo emulatore `256-zero`

6 novembre 2026. **Stima: 256 MiB (268.435.456 byte) come limite configurato nel firmware.** Non è una misura della RAM fisica. Fiducia alta (circa 85–90%) sul valore configurato, nessuna prova hardware.

## Prove

- `DUMPS/BFNSetting.txt`: `DDR_SIZE_ID_Variable_09 = 0x00000120`, presente nei quattro record BFN identici ([dettaglio](S33_BFN_NAND_DDR_e_Configurazione_Persistente.md)).
- BootNAND, routine `0x0F80109C`: `ld r13,[r0,196]` (`0x0F8010A4`), `extb_s` (`0x0F8010EA`), `asl_s r13,r13,0x17` (`0x0F8010F2`). Calcolo `(0x120 & 0xFF) << 23 = 0x10000000` = 256 MiB, passato al test memoria `0x0F801018` ([dettaglio](S33_BootNAND_DDR_ID_Dimensione_e_Checksum.md)). Disassemblato GNU già archiviato in `Risultati/Dump_fotocamera/BootNAND_ID/20261020T153622Z/gnu_verified.txt`.
- Firmware applicativo: il getter `0xC768C` restituisce `1<<28 = 0x10000000`; il record 0 della tabella `0x3766F4` riserva gli ultimi 9 MiB da `0x0F700000` ([dettaglio](S33_Dumper_RAM_Mappa_e_Riserva_Alta.md)).
- Indirizzi usati dal software: finestre fino a `0x0F7B0000`. Con RAM lineare da zero servono almeno 247,6 MiB, quindi 128 MiB non basterebbe ([dettaglio](S33_Limiti_Indirizzi_e_Stima_RAM.md)).
- Il bit 8 dell'ID (`(ID>>8)&1 = 1`) alimenta un ramo del controller (registro `0x0FE20110`), non la capacità.

## Test del 6 novembre 2026

`python3 Python_Trace_Scripts/s33_verify_bootnand_ddr_id.py` → **PASS** (CPU emulata): 12 casi aritmetici con le istruzioni originali e 2 esecuzioni del checksum originale; limite configurato 256 MiB. Nessun hardware.

Nota: `DUMPS/CameraParam_2.dmp` non è più in `DUMPS/` (spostato), quindi il verificatore originale si ferma con `FileNotFoundError` sul controllo hash. È stata eseguita una copia temporanea dello script che salta solo il controllo hash dei file mancanti; gli altri hash e `BootNANDBase.dmp` restano verificati. Evidenza: `Risultati/Dump_fotocamera/BootNAND_ID/20261106T163902Z`. La cartella parziale del primo tentativo fallito è stata rimossa.

## Profilo emulatore `--ram 256-zero`

In `Python_Trace_Scripts/s33_run_gnu_arc700.py`: riempie di zeri `[0, 0x0FE00000)` (circa 254 MiB). La fascia MMIO nota da `0x0FE00000` resta esclusa per non nascondere accessi hardware. `128-zero` e `default` non cambiano.

Prova: `s33_run_gnu_arc700.py tbib --ram 256-zero` → PASS, 10.952 istruzioni, fault MMIO atteso a 2 byte, identico a `128-zero`. Evidenza: `outputs/gnu_arc700/20261106T164002Z_2188535a` (confronto `128-zero`: `20261106T164001Z_2a8c9805`).

## Limiti

- Chip DDR non identificato; nessuna prova indipendente della capacità.
- Mappa CPU→DDR, banche, alias e buchi non ricostruiti.
- Al massimo circa 247 MiB utilizzabili: da `0x0F700000` in su ci sono riserva, MMIO e regioni di natura ignota.
- Registri `0x0FE20018/20/80/84/F4/F8/100/104/134` non decodificati.
- Il test del boot salta `0x08000000` e si ferma a `0x0F700000`: ragione ignota, non riprodotta nel profilo.
- Il profilo `256-zero` è di laboratorio; riempie anche la riserva alta `0x0F700000–0x0FE00000` come RAM. Gli script con `128-zero` o `0x08000000` fisso non cambiano profilo da soli.
- Per la certezza servono la sigla del chip DDR o un dump reale, solo con consenso esplicito dell'utente.

NON_INSTALLARE invariato; nessun accesso alla Nikon.
