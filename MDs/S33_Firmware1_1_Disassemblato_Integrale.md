# Firmware V1.1 — listato integrale

19 ottobre 2026. Creati [Firmware1.1.asm, CMP3](../Risultati/Disassemblati/Firmware1.1.asm) e [Firmware1.1_CMP1.asm](../Risultati/Disassemblati/Firmware1.1_CMP1.asm) nella cartella `Risultati/Disassemblati/`. Sono listati di analisi completi dei byte dei rispettivi contenitori Nikon V1.1: istruzioni candidate GNU e direttive dati esplicite. Non sono il sorgente originale ricostruito né file riassemblabili/installabili. Il [confronto integrale e funzionale circoscritto](S33_Confronto_Completo_CMP1_CMP3.md) raccoglie le prove successive.

Input: `OriginalSoftware_NikonS33_V1.1/firmware.bin`, **29.602.084 byte**, SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`. Il confronto a CPU `0x1353F6`, offset file `0xCFEAE`, è `83 E0`, `cmp_s r0,3` (CMP3). Nessun altro firmware è stato generato o modificato.

Output: **399,542,290 byte** (circa400 MB), **6,125,576 righe di byte** e 6,125,675 righe totali. SHA-256 del listato: `d3d2aa07d248fbc49197bc8933d6468f41cd35fd498af950a2efafbf9e641d1f`. Un editor può impiegare tempo ad aprirlo; per cercare un indirizzo usare `rg`.

Secondo input CMP1: `S33-sections/firmware_HIDDENMENU_RHIR_KHIR_OFFLINE_NOT_FLASH.bin`, stessa dimensione, SHA-256 `932281f89b840a45dc1b050dac52d5250f040ea6576b94696b55f3b93e123f1c`, istruzione `81 E0`. Il suo listato occupa 399.542.316 byte, con le stesse quantità e posizioni di righe; SHA-256 `d011e145af932d1e718409e336be1e237bce588b073f89f6b8ac8ce35c48082c`. I firmware di input sono invariati.

## Riproduzione e verifiche

```bash
python3 Python_Trace_Scripts/s33_disassemble_firmware11.py
python3 Python_Trace_Scripts/s33_disassemble_firmware11.py --variant CMP1
python3 Python_Trace_Scripts/s33_compare_firmware11.py
rg -n "^F000CFEAE " Risultati/Disassemblati/Firmware1.1.asm
```

[Script](../Python_Trace_Scripts/s33_disassemble_firmware11.py), [evidenze JSON](../Ghidra_Results/ghidra_reports/firmware11_full/verified_evidence.json), [log esecuzione](../Ghidra_Results/ghidra_reports/firmware11_full/generation.log). Usati helper e parser già presenti. GNU `objdump -d -z -m arc:ARC700 -EL --show-raw-insn --insn-width=16`, versione `GNU objdump (GNU Binutils) 2.45`.

Il generatore accetta `--variant CMP3|CMP1`; senza argomento mantiene CMP3. [Evidenze CMP1](../Ghidra_Results/ghidra_reports/firmware11_cmp1_full/verified_evidence.json), [log CMP1](../Ghidra_Results/ghidra_reports/firmware11_cmp1_full/generation.log). Entrambe le generazioni hanno completato gli stessi controlli. Il [comparatore](../Python_Trace_Scripts/s33_compare_firmware11.py) ha riletto 6.125.576 righe per variante: 3 righe primarie diverse, una sola istruzione; [diff](../Risultati/Disassemblati/Firmware1.1_CMP3_vs_CMP1.diff), [manifest](../Ghidra_Results/ghidra_reports/firmware11_comparison/verified_evidence.json). La tabella delle regioni qui sotto vale per entrambi. I sorgenti e le evidenze della precedente generazione CMP3 sono conservati nei file `*_previous` della cartella `firmware11_full`.

Controlli effettivamente eseguiti: identità e dimensione input, checksum corpo TBIB, hash/dimensione e confronto integrale dei16payload con il contenitore, somme parole32 dei payload,17roundtrip BIN→ELF→BIN, confronto dei byte di ogni riga GNU con il file. La rilettura indipendente delle righe salvate ricostruisce esattamente29.602.084byte e lo SHA-256 originale; gli offset sono contigui, senza duplicazioni o buchi. Il confronto CMP3 è riancorato e controllato. Il firmware originale è invariato.

Il primo tentativo è stato interrotto volontariamente per spostare i temporanei dalla partizione `/tmp` a quella di destinazione, consentendo la pubblicazione finale atomica. Il [log del tentativo interrotto](../Ghidra_Results/ghidra_reports/firmware11_full/generation_attempt1.log) è distinto dal log riuscito. Nessun risultato parziale è stato presentato come listato finale.

## Come leggere il file

Ogni riga primaria ha questo formato:

```text
F<offset file> V<indirizzo CPU candidato> | <byte in ordine reale> | <disassemblato GNU o .byte>
```

`V--------` indica dati senza indirizzo CPU assegnato. Le sezioni sono ordinate per offset nel contenitore; i16payload TBM sono separati, inclusi quelli11–15 con base candidata comune. I byte zero non sono omessi. Header, gap, padding, P1RES, trailer e code non decodificabili restano dati espliciti: non è stata inventata una base CPU per disassemblarli.

## Indice delle regioni

| Regione | Intervallo file, fine esclusa | Base CPU candidata | Prima riga nel listato | Righe di byte |
|---|---|---|---:|---:|
| DATA_00000000 | `0x00000000–0x0000007C` | — | 13 | 8 |
| TBIB_BODY | `0x0000007C–0x00044C38` | `0x01000000` | 24 | 99,670 |
| DATA_00044C38 | `0x00044C38–0x000482B8` | — | 99699 | 872 |
| TBM_00 | `0x000482B8–0x002F66B8` | `0x000AD800` | 100574 | 988,135 |
| TBM_01 | `0x002F66B8–0x003BE4B8` | `0x00360800` | 1088715 | 226,064 |
| DATA_003BE4B8 | `0x003BE4B8–0x003BE6B8` | — | 1314783 | 32 |
| TBM_02 | `0x003BE6B8–0x004284B8` | `0x005FE800` | 1314818 | 152,119 |
| TBM_03 | `0x004284B8–0x005436B8` | `0x00669800` | 1466941 | 318,586 |
| TBM_04 | `0x005436B8–0x006438B8` | `0x00796800` | 1785531 | 358,161 |
| TBM_05 | `0x006438B8–0x0074F6B8` | `0x00897800` | 2143696 | 276,448 |
| TBM_06 | `0x0074F6B8–0x0090AAB8` | `0x009A3800` | 2420148 | 524,298 |
| TBM_07 | `0x0090AAB8–0x009114B8` | `0x00C67800` | 2944450 | 7,367 |
| TBM_08 | `0x009114B8–0x00911AB8` | `0x00C8E800` | 2951821 | 389 |
| TBM_09 | `0x00911AB8–0x00BA20B8` | `0x00C8F800` | 2952214 | 845,961 |
| TBM_10 | `0x00BA20B8–0x00CC20B8` | `0x00F20800` | 3798179 | 396,550 |
| TBM_11 | `0x00CC20B8–0x00D18CB8` | `0x01044800` | 4194733 | 125,628 |
| DATA_00D18CB8 | `0x00D18CB8–0x00D18EB8` | — | 4320365 | 32 |
| TBM_12 | `0x00D18EB8–0x00D4B0B8` | `0x01044800` | 4320400 | 69,958 |
| TBM_13 | `0x00D4B0B8–0x00E0FAB8` | `0x01044800` | 4390362 | 196,640 |
| TBM_14 | `0x00E0FAB8–0x00ECB8B8` | `0x01044800` | 4587006 | 187,196 |
| TBM_15 | `0x00ECB8B8–0x011148B8` | `0x01044800` | 4774206 | 620,703 |
| DATA_P1RES_AND_TRAILER | `0x011148B8–0x01C3B124` | — | 5394913 | 730,759 |

## Limiti

La copertura è completa per i byte del file, non per il grafo eseguibile del firmware. Il decoder lineare attraversa anche tabelle, stringhe, pool e dati; può saltare ingressi alternativi. Una riga con un mnemonic non prova che la CPU la esegua. Sono presenti ripartenze esplicite agli ingressi noti TBIB/BootTask, MainCode e slice del confronto HiddenMenu; non è un inventario completo delle funzioni.

I commenti GNU dei literal PC-relative scalati non sono automaticamente affidabili: per le forme pertinenti verificare `(PC & ~3) + offset*4`. Le finestre riancorate e le evidenze dei dossier restano il riferimento per sostenere un flusso. Le diagnostiche di coda del decoder sono registrate nel JSON e i byte corrispondenti vengono conservati come dati.

GNU è distinto dal decoder P-code Ghidra: il problema `ld.ab` documentato nell’audit non viene corretto né aggirato da questo file. La generazione e il confronto dei listati non eseguono il firmware. Le prove P-code separate sono descritte nel rapporto di confronto, con i loro confini. Nessun boot completo, flash o accesso hardware; V1.1 non è trasferito alla macchina V1.0. NO-GO flash e circa10% funzionale invariati.

Prossimo punto utile: usare gli offset e le sezioni del listato per seguire commit BootCode e selezione della copia al reset, mantenendo separati codice candidato, codice riancorato e valori hardware ignoti.
