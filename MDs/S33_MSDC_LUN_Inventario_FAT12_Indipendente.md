# MSDC: inventario FAT12 indipendente del LUN della memoria interna

21 ottobre 2026 — R0/R3/R4, continuazione del [dump doppio del LUN](S33_MSDC_LUN_Memoria_Interna_Dump_Doppio.md). **Inventario FAT12 ricavato direttamente dai byte di `read1.img`, senza mount né cache del sistema operativo**: geometria verificata, tutte le catene cluster ricostruite, hash per file ricomputati e confrontati con le letture via mount già pubblicate, contabilità completa dei 1.405 cluster. Il LUN resta la **regione NAND via USB non coperta da alcun dump noto**; l'inventario ne quantifica l'uso logico.

## File e riproduzione

- [Verificatore](../Python_Trace_Scripts/s33_verify_lun_fat12_inventory.py), [evidenza](../Risultati/Hardware/MSDC_Default/LUN_FAT12_20261021T162912Z/verified_evidence.json), [indice latest](../Risultati/Hardware/MSDC_Default/LUN_FAT12_latest.json).
- Riusa la riverifica indipendente del dump doppio ([22 chunk](S33_NAND_PC_Verifica_Indipendente_Journal_e_Confronto_Dump.md)) prima del parse.

```bash
python3 Python_Trace_Scripts/s33_verify_lun_fat12_inventory.py
```

## Geometria verificata dai byte

MBR con unica partizione FAT12 a LBA55 (45.001 settori, tipo 0x01); VBR con 512 byte/settore, 32 settori/cluster (16 KiB), 1 riservato, 2 FAT da 12 settori **identiche tra loro**, 256 voci root, media 0xF8, settori nascosti 55 coincidenti con l'inizio partizione; dati da LBA96, 1.405 cluster totali.

## Inventario

|File|Byte|Cluster|Frammentato|LBA primo..ultimo cluster|
|---|---|---|---|---|
|DCIM/101NIKON/DSCN0144.JPG|5.501.197|336|sì|1440..12191|
|DCIM/101NIKON/DSCN0148.JPG|6.052.103|370|sì|40032..17791|
|DCIM/102NIKON/DSCN0865.JPG|5.776.073|353|sì|17824..29119|
|NCFL/NCMRKLST.LST|825|1|no|29152..29183|

Directory: `DCIM` (cl.2), `DCIM/100NIKON` (cl.3, vuota), `DCIM/101NIKON` (cl.43), `DCIM/102NIKON` (cl.555), `MISC` (cl.4, vuota), `NCFL` (cl.909). Per i file frammentati la coppia LBA è il primo e l'ultimo cluster della catena: l'intervallo comprende i buchi, non è un extent contiguo.

Controlli superati: le dimensioni e i prefissi SHA-256 ricomputati coincidono con le letture via mount del checkpoint LUN (`c1bdeff7…`, `bc510026…`, `875f73b7…`, `fd377c13…`); nessun cluster condiviso fra catene; **1.066 cluster usati + 339 liberi = 1.405 totali**: contabilità chiusa. In `100NIKON` resta una voce cancellata (byte 0xE5, `?SCN0083.MOV`, cluster 5): i cluster della vecchia catena sono stati riusati dalle catene attuali, coerente con la frammentazione osservata.

## Correzioni di percorso

Due difetti del verificatore sono stati corretti durante lo sviluppo (riscontrabili nelle cartelle con `failure.json`): il decodificatore FAT12 per cluster dispari aveva gli shift invertiti, e `read_dir` usava il primo byte del nome come numero di cluster. L'inventario pubblicato proviene dall'esecuzione corretta finale.

## Limiti

- Parse statico di un dump: il LUN è come lo ha scritto il firmware della fotocamera; nessuna prova che il firmware usi sempre questa geometria.
- Gli LBA sono logici nel LUN da 22 MiB: la posizione fisica in NAND resta sconosciuta, come già stabilito.
- Le voci cancellate non sono inventariate sistematicamente; nessun tentativo di recupero file.
- Nessuna scrittura, nessun nuovo dump, nessuna azione hardware; candidato NON_INSTALLARE invariato, circa 10% invariato.

## Continuazione

L'inventario è pronto per confronti automatici con future letture del LUN (drift della memoria interna). Il passo decisivo del ramo NAND/PC resta il **nuovo export MainCode** (operazione utente) per stabilire quale immagine è avviata; in parallelo restano i servizi di scrittura del vicinato dell'estensione indicati nel [rapporto memcpy](S33_NAND_PC_Memcpy_Guardia_Template_e_Canarie.md).
