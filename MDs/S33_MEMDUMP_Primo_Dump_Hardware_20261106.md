# Primo dump RAM su hardware: MEMDUMP v5 sulla Nikon S33

6 novembre 2026. L'utente ha installato il [firmware v5](S33_MEMDUMP_Versione5_Handle_Esclusivo_20261106.md) (SHA-256 `a0e4a4ee…6948`, copiato in `firmware/firmware.bin` sulla SD) sulla propria fotocamera e ha riacceso. **Sulla SD è comparso `MEMDUMP.BIN` di 17.041.228 byte**, esattamente la lunghezza prevista `[0, 0x0104074C)`. Prima prova su hardware: il firmware parte, il task gira e il diagnostico Nikon scrive il file.

Copia di lavoro: `Risultati/Dump_fotocamera/MEMDUMP_20261106/MEMDUMP.BIN`, SHA-256 `c91888b23a8def81dc0afbf5a62a6210361308fea030bfbafcf6a43338286107`. Accanto sono state copiate le due fotografie `DSCN1035.JPG` e `DSCN1036.JPG`. La SD non è stata modificata dopo il dump.

## Cosa mostra il dump

- **È RAM vera:** il blocco 0 del firmware (MainCode, caricato a `0xAD800`) coincide con la RAM per **2.810.811 byte su 2.810.880** (99,998%). Conferma sull'hardware il load address `0xAD800` già dedotto.
- **Pattern del test memoria del boot:** a offset `0xC00000` ci sono le due word `0xAAAA5555 0x5555AAAA` scritte dal test sparso BootNAND (`0x0F801018`), e a `0x0` la coppia `0x5555AAAA 0xAAAA5555` con la prima word alterata (`a3aa5555`). Gli altri punti a passi di 1 MiB sono stati riscritti dopo il boot. Coerente con il test descritto in [BootNAND](S33_BootNAND_DDR_ID_Dimensione_e_Checksum.md).
- **Riempimento stack:** la stringa `katskats` ripetuta (pattern `stak` little-endian) compare in molte zone: aree di stack riempite dal kernel.
- **Zone vuote:** 4–6 MiB per lo più a zero (66–85%); il file nell'insieme ha il 22,8% di zeri.

## Cosa NON dimostra

- Il dump non è una fotografia atomica: la RAM cambiava mentre veniva scritta.
- Copre solo il 6,4% dei 256 MiB configurati; il resto della RAM non è nel file.
- Non so quanto è durata la scrittura né se il task è partito alla prima accensione dopo l'aggiornamento o a una successiva.
- Il fatto che il dump sia stato scritto non prova da solo le altre ipotesi del modello (priorità, stack `0x8000`, identità del task corrente, aree Resource): le rende plausibili, non misurate.
- La fotocamera ha letto la SD exFAT da 119 GB senza problemi nel percorso osservato.

**Prossimo:** analizzare il dump (task, stack, strutture del kernel, tabelle) e decidere se estendere l'intervallo con la v6. Nessun'altra operazione su hardware senza ambito esplicito.

Analisi del dump: [struttura, task e residenza dei payload](S33_MEMDUMP_Analisi_Dump_Hardware_20261106.md).
