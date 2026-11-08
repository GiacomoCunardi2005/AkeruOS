# Datasheet dei componenti della S33 e famiglie compatibili — raccolta pubblica

21 ottobre 2026 — R0. **Raccolta di documentazione pubblica** per i componenti collegati alla Nikon COOLPIX S33 e le famiglie compatibili, scaricata da internet con URL/hash/limiti, in `outputs/s33_component_datasheets/` con [manifest](../outputs/s33_component_datasheets/manifest.json).

## Scaricati (7 PDF, magic/hash/pagine verificati)

|File|Parte|Pagine|Fonte|SHA-256 (prefisso)|
|---|---|---|---|---|
|`K9F1G08U0C_U0D_Samsung.pdf`|Samsung 1Gb SLC NAND (rev. U0D della famiglia U0C)|39|rhydolabz (Samsung)|`f14754419c08…`|
|`TC58NVG1S3ETA00_Toshiba.pdf`|Toshiba 1Gb SLC NAND, datasheet completo|65|Digi-Key (Toshiba)|`833782e525e9…`|
|`TC58BVG0S3HTA00_Kioxia.pdf`|Kioxia 1Gb BENAND (ECC integrato)|47|xonstorage (Kioxia)|`eb7ad5066a56…`|
|`TC58NVG1S3H_Kioxia.pdf`|**solo brochure marketing** (non un datasheet)|3|xonstorage (Kioxia)|`7570b43168d2…`|
|`MT29F1G08_Micron.pdf`|Micron 1Gb x8/x16 SLC NAND|95|Digi-Key (Micron)|`4570b6a82df1…`|
|`Nikon_S33_Reference_Manual_EN.pdf`|Manuale ufficiale Nikon COOLPIX S33|148|Nikon (nikonimglib)|`03cc47d1917e…`|
|`USB_MassStorage_BOT_1.0.pdf`|USB-IF Mass Storage Bulk-Only Transport 1.0|22|USB-IF (usb.org)|`9137e8eefaf3…`|

Perché i NAND 1Gb SLC a pagina 2048+64: la memoria interna della S33 usa pagine da **2112 byte (2048+64), 64 pagine/blocco** — la geometria verificata dai dump e dai verificatori del progetto. I datasheet scaricati coprono le famiglie Samsung/Toshiba-Kioxia/Micron di quella classe; **nessuno di questi è provato essere il chip montato** (vedi limiti).

## Non ottenuti (con motivo)

- **ASIC `SD10P220`**: nessun datasheet pubblico esistente (ricerca eseguita; ID Nikon proprietario). La documentazione più vicina resta il core **ARC700**, già archiviato in `outputs/arc700_public_references/` (ExternalInterfaces, MemoryComponents, MMU, ISA ARCompact).
- **Hynix HY27UF081G2M** (famiglia equivalente): PDF diretto non trovato, solo aggregatori con accesso limitato (alldatasheet/datasheetbank).
- **DDR SDRAM**: chip non identificato (nessun marking noto nei documenti del progetto; `DDR_SIZE_ID 0120` è un codice Nikon interno, non un JEDEC ID) — nessuna base onesta per scegliere un datasheet.
- **LCD/audio/regolatori**: chip non identificati; la S33 non ha teardown pubblici a livello chip (iFixit ha solo la sostituzione batteria/SD).

## Come identificare i chip esatti

L'identificazione certa richiederebbe i **marking sulla scheda** (fotografie del PCB): la S33 è sigillata waterproof, quindi aprirla ha rischi concreti e non è stata richiesta. In alternativa, il datasheet del NAND esatto si può dedurre in parte dal firmware (timing/comandi), ma i comandi SLC standard sono comuni a tutta la famiglia — per questo la raccolta copre la classe, non il singolo lotto.

## Limiti

- Scaricamenti da mirror pubblici (rhydolabz, Digi-Key media, xonstorage, usb.org, nikonimglib): TLS dei mirror non sempre verificato per hostname; identità dei PDF registrata per hash nel manifest, come già praticato per le fonti ARC700.
- Il PDF Samsung è la revisione **U0D** (la U0C è citata nel documento); stessa geometria di pagina.
- Nessuna di queste fonti è stata usata per dedurre nuovi indirizzi/semantica del firmware: restano documentazione.

## Uso nel progetto

Il BOT 1.0 dell'USB-IF è il riferimento formale del trasporto MSDC già implementato dal client del progetto; i datasheet SLC 1Gb forniscono il contesto dei timing ECC/OOB già analizzati con le fonti Linux v6.1 (archiviate in `Risultati/Dump_fotocamera/NAND_ECC/fonti/`). Il manuale Nikon ufficiale documenta memoria interna, batteria EN-EL19 e supporto schede della macchina reale.
