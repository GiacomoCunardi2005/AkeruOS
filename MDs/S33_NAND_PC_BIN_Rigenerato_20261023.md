# BIN NAND/PC rigenerato — 23 ottobre 2026

Su richiesta «fallo il bin» è stato rigenerato il candidato completo NAND/PC v2 con il builder esistente `Python_Trace_Scripts/s33_build_nand_pc_v2.py`. Nessuna nuova patch: il file coincide byte per byte con la build v2 del 21 ottobre. Non contiene il dumper RAM su SD, il cui binding resta incompleto.

- [BIN sperimentale](../Risultati/USB_SCSI/Accesso_NAND_PC/container_v2_20261022T232556Z/S33_NAND_PC_RAW_V2_NON_INSTALLARE.bin): 29,602,084 byte, 16 record e offset originali conservati.
- SHA-256: `39bdefdf9a00948463f528fc11aec36da17b5599f16340be45eacec8c369b6e4`.
- [Verifica della build](../Risultati/USB_SCSI/Accesso_NAND_PC/container_v2_20261022T232556Z/verified_evidence.json): checksum payload/KHIR/XOR, parser del contenitore e rollback esatto; TBIB e P1RES invariati.
- [Confronto riproducibile](../Risultati/USB_SCSI/Accesso_NAND_PC/container_v2_20261022T232556Z/rebuild_comparison.json): uguaglianza esatta con il candidato precedente; i 31 casi CPU e le 256 lunghezze parser sono prove precedenti sul medesimo hash, non una nuova esecuzione CPU.

Nessuna azione sulla fotocamera o sulla SD. Il risultato è un artefatto locale sperimentale **NON_INSTALLARE**: integrità del file verificata, avvio completo, residenza runtime e recupero fisico non certificati. Non costituisce una risposta positiva alla precedente domanda sulla sicurezza dell'installazione.

R0/R4: consegna del contenitore richiesta, nessun incremento funzionale AkeruOS. Prossimo passo: verificare residenza e percorso updater/recupero del candidato v2 prima di rivalutare l'installazione. Riferimento: [candidato v2 e limiti](S33_NAND_PC_Candidato_V2_16_Record.md).

## Ulteriore rigenerazione richiesta — 08:21 UTC

Su nuova richiesta «fallo il bin», [BIN rigenerato](../Risultati/USB_SCSI/Accesso_NAND_PC/container_v2_20261023T082105Z/S33_NAND_PC_RAW_V2_NON_INSTALLARE.bin) con il builder esistente. Dimensione 29.602.084 byte e SHA-256 `39bdefdf9a00948463f528fc11aec36da17b5599f16340be45eacec8c369b6e4`; identico byte per byte alla precedente consegna. [Integrità e rollback](../Risultati/USB_SCSI/Accesso_NAND_PC/container_v2_20261023T082105Z/verified_evidence.json) rieseguiti con esito positivo; [confronto](../Risultati/USB_SCSI/Accesso_NAND_PC/container_v2_20261023T082105Z/rebuild_comparison.json). Nessuna nuova funzione, nessun dumper RAM e nessuna prova hardware: stato **NON_INSTALLARE** invariato.

## Ulteriore rigenerazione richiesta — 09:47 UTC

Su richiesta «fallo il bin», [BIN rigenerato](../Risultati/USB_SCSI/Accesso_NAND_PC/container_v2_20261023T094756Z/S33_NAND_PC_RAW_V2_NON_INSTALLARE.bin) con il builder esistente. Dimensione 29.602.084 byte, 16 record e SHA-256 `39bdefdf9a00948463f528fc11aec36da17b5599f16340be45eacec8c369b6e4`: identico byte per byte alla consegna delle 08:21 UTC. [Integrità contenitore e rollback esatto](../Risultati/USB_SCSI/Accesso_NAND_PC/container_v2_20261023T094756Z/verified_evidence.json) rieseguiti con esito positivo; [confronto](../Risultati/USB_SCSI/Accesso_NAND_PC/container_v2_20261023T094756Z/rebuild_comparison.json). Nessuna nuova patch o funzione RAM su SD, nessuna nuova prova CPU o hardware. Stato **NON_INSTALLARE**: avvio completo, residenza runtime e recupero fisico non certificati. R0/R4 invariati; prossimo punto utile verificare questi limiti prima di rivalutare l'installazione.

## Consegna richiesta con nome firmware.bin — 19:17 UTC

Ricostruito il candidato USB/NAND e preparato il file [firmware.bin](../Risultati/USB_SCSI/Accesso_NAND_PC/container_v2_20261023T191711Z/firmware.bin), 29.602.084 byte, SHA-256 `39bdefdf9a00948463f528fc11aec36da17b5599f16340be45eacec8c369b6e4`. [Integrità e rollback](../Risultati/USB_SCSI/Accesso_NAND_PC/container_v2_20261023T191711Z/verified_evidence.json) PASS; [confronto e copia di consegna](../Risultati/USB_SCSI/Accesso_NAND_PC/container_v2_20261023T191711Z/rebuild_comparison.json) byte-identici alla build09:47. Il nome richiesto non introduce una nuova funzione: è il candidato USB/NAND esistente, senza dumper RAM su SD. Nessuna copia su SD o operazione sulla fotocamera. NON_INSTALLARE: sicurezza di avvio/residenza/recupero non dimostrata; R0/R4 e obiettivo dumper offline invariati.
