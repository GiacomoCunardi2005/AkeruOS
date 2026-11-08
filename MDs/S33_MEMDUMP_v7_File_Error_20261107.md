# MEMDUMP v7: candidato offline con controllo file-error

Il 7 novembre 2026 `python3 Python_Trace_Scripts/s33_build_memdump_held_offline.py --checked` ha prodotto [firmware.bin](../Risultati/Firmware_sperimentali/MEMDUMP/OFFLINE_NON_INSTALLARE_20261107T125157753626Z/firmware.bin), SHA-256 `f095b56d73395f3fe6b78b34e554667ed21c36bb3d9c1de2f06e63e290ee3862`. **NON INSTALLARE.** Il candidato mantiene la copertura v5 `[0,0x0104074C)`, pertanto non realizza ancora il dump di tutta la RAM. Originale e v5 sono invariati.

La guardia richiede firma versione 7; l'adattatore controlla anche `file+0xC` dopo stato zero e prima di accettare un conteggio completo. Il builder ha verificato call site originali, checksum dei blocchi e del contenitore, perimetro delta e ripristino dell'originale; il disassemblato conferma confronto versione 7. Questo controllo non equivale a verificare l'integrità dell'intero payload.

Verifiche:

- [GNU ARC con fixture](../Risultati/Runtime_Kernel/MEMDUMP_Checked_Adapter/20261107T125122811610Z/verified_evidence.json): successo, quattro byte del file-error, conteggio corto, stato errore e inoltro di un altro owner.
- [P-code e FAT sintetica](../Risultati/Runtime_Kernel/MEMDUMP_V7_Hook_FAT/20261107T125248736079Z/evidence.json): il binario del candidato produce un file di 17.041.228 byte, una close, conteggi completi e fsck PASS; confronto DMA parziale.
- [Stessa catena con errore iniettato](../Risultati/Runtime_Kernel/MEMDUMP_V7_File_Error_FAT/20261107T125248750052Z/evidence.json): dopo una write modellata completa, la fixture imposta `file+0xC=0x01A00006`; il diagnostico seleziona il messaggio di errore `0x39304E`, dove la [v5](S33_MEMDUMP_Errore_File_Falso_Successo_20261107.md) selezionava successo. L'iniezione non è un guasto fisico né dimostra corruzione del file.

I test entrano nell'hook e schedulano il task tramite fixture; RAM, FAT e DMA sono modellate. Il worker ignora ancora l'esito della close: stato write, close e persistenza sono distinti. Non sono dimostrati boot, SD, recupero, mappa fisica completa o atomicità; il messaggio intercettato non prova una segnalazione visibile. **NON INSTALLARE.**
