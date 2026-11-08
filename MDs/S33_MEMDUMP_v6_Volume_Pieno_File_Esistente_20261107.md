# MEMDUMP v6: volume pieno e file esistente nel modello

Il 7 novembre 2026 `python3 Python_Trace_Scripts/s33_verify_memdump_held_v5.py --range-full` ha eseguito hook e task del candidato v6 su RAM alta, scheduler, FAT e DMA sintetici. Il firmware usato è quello con SHA-256 `9b00a67aa3b473c27f10f49af47d4a74f9bcb86dcec87703041c35c2170bc879`.

- Con quattro cluster liberi da 1024 byte, la prima scrittura di 256 byte riesce; la seconda richiede 1.048.576 byte, ne scrive 3840 e riporta `0x1A00014`. Il diagnostico emette il codice messaggio `0x39304E` verso una fixture e il task chiude l'handle una volta. Il file parziale `MEMHI.BIN` misura 4096 byte; prefisso e 3840 byte alti coincidono con la sorgente modellata e `fsck.fat -n` passa.
- Con un `MEMHI.BIN` preesistente da 2048 byte, il task non procede al diagnostico: i 110 settori del volume modellato restano invariati.

[Evidenze e traccia](../Risultati/Runtime_Kernel/MEMDUMP_V6_Hook_Full_FAT/20261107T020501785554Z/evidence.json). La [regressione del volume grande](../Risultati/Runtime_Kernel/MEMDUMP_V6_Hook_Large_FAT/20261107T020516038670Z/evidence.json) verifica ancora tutti i 1.048.576 byte sintetici e fsck.

Il codice messaggio intercettato non dimostra una segnalazione visibile sulla fotocamera. Un file parziale rimane presente e impedisce un nuovo tentativo con lo stesso nome nel modello. Questi risultati non dimostrano il comportamento di SD, RAM, boot o recupero fisici; la v6 acquisisce comunque solo una finestra, non l'intera RAM. **NON_INSTALLARE.**
