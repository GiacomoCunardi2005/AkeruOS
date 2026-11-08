# MEMDUMP multiregione: diagnostico originale e FAT sintetica

Il 7 novembre 2026 `python3 Python_Trace_Scripts/s33_verify_memdump_held_adapter_fat.py --map` ha eseguito il [prototipo multiregione](S33_MEMDUMP_Mappa_Multiregione_Prototipo_20261107.md) compilato ARC insieme al diagnostico Nikon `0x16ED40`, ai wrapper di apertura/scrittura/close e a FAT originale in P-code. I due call site del diagnostico vengono instradati all'adattatore da una fixture; non è un firmware installato.

Con mappa sintetica `[0x4000,0x4200)` e `[0x8000,0x8300)`, il modello crea `00004000.BIN` e `00008000.BIN`: quattro deviazioni, due close, due regioni completate. Parser host confronta tutti i byte dei due file, inclusi i rispettivi prefissi da 256 byte, controlla le catene FAT e `fsck.fat -n` passa. [Evidenza](../Risultati/Runtime_Kernel/MEMDUMP_Map_Adapter_FAT/20261107T125824593094Z/verified_evidence.json).

Per consentire il link freestanding `-Os`, l'inizializzazione del nome nel prototipo è ora un ciclo esplicito: prima il compilatore richiedeva `memcpy` non disponibile. Regressioni: [GNU ARC con fixture](../Risultati/Runtime_Kernel/MEMDUMP_Map_Adapter/20261107T125838871787Z/verified_evidence.json), host ASan/UBSan e [adapter precedente su FAT](../Risultati/Runtime_Kernel/MEMDUMP_Held_Adapter_FAT/20261107T125838895509Z/verified_evidence.json) PASS.

Le regioni, la RAM, il filesystem, la DMA e il controller sono modellati; la fixture fornisce anche il percorso diagnostico e intercetta i call site. I casi di errore multiregione sono testati con I/O fixture, non in questa prova FAT. Mancano mappa fisica verificata, gestione volume/task e aggancio nel firmware; non si dimostra acquisizione completa, boot, SD o recupero. **NON_INSTALLARE.**
