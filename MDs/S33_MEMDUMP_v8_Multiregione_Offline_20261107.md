# MEMDUMP v8: integrazione multiregione con mappa vuota

Il 7 novembre 2026 il builder `python3 Python_Trace_Scripts/s33_build_memdump_held_offline.py --map` ha creato il [candidato offline](../Risultati/Firmware_sperimentali/MEMDUMP/OFFLINE_NON_INSTALLARE_20261107T130016443730Z/firmware.bin), SHA-256 `6f43f93859378b728a1f6e3ef1fd5f22c6f1d214f9713d7c6c73a6c2856c8a4d`. **NON INSTALLARE. Questo file non effettua alcun dump:** la mappa fisica non è nota e il conteggio iniziale è zero. Non è il completamento dell'obiettivo.

Il binario collega hook, guardia con firma 8, task con controllo volume e percorso, sessione multiregione e i due call site Nikon al [prototipo verificato su FAT](S33_MEMDUMP_Multiregione_FAT_20261107.md). Il builder verifica checksum, byte originali dei call site, limiti del delta e ricostruzione inversa. La firma controlla solo intestazione/versione; non certifica il payload o la memoria.

- [Mappa vuota](../Risultati/Runtime_Kernel/MEMDUMP_V8_Empty_Map/20261107T130214949141Z/evidence.json): il banco entra due volte nell'hook, crea un task simulato, esegue il task del candidato e osserva zero scritture e chiusure; 110 settori sintetici invariati.
- [Mappa sintetica iniettata](../Risultati/Runtime_Kernel/MEMDUMP_V8_Fixture_Map/20261107T130202725974Z/evidence.json): il banco cambia **solo nella RAM emulata** il conteggio e due record della mappa; il codice e i call site patchati del candidato eseguono il diagnostico e creano due file di 768 e 1024 byte. Tutti i byte e le catene FAT sono confrontati, due close e fsck PASS. Questo non modifica il firmware salvato e non dimostra che quegli indirizzi siano validi sulla fotocamera.
- [Adapter ARC](../Risultati/Runtime_Kernel/MEMDUMP_Map_Adapter/20261107T130214906034Z/verified_evidence.json): regressione con I/O fixture PASS.

L'aggancio viene invocato direttamente; scheduler, volume, FAT, RAM e DMA sono modellati. La cattura completa richiede una mappa reale, la selezione di un meccanismo affidabile per fornirla, verifica degli errori integrati, boot, SD e recupero. Il task usa un'attesa limitata e la sessione non fornisce ancora conferma persistente della chiusura. **NON INSTALLARE.**
