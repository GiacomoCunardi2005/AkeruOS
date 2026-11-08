# MEMDUMP v8: errori multiregione su FAT sintetica

Il 7 novembre 2026 `python3 Python_Trace_Scripts/s33_verify_memdump_held_v5.py --map-errors` ha eseguito il [candidato v8](S33_MEMDUMP_v8_Multiregione_Offline_20261107.md) esatto, iniettando tre intervalli sintetici soltanto nella RAM emulata. Scheduler, volume, FAT, memoria, DMA e controller sono modellati; non è un test della fotocamera.

- **Secondo file già presente:** la prima regione completa e viene chiusa; il secondo nome viene rifiutato, il file preesistente da 2048 byte resta identico e il terzo file non viene creato.
- **Volume pieno durante la seconda regione:** la prima regione completa; la seconda lascia 3072 byte (prefisso 256 più 2816 di dati), riporta errore e viene chiusa; la terza non parte. Il contatore in RAM resta a una regione completata.

Un parser host segue le catene FAT e confronta i contenuti, inclusa la parte parziale; entrambe le immagini passano `fsck.fat -n`. [Evidenza](../Risultati/Runtime_Kernel/MEMDUMP_V8_Map_Errors/20261107T130419918161Z/evidence.json). Regressioni del candidato [mappa sintetica](../Risultati/Runtime_Kernel/MEMDUMP_V8_Fixture_Map/20261107T130434894803Z/evidence.json) e [mappa vuota](../Risultati/Runtime_Kernel/MEMDUMP_V8_Empty_Map/20261107T130434908911Z/evidence.json) PASS.

La v8 non salva sulla SD la mappa richiesta o un attestato di fine acquisizione: nome e lunghezza di un file isolato non bastano a dimostrare la completezza dell'insieme senza conoscere la mappa e l'esito della close. Mappa fisica, durata, boot, SD reale e recupero restano aperti; il firmware reale ha mappa vuota e non acquisisce nulla. **NON INSTALLARE.**
