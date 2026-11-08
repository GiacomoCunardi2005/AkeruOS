# Dumper RAM: walker directory e scanner record originali

**Aggiornamento prioritario:** [catena integrata e falso successo](S33_Dumper_RAM_SD_Lookup_Integrato_e_Falso_Successo_Parser.md). Le condizioni a fixture di questo rapporto non predicono ogni esito della catena originale: errore alloc257 del parser, scratch0, finder originale→record vuoto con stato0, accettato dalla callbackr. Non assumere sempre01A00002 né identità del file dal solo successo. Risultato offline, non hardware.

23 ottobre 2026, R0/R1/R4. Segue [coordinatore lookup e parser](S33_Dumper_RAM_SD_Lookup_Parser_Errori_e_Buffer.md). Due nuovi gruppi indipendenti riducono i confini simulati: **20 casi eseguono2A3360 con il walker2A318C originale;8 casi separati eseguono lo scanner2A2D88 su un settore sintetico.** La regressione precedente18casi passa dopo il riuso dell'harness. Non sono28 esecuzioni dell'intero filesystem: nei20casi i record sono ancora forniti da una fixture; negli8casi è la lettura del settore a essere simulata.

Sono chiariti due contratti d'errore: il walker directory comprime cause diverse in una sentinella1, che il coordinatore traduce in01A00003; lo scanner può tornare nullo al marcatore finale **senza scrivere lo stato ricevuto dal chiamante**.

## Prove riproducibili

| Gruppo | Sorgenti | Prove |
|---|---|---|
|20coordinatore+walker|[runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_directory.py), [probe](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDDirectory.java)|[manifest](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Directory/20261023T000027Z/verified_evidence.json), [traccia](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Directory/20261023T000027Z/trace.txt), [nove finestre GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Directory/20261023T000027Z/gnu_verified.txt)|
|8scanner record|[runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_record_finder.py), [probe](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDRecordFinder.java)|[manifest](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Record_Finder/20261023T075642Z/verified_evidence.json), [traccia](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Record_Finder/20261023T075642Z/trace.txt), [quattro finestre GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Record_Finder/20261023T075642Z/gnu_verified.txt)|
|18regressione|[runner precedente](../Python_Trace_Scripts/s33_verify_ram_dump_sd_lookup.py), [harness condiviso](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDLookup.java)|[manifest](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lookup/20261023T000056Z/verified_evidence.json), [traccia](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lookup/20261023T000056Z/trace.txt)|

```bash
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_directory.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_record_finder.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_lookup.py
```

Il probe condiviso conserva il comportamento precedente per default. Il nuovo probe abilita soltanto il corpo originale del walker, riusando parser, heap con guardie e controlli sugli errori. Snapshot e hash identificano ogni versione; la regressione è stata rieseguita dopo questa modifica. I16payload canonici sono verificati, GNU resta letto/eseguito senza modificarne sorgenti o build.

## Walker directory2A318C eseguito dentro2A3360

Il coordinatore non riceve più un risultato directory preconfezionato. Il walker originale alloca256byte, separa i componenti con29FF74, li valida e chiama2A2D88 con selettore0x10 per i record di directory. Per la radice vuota non chiama il finder di componenti. Sono originali anche classificazione di punto/punto-punto, copie/stringhe e decodifica dei campi; i casi specifici punto/punto-punto non sono inclusi nella matrice pubblicata.

La fixture del finder directory fornisce due record espliciti, con attributo0x10: DIR contiene valore cluster0x00012345, sub contiene0x00023456. Il codice originale ricompone i byte record+0x1A/+0x1B e+0x14/+0x15, poi applica una maschera. **Nel backend1 provato la maschera è0xFFFF**, quindi i risultati osservati sono0x2345 e0x3456. Questa è la semantica software del profilo, non una prova di cluster fisici o una diagnosi di perdita dati: i campi alti sono appositamente sintetici. Il ramo backend12 usa una maschera diversa ma non è certificato dalla matrice CPU.

| Percorso nel coordinatore | Chiamate per directory | Risultato walker |
|---|---:|---|
|nome alla radice, con slash o backslash|0|0|
|nome relativo, directory normalizzata vuota|0|0x123 predisposto in context+0x74|
|directory DIR seguita dal nome file|1|0x2345|
|DIR/sub seguiti da FILE.BIN|2|0x3456|

Restano i profili scratch0/0xA5 e il controllo con flagcontext+720 a0 del rapporto precedente. Con flag1, un percorso ordinario completo ora richiede quattro allocazioni517/257/256/256, tutte liberate; con flag0 tre. Le guardie, i link di controllo degli output, stack e nesting critico restano verificati. La selezione del callsite finale sensibile allo scratch alla radice è confermata anche con il walker originale.

### Compressione degli errori

Tre casi distinti raggiungono **walkerResult=1** e **stato finale01A00003** nel coordinatore:

- finder directory restituisce puntatore nullo e stato0;
- finder directory restituisce un record ma stato01A00021; il walker controlla anche lo stato e rifiuta il record;
- allocazione256 interna al walker fallisce, prima della ricerca dei componenti.

Il corpo2A318C non espone al coordinatore un codice che distingua questi motivi: l'allocazione nulla ritorna1 da2A31B2, il record nullo/stato nonzero passa da2A3316, e2A3360 traduce1 in01A00003. Quindi01A00003 non dimostra da solo che una directory sia assente. Non si conclude che01A00021 sia un errore fisico misurato: è un codice fornito dal confine simulato.

Rimane confermato l'altro mascheramento: fallimento alloc257 del parser, con scratch0, porta a nome vuoto e01A00002. Prime e terze allocazioni del coordinatore fallite restano01A00006. Il caso della quarta allocazione ora aggiunge una causa diversa che diventa01A00003. In tutti20casi i buffer effettivamente acquisiti sono liberati una volta.

La finestra statica identifica anche la stringa **DCIM**: pool2A324C→0x352478. Il relativo percorso di ottimizzazione è fuori matrice; non viene simulato come se fosse una directory ordinaria già verificata.

## Scanner2A2D88: record originali su un settore sintetico

Qui il finder non è sostituito. Esegue il suo corpo completo, parser del nome breve2A01AC, confronto2A0144, filtro attributi2A017C e stringhe/millicode. La fixture2A1178 restituisce un buffer da512byte o errore;21B2CC/21A454 restituiscono0 per escludere oggetti cache esterni. Contesto: cluster radice0,16record/settore, un solo settore. Nessuna lettura fisica o FAT.

La finestra GNU parte dall'ingresso corretto2A2D88 e termina2A318C: evita i falsi callsite prodotti iniziando il disassemblaggio a metà istruzione. La chiamata del filtro attributi è **2A2FEC→2A017C**; il frammento lineare iniziato a2A2FEE avrebbe interpretato la seconda metà come una falsa chiamata breve a2A2AA8.

| Caso | Risultato originale |
|---|---|
|AKERUDMP.ON nel primo record|puntatore al record0, metadata offset0|
|stesso nome dopo record cancellato0xE5, altro nome e record non corrispondente conattr0x0F|puntatore al record3, offset3|
|query minuscola akerudmp.on, record maiuscolo|corrispondenza al record0|
|selettore0x10, due record DIR conattr0x20 poi0x10|primo escluso, secondo selezionato, offset1|
|nome assente seguito da marcatore0|nullo, stato iniziale conservato|
|stessa assenza con stato iniziale0|nullo, stato finale0|
|lettura settore simulata fallisce01A00021|nullo, stato finale01A00021|
|record corrispondente posto dopo un marcatore0 iniziale|nullo: non raggiunge il record successivo; stato conservato|

Ogni caso richiede esattamente una lettura del settore. Il buffer sintetico da512byte rimane byte per byte invariato e la query viene ripristinata dopo gli edit temporanei. La prova conattr0x0F non è una certificazione di catene di nomi lunghi: è soltanto un record non corrispondente davanti al risultato breve.

### Lo stato va inizializzato dal chiamante

Nei due ritorni al marcatore0 con canary iniziale **0xCAFEBABE**, il finder lascia quel valore invariato: il ramo **2A2FDE→2A3182** salta lo store finale dello stato a2A3180. Il controllo con stato iniziale0 conserva invece0. Nei casi con record trovato il percorso finale scrive0; nel caso di errore settore scrive il codice fornito dalla lettura.

Non è corretto descrivere ogni assenza come «il finder scrive0». Il contratto locale richiede un input di stato inizializzato prima della chiamata.2A3360 predispone già il proprio stato0 e traduce puntatore nullo/stato0 in01A00002, come verificato nel gruppo del coordinatore con finder ancora fixture. Le due prove sono coerenti ma **non ancora collegate in un'unica esecuzione**.

I primi tentativi dello scanner sono conservati: un metodo del probe collideva con find finale dell'API Ghidra; poi il controllo iniziale si aspettava erroneamente uno store0 nel caso di marcatore finale. Corretti nome del metodo e aspettativa sulla base del ramo originale, senza modificare opcode del firmware.

## Confini ancora aperti

Le20sequenze terminano al finder record simulato; gli8casi dello scanner partono direttamente dal finder con un settore predisposto. Cache reale, attraversamento dei cluster, più settori, nomi lunghi completi, rimozione SD, backend12/DCIM e concorrenza non sono coperti. Il comportamento dei record deriva dal dataset, non da una directory acquisita dalla macchina.

Prossimo: collegare coordinatore→walker→finder originali sullo stesso albero di settori sintetici; poi attraversamento dei cluster e I/O inferiore, raccordo conr e con i percorsi di creazione esclusiva/cleanup. Rimangono mappa fisica RAM completa e lifetime launcher/stack. Nessun adattatore Nikon dichiarato pronto.

Nessun C applicativo o BIN modificato, nessuna fotocamera/SD fisica usata. **NON_INSTALLARE**, circa10% funzionale AkeruOS invariato; obiettivo generale di decodifica attivo.

## Continuazione — lettore e trasferimento eseguiti

[S33_Dumper_RAM_SD_Settori_Cache_e_Trasferimento_Originale.md](S33_Dumper_RAM_SD_Settori_Cache_e_Trasferimento_Originale.md): lettore/cache28casi, trasferimento25, lookup integrato20 fino a callback dispositivo sintetica. ProdottoDSP dichiarato e driver simulato; non prova persistenza fisica o r/open/close integrati. Il rapporto distingue regressioni e limiti; nessun hardware.
