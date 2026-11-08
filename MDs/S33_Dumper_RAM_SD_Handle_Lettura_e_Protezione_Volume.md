# Dumper RAM: handle di lettura e protezione del volume

**Aggiornamento prioritario:** [catena integrata e falso successo](S33_Dumper_RAM_SD_Lookup_Integrato_e_Falso_Successo_Parser.md). Le condizioni a fixture di questo rapporto non predicono ogni esito della catena originale: errore alloc257 del parser, scratch0, finder originale→record vuoto con stato0, accettato dalla callbackr. Non assumere sempre01A00002 né identità del file dal solo successo. Risultato offline, non hardware.

23 ottobre 2026, R0/R1/R4. Segue [lista file e guardia volume](S33_Dumper_RAM_SD_Lista_File_e_Guardia_Chiusura_Volume.md). **12 casi CPU originali** provano il percorso `r` verso un record esistente e la sua partecipazione alla lista che blocca la chiusura del volume nel backend1. Un caso mantiene il riferimento `r` mentre apre/chiude un secondo file `n`, con nome distinto.

Il risultato chiude la domanda locale lasciata dal rapporto precedente: non occorre creare un file nuovo per incrementare la lista degli oggetti vivi. Il lookup del record resta una fixture, quindi non è ancora una verifica completa dell'attraversamento della directory sulla SD.

## Prove riproducibili e confini

- [Runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_read_pin.py), [probe](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDReadPin.java), helper del test precedente conservati.
- [Manifest](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Pin/20261022T234815Z/verified_evidence.json), [12 esiti](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Pin/20261022T234815Z/trace.txt), [11 finestre GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Pin/20261022T234815Z/gnu_verified.txt), [log](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Pin/20261022T234815Z/headless.log), [candidati helper backend](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Pin/20261022T234815Z/backend_helper_candidates.json).

```bash
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_pin.py
```

Le callback open/close1F43AC/1F48A4,21A0D0, allocazione adattatore2AC528, lista, resolver, semaforo e primitive critiche sono originali. I wrapper generici sono predisposti dal test. **Lookup2A3360** fornisce un record da32byte o uno stato d'errore esplicito; il pool fornisce oggetti azzerati da80byte o nullo e registra i rilasci. Clock/cache/dirty e ioctl3 hanno gli stessi limiti della prova precedente. Nessun registro dispositivi o wrapper superiore open/close è eseguito.

Nel solo caso combinato, l'apertura `n` usa il confine create2AC2B4 del probe precedente. **L'esecuzione dedicata a `r` rifiuta come errore del test qualunque visita a2AC2B4.** Questo distingue il percorso software senza trasformare il lookup simulato in una lettura fisica, né provare l'esclusività del create simulato.

Sorgenti e snapshot sono verificati tramite hash, insieme ai payload canonici. GNU resta sola lettura; nessun dispositivo, dump originale o firmware è scritto.

## Percorso r e flag temporaneo

Il parser1F43AC seleziona **1F4586** per `r`: se il carattere successivo è `+` passa2, altrimenti0 a **21A0D0**, usando context+424 come handle e il nome dopo il prefisso del dispositivo.

21A0D0 risolve e acquisisce il contesto tramite2A1300. Prima del lookup scrive **1 a context+720 (180×4)** e chiama2A3360 conr5=0. Nei casi provati il flag viene **riportato a0 nel delay slot21A17C prima del post2A1398**, sia dopo successo sia dopo rifiuti attributi, errore lookup o allocazione nulla. Non lo si associa a un registro fisico.

Quando stato lookup=0 e il puntatore al record è valido, legge il byte record+11. Maschera0x18 nonzero→01A0000E; bit0 impostato con modo1/2→01A00004. Il modo0 usato da `r` accetta anche bit0. I nomi fisici dei bit non sono necessari alla prova: vengono verificati i valori grezzi e i rami originali.

Il record accettato passa a2AC528: viene creato un oggetto nella stessa lista **context+100, count halfword+108**, e il suo modo a object+44 è0 perr,2 perr+. La copia del record conserva il marcatore sintetico0x41424344. Nessun create è necessario in questo percorso.

## Matrice eseguita

| Input | Ritorno open | Oggetto/lista |
|---|---|---|
|r, attributi0/1/0x20|0 nei tre casi|un oggetto, modo0|
|r, attributi0x10/8/0x18|01A0000E nei tre casi|nessun oggetto|
|r+, attributo1|01A00004|nessun oggetto|
|r+, attributi0|0|un oggetto, modo2; controllo distinto dar|
|errore lookup fornito01A00002|01A00002|nessun oggetto/pool|
|pool nullo|01A00006|nessun oggetto in lista|
|contesto non pronto|01A0000C|lookup e pool non chiamati|
|r mantenuto durante n open/close|0|count1→2→1→0, volume protetto fino all'ultimo close|

Ogni rifiuto lascia wrapper+4 nullo. Gli oggetti accettati impediscono volume close e ingresso225A60: entrambi restituiscono01A00010, conservando volume/ready/backend nei punti controllati. Dopo il close del riferimento `r`, il count torna0 e il volume è chiudibile. Stack, nesting critico, conteggio semaforo, ring/lista e numero rilasci sono verificati.

Il codice chiamante deve rispettare il contratto del lookup: stato0 implica un record valido nel test. Lo stato01A00002 qui è **fornito dalla fixture**; non dimostra il codice reale di ogni file assente o errore SD. Il modo0 e l'assenza del create non dimostrano assenza di ogni possibile scrittura del filesystem: cache/dirty e persistenza restano fuori prova.

## Sequenza con riferimento mantenuto

Il caso combinato usa due nomi distinti nel modello: `B:\AKERUDMP.ON` per il record esistente di appoggio e `B:\AKR00000.DMP` per il nuovo output. Non verifica la presenza fisica del trigger e non autorizza il primo file a essere creato.

1. Callbackr→lookup fixture→oggetto vivo, count1.
2. Volume close e225A60 rifiutano con01A00010.
3. Callbackn sul secondo nome→create fixture→secondo oggetto, count2.
4. Close del nuovo oggetto→count1; volume close resta rifiutato.
5. Close del riferimento di lettura→count0; volume close riesce.

Le chiamate sono sequenziali nello stesso task di laboratorio. Non sono un test di interleaving, rimozione SD o perdita di alimentazione. Il risultato permette di studiare il preflight con un riferimento già aperto, evitando una doppia acquisizione del semaforo non ricorsivo; non prova ancora ogni condizione necessaria al binding.

## Percorsi noti verso gli helper backend

La ricerca nel listato lineare Main restituisce cinque chiamate ai due helper; tutte le cinque istruzioni sono confermate nelle nuove finestre GNU.

| Callsite | Destinazione e portata |
|---|---|
|1F3FAA|1F35D4, selezione nel mount già provato|
|1F3FBC|1F3608, init speciale nel mount|
|1F46F4|1F35D4 conflag0: non azzera il backend|
|225AB2|1F35D4 conflag1, dopo la guardia d'ingresso225A60|
|225F66|1F3608 nel successivo percorso della stessa routine|

Nessuna occorrenza byte-per-byte **LE32 o immediate ARC LIMM** degli indirizzi1F35D4/1F3608 nei16payload canonici. È un negativo limitato ai due pattern: non esclude indirizzi calcolati, dispatch indiretti, alias, altri store diretti di context+0x70 o codice non incluso nei payload. Anche il listato Main è un inventario candidato per le chiamate, non un census globale dell'intera macchina.

## Stato e prossimo passo

La strategia di mantenere un oggetto di lettura è ora sostenuta sul backend1 nei due ingressi di chiusura/riconfigurazione provati. Rimane da eseguire **2A3360** con il lookup inferiore e chiarire i suoi stati/allocazioni/alias; poi verificare gli altri scrittori diretti del backend e i percorsi superiori che aprono o chiudono il volume. Backend7/12 e concorrenza non sono coperti.

Non viene ancora scritto un adattatore Nikon per far apparire risolta l'integrazione: creazione esclusiva reale, cleanup, mappa RAM fisica completa, lifetime launcher/stack e recupero restano aperti. Il prototipo C e i BIN sono invariati. **NON_INSTALLARE**, nessuna SD fisica o fotocamera usata, circa10% funzionale AkeruOS invariato.

## Continuazione — coordinatore lookup originale, 23 ottobre 2026

[18 casi successivi](S33_Dumper_RAM_SD_Lookup_Parser_Errori_e_Buffer.md) eseguono2A3360 e parser con due livelli inferiori ancora fixture. Il fallimento alloc257 del parser non viene propagato: nel profilo0 finisce01A00002.259A58 non ha l'azzeramento di268EE4; profili heap0/A5 dichiarati. Non trasferire automaticamente le proprietà al test r precedente: integrazione ancora da fare. Prossimo2A318C/2A2D88; NON_INSTALLARE.

## Continuazione — walker e scanner originali, 23 ottobre 2026

[Nuova verifica](S33_Dumper_RAM_SD_Directory_e_Scanner_Record_Originali.md):20casi con2A318C originale nel coordinatore,8separati dello scanner2A2D88 su settore sintetico,18regressione. Errori directory e allocnull diventano01A00003; al marcatore0 lo scanner può conservare lo stato ricevuto. Non sono ancora una catena integrata né I/O fisico; prossimo albero di settori sintetici e raccordor. NON_INSTALLARE.
