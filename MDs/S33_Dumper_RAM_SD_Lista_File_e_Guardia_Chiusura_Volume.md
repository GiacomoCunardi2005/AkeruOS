# Dumper RAM: lista degli oggetti file e guardia di chiusura del volume

23 ottobre 2026, R0/R1/R4. Continuazione di [montaggio e chiusura](S33_Dumper_RAM_SD_Mount_Chiusura_e_Stabilita_Backend.md). **Sei sequenze CPU originali collegano apertura n, lista file, callback close e guardia del volume nel backend1.** La halfword context+108 è il conteggio della lista di oggetti file, con testa a context+100: non è più soltanto una guardia di significato ignoto.

Un oggetto file vivo impedisce la chiusura del volume tramite il percorso provato. Con due oggetti il rifiuto permane dopo il primo rilascio; soltanto dopo l'ultimo la chiusura riesce. È una base concreta per studiare un handle mantenuto aperto durante il preflight, non ancora un binding completo o una garanzia contro ogni smontaggio/riconfigurazione.

## Prove e riproduzione

- [Runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_file_lifetime.py), [probe](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDFileLifetime.java).
- [Manifest](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Lifetime/20261022T234314Z/verified_evidence.json), [sei sequenze](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Lifetime/20261022T234314Z/trace.txt), [15 finestre GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Lifetime/20261022T234314Z/gnu_verified.txt), [log](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Lifetime/20261022T234314Z/headless.log), [14 candidati di chiamata](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Lifetime/20261022T234314Z/linear_call_candidates.json).

```bash
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_file_lifetime.py
```

Ogni sequenza parte da un contesto montato esplicito, backend1/ready1, puntatore volume context+424, semaforo context+388 con conteggio1. I wrapper generici da32byte sono predisposti dal test; vengono però eseguite **le callback originali1F43AC e1F48A4**, che collegano e leggono i rispettivi oggetti. Non viene eseguito il registro dispositivi o il wrapper generico open/close superiore.

**Codice originale eseguito:** parser n→2A1648, resolver, allocatore adattatore2AC528, memcpy225618, lista2E8A54/2E8BB0, primitive critiche1786E8/179354, wait/post, close normale21AD30→2AC564, close volume1F46C4, gate2A45E4 e rifiuto iniziale225A60. Sorgenti/snapshot e payload sono verificati tramite hash. Nessun builder GNU o modifica ai campioni canonici.

**Fixture:** creazione directory2AC2B4 fornisce un record sintetico oppure collisione; pool2F7ABC fornisce oggetti azzerati da80byte oppure nullo;2F7AF0 registra il rilascio. Clock21B300 fornisce zeri, predicato cache21A424 vale0 e il campo dirty rimane0, quindi i rami di aggiornamento storage del close non sono percorsi. Ioctl3 del volume ritorna0. Non sono prove fisiche di creazione esclusiva, cache, persistenza o FAT.

## Layout e produttori identificati

| Campo | Interpretazione verificata |
|---|---|
|context+100/+104|next/prev della testa circolare|
|context+108, halfword|numero oggetti in lista|
|context+110, halfword|limite della lista;0 nel costruttore usato dal mount ordinario|
|object+0/+4|next/prev del nodo|
|object+8|magic0x4D465356; complementata prima del rilascio|
|object+12..43|record da32byte copiato dall'entry sintetica|
|wrapper+0|dispositivo|
|wrapper+4|oggetto file pubblicato dalla callback open|

**2A45D4(list,limit)** mette testa/prev a se stessa, count0 e limit. Il mount ordinario precedente lo chiama con list=context+100 e limit0; il nuovo probe ripete questo inizializzatore originale. Il test non deduce dal limite0 una capacità infinita del pool reale.

**2AC528(context,entry)** richiede un oggetto al pool context+416. Se non nullo invoca **2E8A54(context+100,object)**, scrive la magic e copia32byte dell'entry tramite225618. Il marcatore sintetico0x41424344 viene verificato in object+12, quindi la copia non è controllata soltanto con dati già tutti zero. La callback n pubblica l'oggetto a wrapper+4 presso1F4618.

**2E8A54** aggiorna i link della lista e incrementa la halfword count sotto le primitive critiche originali. **2AC564(context,object)**, se object non nullo, invoca **2E8BB0(context+100,object)**: scollega il nodo e decrementa count, poi complementa magic e richiede il rilascio al pool. L'argomento object nullo non altera la lista e non richiede rilascio.

Il close di un file ordinario viene seguito dalla callback1F48A4 fino a21AD30: quest'ultima risolve contesto/oggetto con2A1344, prende il semaforo, raggiunge2AC564 e poi rilascia il semaforo. Non si tratta soltanto di un decremento applicato dal test. Nei confini descritti, a ogni ritorno stack, nesting critico e semaforo sono verificati; lista circolare, link prev, coda e count devono concordare.

## Sequenze eseguite

| Sequenza | Risultato |
|---|---|
|nessun file|close volume0, lista vuota|
|un open n riuscito|count1; close volume01A00010; close file→count0; close volume0|
|due open, rilascio nell'ordine di apertura|count2→1→0; volume rifiutato a2/a1, consentito a0|
|due open, rilascio inverso|stessi esiti e lista coerente|
|pool nullo|open01A00006, nessun oggetto pubblicato o inserito; close volume consentito|
|collisione della fixture create|open01A00011, pool non chiamato, lista0; close volume consentito|

In ogni sequenza viene infine provato il rilascio nullo: nessuna ulteriore richiesta al pool e lista invariata. Le due sequenze a due file provano anche che il comportamento non dipende dal rilascio del nodo di testa rispetto alla coda.

Dopo il close della callback, **wrapper+4 conserva il vecchio indirizzo dell'oggetto già rilasciato**. Non autorizza il riuso o un secondo close: il livello generico superiore possiede il wrapper e ne gestisce la distruzione, come documentato nel rapporto sugli handle. La callback da sola non consuma o azzera quel puntatore.

## Guardia di volume e secondo percorso di riconfigurazione

Per backend1, la callback volume1F48A4→1F46C4 riacquisisce il semaforo e interroga **2A45E4(context+100)**. Il codice ritorna1 solo se count è0. Quando vi sono uno/due oggetti vivi, ritorno volume **01A00010** e context+424 conservato; dopo l'ultimo close, context+424 viene azzerato e ritorno0.

Nelle tre sequenze con oggetti vivi viene eseguito anche l'ingresso **225A60**: acquisisce il semaforo con2A12D8 e applica lo stesso gate2A45E4, quindi rilascia e ritorna **01A00010 prima di modificare ready, backend o puntatore volume**. Il caso senza oggetti non esegue il ramo successivo di questa routine. Non attribuiamo ancora un nome UI o un comportamento fisico all'intero servizio; la portata nuova è il suo rifiuto sotto guardia.

Questi risultati rispondono positivamente alla domanda locale «un oggetto file impedisce la chiusura del volume e questo ingresso di riconfigurazione nel backend1?». Non dimostrano che tutti i modi di cambiare backend o rimuovere il supporto passino da questa guardia.

## Ricerca limitata e limiti del binding

Il manifest separato conserva14 chiamate candidate ai sei helper pertinenti nel listato lineare Main. Fra queste,2AC528 è chiamato da n/w/x/d e21A14E;2AC564 da21AE80. Le API lista2E8A54/2E8BB0 hanno anche chiamanti2772xx: non attribuirli al filesystem senza seguire le basi. La scansione non copre altri payload, chiamate indirette, copie o tutti gli scrittori del contesto. Le finestre GNU qui pubblicate validano i percorsi effettivamente discussi, non ogni candidato del listato.

- Backend7 e12 fuori dalle sequenze: nessuna garanzia di mantenimento del volume per quegli oggetti o layout.
- Sequenze senza concorrenza reale; heap/cache e directory create simulati. Non si conclude sulla sicurezza di una SD o di un flash.
- Le prove non coprono close con dati dirty/cache attiva, esaurimento del pool reale, overflow del contatore o tutte le operazioni di riconfigurazione.
- Non è ancora dimostrata l'apertura di un file esistente in sola lettura come handle di appoggio: qui il percorso open provato è n con create fixture.

**Prossimo:** seguire r/open-existing e i suoi oggetti per verificare un handle di appoggio senza creazioni preliminari; completare i chiamanti che cambiano backend e i livelli superiori di sincronizzazione. Solo dopo raccordare validazione del backend e creazione new-only. Restano mappa fisica RAM completa, lifetime launcher/stack e contratto affidabile degli errori/cleanup.

Nessun prototipo C o BIN modificato, nessuna fotocamera connessa dal verificatore. **NON_INSTALLARE**, circa10% funzionale AkeruOS invariato; obiettivo generale di decodifica ancora aperto.

## Continuazione — riferimento di lettura, 23 ottobre 2026

[12 casi successivi](S33_Dumper_RAM_SD_Handle_Lettura_e_Protezione_Volume.md) seguono r/r+ fino a lookup fixture2A3360 e lista oggetti originale. r non chiama create, modo0 mantiene la guardia volume; un caso conserva r durante n su nome diverso. Attributi, errori e flagcontext+720 verificati. Non è prova fisica di file esistente o assenza di ogni scrittura filesystem. Prossimo: corpo lookup e altri scrittori/backend; NON_INSTALLARE.

## Continuazione — FAT multisettore e r/driver/close

[S33_Dumper_RAM_SD_Catena_FAT_Multisettore_e_Identita_File.md](S33_Dumper_RAM_SD_Catena_FAT_Multisettore_e_Identita_File.md):34casi avanzamento/decoder,13catena multisettore e7r/driver/close. Il precedente limite del lettore sostituito nella sequenza r è superato per l’albero con un settore per directory; la FAT multisettore è provata separatamente. Nuovi casi errore FAT perso, voce0 che riporta alla root, ciclo limitato e root esaurita. Close libera tre buffer ma non ne azzera le celle. Driver/DSP/pool dichiarati; nessun hardware o BIN.
