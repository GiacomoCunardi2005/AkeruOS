# S33 — motori write, PMSD/DEVSD e rilettura dalla SD sintetica

23 ottobre 2026, R0/R1/R4. Continuazione della [scrittura asincrona e PIO](S33_Dumper_RAM_SD_Scrittura_Asincrona_e_PIO_Originali.md). Obiettivo attivo: creare, scrivere, chiudere e riaprire un file tramite il filesystem Nikon originale, fino al controller simulato. Questo checkpoint supera il precedente confine ai motori write; la prova completa di un file FAT resta da costruire.

**Risultato verificato:** 24 scenari CPU, tutti ritornati. Tredici eseguono anche i motori read originali e confrontano 11.264 byte con la sorgente. Quindici catture conservano 12.800 byte emessi dagli store PIO originali, comprendendo ritentativi e copie seguite da errore. Il modello della scheda è una finestra di byte in memoria, non ancora un filesystem FAT. Nessun dispositivo fisico, nuovo BIN firmware o modifica al C del dumper. **NON_INSTALLARE.**

## Riproduzione e provenienza

```sh
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_write_partition.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_write_async.py
```

- [Runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_write_partition.py) e [probe](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDWritePartition.java).
- [24 casi e hash](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Write_Partition/20261023T182409Z/verified_evidence.json), [traccia](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Write_Partition/20261023T182409Z/trace.txt), [finestre GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Write_Partition/20261023T182409Z/gnu_verified.txt).
- [Regressione 36 casi](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Write_Async/20261023T182159Z/verified_evidence.json): 24 asincroni e 12 PIO, 48 timeout/progress e 4.800 tick. Eseguita nuovamente; i probe precedenti sono invariati.

Il nuovo runner verifica i 16 hash canonici, 21 finestre GNU e 17 istruzioni chiave; conserva comando, log e snapshot dei sette sorgenti. Le ultime sei finestre descrivono il collegamento superiore **statico** da affrontare, non funzioni eseguite nei 24 casi. Tutte le operazioni CPU fermano anche quando `step()` riesce ma il rilevatore segnala un accesso sconosciuto.

Campione V1.1: 29.602.084 byte, SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`. Questa identità non stabilisce compatibilità con la V1.0 della macchina nei log.

## Catena ora eseguita nella stessa prova

```text
2A0C60(context,10,LBA,count,buffer)
  → seek226204 / controllo7 e offset partizione2048
  → 1FA090 → callback PMSD2A0890
  → 1FA090 → callback DEVSD2A0534
  → 1684B4 → 168410 (tentativi)
  → 25BB5C single / 25B9C0 multi
  → 2E514C preparazione / 2E509C descrittore
  → 2E52F4 / 25A278 comando / 25A5F8 polling / 25A3E0 risposta
  → 2E5648 / 3042A8
      modo0: 304004 → 303F24 se necessario → 25A430 store PIO
      modo1, allineato: 3040DC → oggetto write / callback / eventi / release
  → completamento25A658 / eventuali comandi0C e0D
  → DEVSD conteggio / PMSD copia errore / post semaforo PM
```

Gli handle PMSD/DEVSD, geometria, partizione1 e selezione volume sono predisposti nel laboratorio. Il semaforo PM è originale: il token è0 all'ingresso del motore e torna1 all'uscita, con una acquisizione e un rilascio anche sui tre tentativi falliti. L'ingresso è il trasferimento settori `2A0C60`, non il wrapper di scrittura di un file; non viene rivendicato un lock filesystem superiore acquisito dal test.

Il wrapper DEVSD seleziona effettivamente modo0 nei casi provati: viene eseguita la copia PIO, con conteggio1/2 e LBA logico7 tradotto in2055. Il ramo asincrono è verificato entrando nei motori con modo1. Un buffer non allineato a4 fa ricadere quest'ultimo in PIO. Non si trasferisce l'etichetta «asincrono» a tutte le scritture del filesystem.

Il multi esegue anche `1C4C2C`, `158F94` e `158FA4`: lettura e ripristino della priorità sul profilo predisposto con task corrente e ready-record di priorità0. Non viene sostituito il risultato di questi helper; non è una prova dello scheduler generale.

## Byte scritti e rilettura

Ogni caso parte con la finestra della scheda a `CC`. Solo dopo l'esecuzione di `sth.di` a `25A43A` il laboratorio legge la halfword dalla porta e ne inoltra i due byte al modello della scheda e alla cattura. Non copia direttamente il buffer sorgente nella scheda e non scrive il risultato atteso nel buffer di rilettura.

Il pattern noto differenzia i settori consecutivi: `(k*37+11) XOR ((k>>8)*97)`, troncato a8 bit. Il runner verifica esplicitamente che i primi due settori siano differenti. Dopo la scrittura, `B15B4/B16D0` eseguono comandi e copie PIO originali; i loro load dalla porta ricevono i byte conservati dal modello. Il confronto copre tutto il contenuto e le guardie del buffer di destinazione. Anche sorgente e guardie restano invariati.

Sono 13 riletture: single/multi sui due selettori, byte-addressing, due rami stop-special, pre-completion, errore finale single, fallback non allineato, single/multi PMSD e flag-volume2. Comprendono due casi in cui **i byte sono presenti nel modello ma il write restituisce errore**. Il primo aggiornamento interlocutorio indicava12; il conteggio finale verificato è13.

Il modello serve la stessa finestra scelta dal caso; non implementa una scheda completa, la macchina a stati SD o una FAT. La verifica dell'argomento comando distingue indirizzamento a blocchi e a byte, ma non dimostra ogni LBA o geometria. Nessuna conclusione di persistenza fisica, cache elettrica o resistenza allo spegnimento.

## Errori e conteggi effettivamente osservati

| Scenario | Byte PIO catturati | Esito software |
|---|---:|---|
| PMSD single / multi | 512 / 1.024 | stato0, raw/PM count1/2, rilettura identica |
| PIO bit6 dopo128 store, stato bit2 | 3×256 | `E01200`, raw/PM count0 |
| Stesso limite, stato bit3 | 3×256 | `E01310`, raw/PM count0 |
| Errore polling comando dati | 0 | `E00100`, tre tentativi, raw/PM count0 |
| Single: errore completamento dopo dati | 512 | `E00103`, rilettura del modello ancora identica |
| Multi: stop `E00200` al confine esatto | 1.024 | accettato; anche `0D/E00200` finale convertito in0 |
| Multi: stesso stop lontano dal confine | 1.024 | `E00200` propagato |
| Volume flag+49 esattamente1 | 0 | stato0, raw/PM count2, nessun motore |
| Volume flag+49 uguale2 | 1.024 | percorso normale e rilettura identica |
| Count0 | 0 | seek eseguito, callback dati saltate |

Nei due errori PIO il driver **non riporta 256 byte parziali**: emette quel prefisso a ogni tentativo, poi espone conteggio0. La finestra sintetica conserva un solo prefisso di256 byte perché i tre tentativi ripartono dallo stesso punto; la cattura contiene tutte le768 emissioni. Il test non attribuisce tale quantità a una SD fisica. Un adapter non può tradurre questo conteggio0 in «nessuna modifica al supporto» né in una quantità fisica certa.

Il bit+49 conserva il falso successo già osservato: producer e condizioni runtime restano aperti. Il test inietta0/1/2 e non corregge arbitrariamente il firmware.

Il campo contesto SD+D4 uguale1 fa eseguire tre chiamate originali di completamento nel multi: preparazione, prima dello stop e dopo lo stop. Il caso dedicato ne asserisce il numero. I rifiuti range producono `E00303` single / `E00302` multi, nessun dato e comando di uscita0D.

## Ramo asincrono collegato ai motori

I quattro casi modo1 eseguono il corpo del motore fino al servizio già verificato: completion→0; errore bit2→`E01211`; bit3→`E01321`; nove progress invariati→`E01211` dopo900 tick del profilo. Start/release/try/post sono uno per caso; handle e id sono consumati, token torna1, maschere e stack sono ripristinati.

Sono originali registrazione status, router040E, walker, dispatcher dati2689FC, callback, SET/WAIT/query/CLEAR, scadenze, progress e post. Il cambio di frame CPU a `B2D50` resta astratto, con salvataggio dei registri e rientro soltanto dopo il risveglio originale. Non è consegna di un interrupt fisico.

Non viene inventato un trasferimento DMA: nessuno store PIO avviene e la scheda sintetica resta aCC **anche quando il motore ritorna0**. Questi casi provano controllo e lifetime software, non scrittura dei dati. Cache `17FAA4`, delay `2E500C`, recovery `25B63C` e query write `25BF3C` sono ancora fixture; i prodotti DSP sono modellati. In particolare i risultati di recovery/query non vengono attribuiti ai corpi originali.

## Primo componente superiore da eseguire

Le finestre GNU asseriscono questo percorso statico, non ancora integrato nel nuovo test:

```text
12DE3C(file,buffer,bytes,selector,&written)
  → 1FA090 → 1F4958
  → backend !=7: 21A4B8
     → 2A1344: risolve contesto e oggetto, prende semaforoFS
     → 1F25D8 / allocazione2AB95C / aggiornamento directory1F337C
     → 2A0D70 → 2A0C14 → PMSD/DEVSD → motori
```

Il **primo confine mancante per la scrittura di file è `1F4958 → 21A4B8`**, con gestione della posizione, allocazione/avanzamento dei cluster e metadati. `2A0D70` è il raccordo cluster→settori da aggiungere alla catena ora eseguita. Primo scenario utile: file aperto `r+` con catena FAT nota, scrittura e rilettura tramite il medesimo albero sintetico; poi creazione originale e close con metadati sporchi. Non sostituire queste operazioni modificando direttamente la directory attesa nel test.

Per il file nuovo rimane la continuazione di `2ABCD4` dopo la guardia `2ABD36`: il controllo duplicato precedente è eseguito, ma la creazione FAT completa no. Il [binding ABI](S33_Dumper_RAM_Binding_SD_ABI.md) mantiene `n` new-only solo nelle condizioni dimostrate del backend diverso7 e campo760=0 sotto il semaforo originale. Nel backend7 `n/w` condividono il ramo; `x` genera nomiTMP e non equivale a C11. Restano da eseguire collisione sul medesimo filesystem, allocazione, sync e close, senza una finestra check/create priva di lock.

## Copertura dell'obiettivo e stime separate

Le percentuali seguenti misurano **tappe offline a peso uguale**, con una tappa conteggiata soltanto quando provata nel profilo dichiarato. Non sono percentuali di firmware funzionante, di sicurezza o di probabilità di successo hardware; non rendono completo il test FAT.

| Area | Stima | Criterio |
|---|---:|---|
| Filesystem | 25% (2/8) | lookup/apertura di file esistente e lifetime/lock già eseguiti; da completare creazione, collisione integrata, write-file, sync/close sporco, riapertura/contenuto, errori completi |
| Write SD | 75% (6/8) | PMSD/DEVSD, retry/count, comandi/gate, PIO/rilettura, lifecycle asincrono, risorse/release provati; mancano copia DMA/cache e recovery/query originali |
| Interrupt/eventi | 63% (5/8) | register, router/walker, dispatcher callback, eventi/deadline, risorse provati; mancano frame CPU, consegna vettore hardware, interleaving/concorrenza |
| Adapter AkeruOS | 20% (1/5) | contratto generico e motore host già verificati; open esclusivo, write/count, close/ownership e collegamento RTOS concreto ancora da validare |
| Integrazione hardware | 0% (0/5) | nessuna prova di immagine compatibile, residenza/stack, mappa fisica completa, recupero o acquisizione reale |

Audit dei requisiti dell'allegato:

| Requisito | Stato ed evidenza |
|---|---|
| Preparare SD FAT sintetica per la nuova scrittura | Parziale: albero FAT read precedente; qui finestra dati senza FAT |
| Creare file nuovo con contenuto noto | Mancante: creazione originale dopo la guardia non eseguita |
| Scrivere tramite filesystem e controller | Parziale: trasferimento settori→controller ora eseguito; write-file superiore statico |
| Callback/eventi originali | Provati sul profilo CABI dichiarato, copia DMA assente |
| Close corretto del file scritto | Mancante: close read già provato, close con metadati della nuova scrittura no |
| Riaprire e verificare byte/dimensione/integrità | Parziale: rilettura settori identica, nessuna riapertura del nuovo file |
| Collisione senza overwrite | Parziale: guardia originale provata con lookup fixture; manca collisione sul medesimo FAT integrato |
| Errori/timeout/parziali | Provati a livello motori/PMSD, non ancora su tutto il ciclo del file |
| Adapter compatibile con ram_dump.h | Contratto disponibile; adapter Nikon concreto non aggiunto prima della verifica richiesta |
| Backend7 e modi w/w+/n/x | Tabelle/rami statici e guardia parziali; semantica completa di backend7 da eseguire |
| Nessun hardware, firmware installabile, push/deploy | Rispettato; originali e sorgenti GNU/C preservati |

L'obiettivo resta attivo. La rilettura dei settori è un nuovo collegamento verificato; non sostituisce la richiesta di creare e riaprire un file FAT. Restano inoltre mappa RAM completa, memoria privata, task/hook e immagine compatibile prima del primo dump reale.

## Correzioni del laboratorio

Conservati i tentativi precedenti: il primo aveva un'eccezione Java non gestita nello step del singolo store; il secondo leggeva una word nel probe per ispezionare un flag byte del contesto SD, toccando tre byte non predisposti. Corretto il probe a una lettura byte. Non erano errori Nikon. Rafforzati poi conteggi lifecycle, ripristino gate/maschera, caso+D4 e pattern differente fra settori. Nessuna modifica al firmware o al decoder per far passare la prova.

## Continuazione — fileFAT e correzione write,23ottobre2026

[13nuovi scenari](S33_Dumper_RAM_SD_File_FAT_Creazione_Scrittura_Close_e_Riapertura.md) eseguono creazione n/collisione,allocazioneFAT,12DE3C→PMSD/DEVSD/controller,close e riapertura con contesto nuovo.4immagini positive superanofsck;il negativo frammentatoFF7 viene respinto. Stato0puòaccompagnarecount0 o1024/2048 ecountpienopuònasconderefileError1A00006. HardwareDMA esplicitamente modellata,81timeout/8100tick,regressione24PASS. Ilprimo confine superiore èora1F21F8/12DBFC/12D604 conregistro/slot/ownership,poibackend7/modi eadapter. C eGNU invariati,mappafisica/task/hookancoranecessari,obiettivoattivo,NON_INSTALLARE.
