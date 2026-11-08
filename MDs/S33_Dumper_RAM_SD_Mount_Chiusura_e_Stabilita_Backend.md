# Dumper RAM: montaggio, chiusura e stabilità del backend SD

23 ottobre 2026, R0/R1/R4. Segue [semaforo e inizializzazione](S33_Dumper_RAM_SD_Semaforo_Campo_Temporaneo_e_Inizializzazione.md). **16 nuovi casi CPU originali:13 del montaggio e3 della callback di chiusura nel ramo volume.** Confermano che la selezione del backend avviene sotto il semaforo del contesto, ma non ogni modifica del suo puntatore al volume. Non si può ancora associare un controllo preliminare separato alla garanzia di creazione esclusiva.

## Prove riproducibili

- [Runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_mount.py), [probe](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDMount.java), helper preesistenti ProbeDumpSDMutex/ProbeStatusRead.
- [Manifest](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Mount/20261022T233548Z/verified_evidence.json), [16 esiti](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Mount/20261022T233548Z/trace.txt), [16 finestre GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Mount/20261022T233548Z/gnu_verified.txt), [log](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Mount/20261022T233548Z/headless.log).

```bash
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_mount.py
```

Vengono eseguiti1F3EF0,1F35D4,1F3608,23ECA4/23EE48,13A954 e millicode originali. I tre casi di chiusura entrano dalla callback1F48A4, seguono1F46C4 con file+4=0, resolver2A12D8 e gate2A45E4 originali. I pool1F3900/1F3904 contengono rispettivamente1F43AC e1F48A4, gli ingressi open/close registrati dal costruttore già verificato.

**Fixture dichiarate:** resolver del nome1F19E0, ioctl1F2348, query geometria2A4544, lettura settori2A0C60, allocazioni/rilasci, registrar2A4528, setup2A45D4, predicato1F64E8 e due getter del backend speciale. Il parser ordinario1F37AC e le notifiche sono simulati. Il parser ordinario pone esplicitamente ready=1 nel modello: non è prova di FAT valida. Nei casi di close i buffer del contesto sono nulli e ioctl3 è simulato; backend12 non viene percorso.

Firmware/dump canonici immutati; payload verificati tramite hash, GNU solo letto/eseguito, sorgenti e snapshot conservati. I tentativi preliminari restano nel risultato storico: il primo fallì per un punto di osservazione posto nel delay slot della wait, corretto al reale indirizzo di ritorno1F3F68. Non era un errore firmware.

## Montaggio: pubblicazione anticipata e lock

1F43AC, quando context+424 è nullo, raggiunge1F3EF0. Questa routine risolve il nome del dispositivo, legge **context+420 (105×4)** come handle preesistente e pubblica **il file passato in context+424 (106×4)** a1F3F2C, prima della wait. Questi due campi non sono intercambiabili: il secondo è l'oggetto volume da cui gli helper successivi risolvono nuovamente il contesto.

Dopo ioctl0x2017 e query2A4544, **1F3F62 esegue wait(context+388)**. Da quel punto risultano sotto il semaforo: buffer temporaneo, lettura di laboratorio, ioctlA0A1, selezione1F35D4 e inizializzazione1F3608 per backend7. Il post normale è1F410A; gli errori di allocazione provati lo raggiungono direttamente o tramite1F3FE0.

| Caso | Wait/post | Stato finale osservato |
|---|---|---|
|record tipo7, soglia0x04000000, predicato speciale1|1/1|backend7, ritorno0|
|tipo7 immediatamente sotto soglia|1/1|backend1 iniziale conservato; tre buffer e parser ordinario fixture|
|tipo0 alla soglia|1/1|backend1 conservato; ramo ordinario|
|tipo7 alla soglia, predicato speciale0|1/1|**backend resta7**, ready0, ritorno01A0000C|
|resolver rifiuta con01A00002|0/0|nessuna pubblicazione a+424, semaforo1|
|ioctl2017 rifiuta con01A00020|0/0|+424 già pubblicato, semaforo1|
|query2A4544 rifiuta|0/0|+424 già pubblicato, semaforo1|
|**ioctlA0A1 rifiuta dopo la wait**|**1/0**|ritorno errore, **semaforo0**, +424 pubblicato|
|prima/seconda/terza allocazione ordinaria nulla|1/1 ciascuno|01A00006, semaforo1|
|parser ordinario fixture rifiuta|1/1|01A00002, semaforo1|
|semaforo già0|1/0|waiter accodato, stop prima dello scheduler; nessuna query o selezione backend|

Il ramo dell'ioctlA0A1 fallito è byte-provato: **1F3F8E→1F4110**, saltando1F410A. Il caso CPU lascia effettivamente il conteggio0. Questa è una conclusione locale con ioctl/notifiche simulati, non una diagnosi di deadlock della fotocamera: gli effetti reali del servizio e il cleanup dei chiamanti restano da seguire. Analogamente, la pubblicazione anticipata mostra perché né il solo errore di mount né il solo backend possono essere usati come stato completo del volume.

Il corpo speciale1F3608 è eseguito, incluse40 voci da1168byte inizializzate in RAM di laboratorio. Il predicato e i dati fisici sono fixture: il test non monta una scheda né misura una capacità.

## Callback close: due sequenze distinte

1F48A4 legge file+4. Con0 chiama1F46C4, il ramo volume oggetto dei tre casi. Prima risolve il contesto con2A12D8, che prende il semaforo; **1F46D6 lo rilascia subito tramite2A1398**. Solo dopo controlla il backend.

### Backend7

Il ramo chiama1F661C, poi **1F46EE azzera context+424 con conteggio semaforo già1**. In seguito1F35D4(context,0) conserva backend7, come previsto dalla prova precedente. Nel caso eseguito ready+0x40 resta1. Una wait/post bilanciata non dimostra quindi che quel puntatore sia immutabile durante una successiva apertura.

Questo non prova una race fisica: altri livelli possono serializzare i chiamanti. Prova però che non è corretto attribuire ogni modifica al solo semaforo context+388.

### Backend1

Dopo il primo post esegue ioctl3 senza quel semaforo, quindi **riacquisisce** tramite2A12D8. Chiama2A45E4(context+100): il corpo originale legge la halfword all'offset8 dell'argomento, cioè **context+108 (0x6C)**. Ritorna1 se zero,0 se nonzero.

- halfword0: con buffer nulli completa la pulizia e **1F488A azzera+424 sotto la seconda acquisizione**, poi post e ritorno0;
- halfword1: evita la pulizia, conserva+424, esegue il secondo post e ritorna **01A00010**, costante verificata a1F4C48.

In entrambi i casi backend1 e ready1 restano invariati. Non attribuiamo ancora alla halfword il significato di contatore di file o riferimenti: manca il censimento dei suoi scrittori. Il solo nome «close» non implica azzeramento di ready o backend.

## Il lock del registro dispositivi non copre l'open callback

La nuova finestra statica1F21F8 chiarisce un possibile equivoco: l'open generico prende il semaforo **kernel+0x334** per cercare il dispositivo nel registro, ma lo rilascia a1F225C. Solo dopo alloca il file e invoca la callback **1F2292**. Non è quindi un lock esterno che questo percorso conserva durante il montaggio o l'open specifico. Il precedente test del close generico1F22C0 resta valido nella propria diversa portata; non trasferire automaticamente il suo ordine all'open. Questa conclusione è statica, non un nuovo caso CPU dell'open generico.

## Conseguenze e prossimo passo

Il risultato restringe la sincronizzazione utile ma lascia aperto il binding: backend7 non offre ancora la guardia new-only del percorso n ordinario; il puntatore+424 e il backend non costituiscono da soli una dichiarazione di volume pronto. Non è lecito pre-acquisire il semaforo del contesto per chiamare un open che lo prende di nuovo.

Prossimo: seguire gli scrittori della halfword **context+108**, i chiamanti della callback close e gli altri percorsi degli helper backend (1F46F4 passa flag0,225AB2 passa1;225F66 chiama1F3608), per stabilire se mantenere un handle ordinario impedisce la chiusura del volume e quale livello serializza gli accessi. Poi raccordare preflight e creazione esclusiva nella stessa operazione. Rimangono mappa RAM fisica completa, lifetime launcher/stack e cleanup affidabile.

Nessuna modifica al prototipo C o ai BIN; nessuna fotocamera, SD fisica o nuova procedura di installazione. **NON_INSTALLARE**, circa10% funzionale AkeruOS invariato.

## Continuazione — oggetti file e guardia, 23 ottobre 2026

[Sei sequenze successive](S33_Dumper_RAM_SD_Lista_File_e_Guardia_Chiusura_Volume.md) attribuiscono context+108 al conteggio della lista file a+100 nel backend1. Open n e close ordinario originali incrementano/decrementano; volume close e ingresso225A60 rifiutano con oggetti vivi. Due ordini di rilascio e fallimenti pool/collisione verificati. Non è ancora prova di r/open-existing, di altri backend o di tutti i mutatori. Prossimo: handle di appoggio in sola lettura e sincronizzazione superiore. NON_INSTALLARE.

## Continuazione — FAT multisettore e r/driver/close

[S33_Dumper_RAM_SD_Catena_FAT_Multisettore_e_Identita_File.md](S33_Dumper_RAM_SD_Catena_FAT_Multisettore_e_Identita_File.md):34casi avanzamento/decoder,13catena multisettore e7r/driver/close. Il precedente limite del lettore sostituito nella sequenza r è superato per l’albero con un settore per directory; la FAT multisettore è provata separatamente. Nuovi casi errore FAT perso, voce0 che riporta alla root, ciclo limitato e root esaurita. Close libera tre buffer ma non ne azzera le celle. Driver/DSP/pool dichiarati; nessun hardware o BIN.
