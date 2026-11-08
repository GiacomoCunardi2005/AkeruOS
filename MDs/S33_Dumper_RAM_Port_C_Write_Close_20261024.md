# Dumper RAM — port C di write/close Nikon V1.1

24 ottobre 2026. **Realizzato e verificato il componente C che collega scrittura
e chiusura del motore di dump alle funzioni originali Nikon. L'aggiornamento
completo per tutta la RAM non è ancora prodotto. NON_INSTALLARE.**

## Implementazione e prove

`AkeruOS/nikon_v11_sd_io.c/.h` adotta un wrapper superiore già aperto e posseduto
dal chiamante. Il chiamante elimina la propria vecchia copia dopo il trasferimento.
Non apre file e non presume che il backend o la creazione esclusiva siano sicuri.

- Write originale `0x12DE3C`, selettore0: successo soltanto con stato0,
  conteggio esattamente richiesto ed errore wrapper+0xC uguale0. Un risultato
  corto è errore definitivo; il motore generico non può ritentare silenziosamente.
- Close originale `0x12D604(&native)`: il token applicativo viene consumato una
  sola volta. La cella nativa resta nel contesto del port e distingue wrapper
  consumato, trattenuto o sostituito. Nessun retry automatico e nessun free aggiunto.
- Write/close falliti rendono il contesto non riutilizzabile. Se il puntatore
  nativo resta vivo, anche il contesto deve restare vivo. Il futuro task deve
  garantire questa durata, compresa l'uscita in errore.
- Cella nativa nulla non certifica rilascio dell'oggetto FAT né persistenza SD.
  Non viene dereferenziato il wrapper dopo il close.

Compilazione ARC700: **284 byte di codice, data/BSS0**, nessuna rilocazione SDA;
le sole dipendenze sono le due funzioni Nikon, risolte agli indirizzi V1.1 nel
link di laboratorio. Gli indirizzi del codice C nel laboratorio non sono una
proposta di collocazione sulla fotocamera.

| Verifica | Risultato e confine |
|---|---|
| Host C, ASan/UBSan | 20 casi del port, incluse uscite del motore su errore; API Nikon simulate |
| Motore e parser esistenti | 28 casi host, streaming128MiB sintetici,20 dump malformati respinti |
| Dump del motore attraverso il nuovo port | 64 byte sintetici, CRC/contenuto/formato riletti dal parser |
| Port compilato ARC + firmware originale | 7 scenari P-code; write/close Nikon eseguono i corpi originali |

Riproduzione:

```bash
make -C AkeruOS ram-dump-verify
make -C AkeruOS ram-dump-sd-io-verify
make -C AkeruOS build/nikon_v11_sd_io.o
```

Fonti: `AkeruOS/tests/nikon_v11_sd_io_test.c`,
`Python_Trace_Scripts/s33_verify_ram_dumper.py`,
`Python_Trace_Scripts/s33_verify_ram_dump_sd_io_port.py`,
`S33-sections/analysis_ghidra/scripts/ProbeDumpSDIOPort.java`.
Evidenze: `Risultati/Runtime_Kernel/RAM_Dumper/latest.json` e
`Risultati/Runtime_Kernel/RAM_Dumper_SD_IO_Port/latest.json`, con snapshot,
hash dei sorgenti/payload, log compilazione, listati e tracce.

## Sette scenari col firmware originale

| Scenario | Risultato osservato dal port |
|---|---|
| Normale1024byte | write1024, close0; riapertura e rilettura originali coincidono coi dati scritti |
| Scrittura corta2048byte | API superiore stato0/count1024; port restituisce errore, nessuna seconda write |
| Errore comando | API superiore stato0/count0; port restituisce errore |
| Cache metadati assente | API superiore stato0/count1024/fileError01A00006; port restituisce errore |
| Errore nel close | close00E00100, wrapper consumato; port conserva errore e non ritenta |
| Ready0 prima del close | close01A0000C, wrapper consumato ma oggetto FAT ancora vivo:1/0alloc/free |
| Volume assente prima del close | closeFFFFFFFF, wrapper e oggetto FAT trattenuti; puntatore conservato dal port |

Allocazioni scratch, registro/semafori e nesting critico sono controllati.
Il laboratorio riusa il modello FAT12/SD/PIO degli esperimenti lifecycle:
contesti montati/kernel preparati, settori SD e MMIO sintetici, DMA/DSP dichiarati.
I16byte oltre il codice estratto sono padding di lettura del decoder del laboratorio,
non codice aggiunto al firmware. Nessuna API write/close superiore è sostituita
in questi sette casi. **Non è una verifica elettrica, di persistenza o di SD fisica.**

I tentativi precedenti del nuovo probe restano nei risultati: correzioni di
memoria inizializzata per il codice, lettura anticipata del decoder e cella
del chiamante da scartare dopo adozione. Solo il manifest PASS finale è pubblicato
in `latest.json`. Non sono stati cambiati i byte Nikon per superare i test.

## Lavoro necessario prima dell'aggiornamento completo

1. Completare la sessione SD: identità verificata di `B:AKERUDMP.ON`, guardia
   backend/contesto stabile prima della creazione, modo esclusivo realmente
   compatibile e durata dei file trattenuti. `n` sul backend7 segue il ramo `w`:
   non usarlo come creazione esclusiva universale.
2. Fornire una mappa fisica completa verificata, con alias/buchi/MMIO chiariti.
   I256MiB configurati e i128MiB sintetici non la sostituiscono. Prossimo punto
   statico già individuato: corpo DDR BootNAND `0x0F800A54` e configurazione BFN.
3. Chiudere collocazione/durata del modulo, stack e integrazione task/launcher.
   I componenti RTOS e la guardia CRC esistono, ma non costituiscono un update integrato.
4. Solo dopo, assemblare e verificare il pacchetto update; l'esecuzione hardware
   resta un ambito distinto. Nessun BIN pronto viene dichiarato da questo port.

Il tentativo separato backend7 `20261024T112221Z` si arresta su una lettura di
stato non inizializzato nel laboratorio (`0x4B92F5`, PC`0x1F650C`), prima di leggere
settori exFAT. Non è un PASS e non prova il supporto backend7 attivo.

Nessun accesso alla fotocamera, nessuna scrittura SD/NAND, nessuna installazione.
Originali, calibrazioni e alberi GNU preservati. Il goal dell'aggiornamento
per il dump completo della RAM rimane attivo.
