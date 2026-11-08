# Primo registro hardware: bit 7 e selezione dei due percorsi

20 ottobre 2026, R3/R4. **Entrambi i valori del bit 7 fanno proseguire il firmware fino alla lettura di un secondo registro.** La scelta è identica nei due campioni V1.1. Le risposte sono input costanti del laboratorio: non è stata ricostruita una periferica completa né dimostrato l'avvio della Nikon.

## Istruzioni e dati riancorati

MainCode `0x12CA28` e TBIB `0x01009E54` confrontano l'argomento r0 con zero. Se è diverso da zero selezionano direttamente il record 12 (`0x0C`). Se è zero leggono una halfword da `0x0FE800F8` e ne controllano soltanto il bit 7:

| Condizione | Record scelto | Campo indirizzo del record |
|---|---:|---|
| r0 diverso da zero | 12 | `0x0FE80050` |
| r0=0, bit 7 a zero | 13 (`0x0D`) | `0x0FE80064` |
| r0=0, bit 7 a uno | 12 | `0x0FE80050` |

Il literal MainCode `0x12CA38` e quello TBIB `0x01009E64` sono entrambi esattamente `0x0FE800F8`. Il servizio successivo è rispettivamente `0x17A000` / `0x010095DC`. I record sono di 16 byte: tabella MainCode `0x399568`, tabella TBIB `0x01042D6C`. I due record selezionati sono identici byte per byte nelle tabelle dei due componenti. Il campo word a +12 contiene rispettivamente 200.000.000 e 250.000.000: sono dati originali, non una frequenza misurata della CPU o della periferica. Il significato fisico completo del registro non è ancora attribuito.

Le **11 finestre GNU** separano codice e pool: 7 MainCode e 4 TBIB. I byte dei pool vengono letti come dati, senza usare le false istruzioni prodotte da una scansione lineare. Controllati i 16 payload tramite helper esistente, hash dei due firmware, componente TBIB uguale, checksum TBIB e roundtrip ELF del corpo.

## Prove eseguite

```bash
python3 S33-sections/safety_audit_codex/verify_hardware_bit.py
```

[Runner](../S33-sections/safety_audit_codex/verify_hardware_bit.py), [probe](../S33-sections/analysis_ghidra/scripts/ProbeHardwareBit.java), [helper di avvio riusato](../S33-sections/analysis_ghidra/scripts/ProbeStatusRead.java), [manifest](../S33-sections/safety_audit_codex/hardware_bit_verified.json), [GNU](../S33-sections/safety_audit_codex/evidence/hardware_bit_gnu.txt), [log](../S33-sections/safety_audit_codex/evidence/hardware_bit_run.log).

**36 casi isolati:** per ciascun campione e per ciascun selettore MainCode/TBIB, argomento 0/1 e halfword 0/127/128/65535; più un caso argomento 1 senza inizializzare affatto il registro. Quest'ultimo arriva al servizio senza fault, confermando nel tratto eseguito il bypass della lettura. I valori 127 e 65535 controllano che la scelta dipenda dal bit 7, non dall'intera parola o soltanto dal fatto che sia zero. Ogni caso esegue le vere istruzioni fino al servizio e controlla PC, record selezionato, budget e assenza di fault/errore. Non viene eseguita la periferica fisica.

**16 tentativi limitati di avvio:** CMP3/CMP1 × TBIB/MainCode × STATUS32 iniziale 0/6 × halfword simulata 0/128 a `0x0FE800F8`. Gli altri bit di quella halfword partono esplicitamente da zero. Il valore viene fornito prima dell'esecuzione come memoria costante del modello, senza attribuirgli proprietà temporali, effetti di lettura o comportamento elettrico. Gli altri registri hardware restano sconosciuti e arrestano la prova. Non è un backend MMIO generale e non è un dump della Nikon.

## Nuovo confine, verificato per ogni profilo

| Bit 7 simulato | TBIB: primo arresto / passi riusciti | MainCode: primo arresto / passi riusciti | Registro successivo |
|---|---|---|---|
| 0 | `0x010095FA` / 10.714 | `0x17A01E` / 444.299 | `0x0FE80064`, halfword |
| 1 | `0x010095FA` / 10.715 | `0x17A01E` / 444.300 | `0x0FE80050`, halfword |

Gli assert verificano esattamente PC, numero di passi, indirizzo e dimensione del fault, STATUS32 già superato e assenza di errore Ghidra. Nei casi MainCode è ricontrollato l'azzeramento di 1.758.364 byte da A5 a zero dopo 439.690 passi. I profili STATUS32 0/6 raggiungono gli stessi confini; non si deduce equivalenza globale dei due stati.

Tracce registrate e riepiloghi CMP3/CMP1 sono identici. Il confronto HiddenMenu non viene raggiunto. Come nel laboratorio precedente, le tracce non sono una registrazione di tutta la RAM/CPU; i tentativi TBIB e MainCode sono separati, con dati precaricati, base vettori 0 e contesto core ipotetici. Non è una sequenza ROM→TBIB→MainCode completa.

I file e i risultati del [checkpoint LP](S33_Correzione_Ciclo_LP_e_Avvio.md) sono conservati immutati e verificati per hash prima/dopo; quei test non sono stati rieseguiti qui. Nessun nuovo decoder introdotto: si usa `ARCompact:LE:32:loopfix` già convalidato nel proprio perimetro.

## Prossimo punto e limiti della sicurezza

Seguire i record 12/13, la maschera del registro successivo e il calcolo/consumatore del risultato; poi confrontare input di laboratorio espliciti per quel tratto. Non dedurre valori hardware da una frequenza nominale nella tabella e non azzerare automaticamente tutti i registri. Restano writer indiretti dello stato HiddenMenu, concorrenza del 3 temporaneo, CPU/DSP e interrupt completi, avvio/UI completi, updater residente V1.0 e recupero dopo mancato avvio o aggiornamento interrotto.

**NO-GO flash e circa 10% funzionale invariati.** Nessun firmware modificato, nessun accesso USB/PTP o scrittura sulla fotocamera. Tutti i rapporti Markdown restano nella radice.

## Continuazione: origine di r0 verificata — 20 ottobre 2026

[Nuovo audit](S33_Copertura_Esecuzione_e_Audit_Modello.md): nelle due chiamate Main osservate,29F65C/29F678→231420, l’istruzione231424 imposta r0=0 nel delay slot del salto al selettore12CA28. Nel TBIB rieseguito,0101F558→010139D0,010139D4 imposta0 prima di01009E54. Non deriva dallo zerohost iniziale; non prova tutti i chiamanti del ramo r0nonzero. Tracce e finestreGNU nel nuovo manifest; nessun nuovo valore fisico FE800F8 attribuito.
