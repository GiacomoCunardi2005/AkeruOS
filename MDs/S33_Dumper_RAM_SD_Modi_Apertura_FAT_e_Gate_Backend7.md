# Dumper SD: modi FAT originali e gate del backend7

23 ottobre 2026 — R0/R1/R4. **20 casi CPU ritornati**,20immagini verificate da parser host e `fsck.fat -n`,9finestre GNU e11istruzioni asserite. Nessun hardware, **NON_INSTALLARE**.

- [Evidenza](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Modes/20261023T192829Z/verified_evidence.json), [trace](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Modes/20261023T192829Z/trace.txt), [GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Modes/20261023T192829Z/gnu_verified.txt).
- [Probe](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDFileModes.java), [runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_file_modes.py);10sorgenti con snapshot/hash.
- Usa registro e setup della [prova lifecycle](S33_Dumper_RAM_SD_Registro_Apertura_Close_e_Ownership_Integrati.md), ma gli scenari dei modi sono separati dai17casi di scrittura/errori. Non sommare i due gruppi come una sola sessione.

```bash
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_file_modes.py
```

## Backend1: sedici prove di apertura e close

Gli input sono gli otto modi `w,w+,n,n+,r,r+,x,x+`, ciascuno con nome assente/presente; per x la presenza riguarda il primo nome TMP generato. Sono eseguiti `1F21F8 → 1F43AC`, parser originale, helper FAT,creazione/lookup/troncamento,`1F22C0 → 1F48A4/21AD30`. Ogni wrapper viene allocato/liberato1/1; ogni oggetto privato creato viene rilasciato una volta. Il close di questo gruppo è quello generico, coerente con l'apertura generica: non si crea uno slot volume sintetico per x.

| Modo | Nome assente | Nome presente | Halfword privato+44 |
|---|---|---|---:|
|w |crea vuoto |tronca2048→0,libera la catenaFAT |1 |
|w+ |crea vuoto |tronca2048→0,libera la catenaFAT |2 |
|n |crea vuoto |1A00011,nessuna modifica della scheda |1 sul successo |
|n+ |crea vuoto |1A00011,nessuna modifica della scheda |2 sul successo |
|r |1A00002,nessun file creato |apre2048byte,non modifica la scheda |0 |
|r+ |1A00002,nessun file creato |apre2048byte,non modifica la scheda |2 |
|x |creaTMP00000.@@@ nella directory |saltaTMP00000.@@@,creaTMP00001.@@@ |2 |
|x+ |stesso percorso x |stessa collisione x |2 |

Il nome TMP preesistente e il file TARGET.BIN sono preservati nei casi x. Il suo buffer di261byte è allocato dalla fixture heap, ma formato,contatore,retry,lookup e creazione sono originali. Il loop originale usa il budget300 già descritto nell'[ABI](S33_Dumper_RAM_Binding_SD_ABI.md); questi casi provano una collisione, non tutte300.

L'uguaglianza di x e x+ deriva anche dalle istruzioni: il parser1F4574 passa r1=0 a2A16F0 in entrambi; 2A1758 sceglie r21=2 e2A1822 lo scrive a oggetto+44. **x non è un’apertura esclusiva del path esatto fornito dal chiamante:** il path è una directory e il nome viene scelto da Nikon. Questa differenza impedisce di sostituire direttamente open_new del dumper con un fopen di modo x.

Il parser host rilegge voci directory,dimensioni,FAT12 e assenza di nuovi dati in tutti i settori102..109; verifica che w liberi i cluster2/3 e che n/r/x preservino le catene previste. Tutte20immagini superano `fsck.fat -n` con exit0 e hash invariato. Non viene dedotta la correttezza dalla sola risposta0 della CPU.

## Backend7: quattro rifiuti originali, portata limitata

I quattro input w,w+,n,n+ impostano il backend del contesto a7 e il gate **369400 a0**. Il parser originale:

- sceglie un record libero nella tabella40entry4B7F78 e lo marca occupato;
- passa sia n sia w al medesimo ramo1F44D8;
- invoca **1F8B44** per creazione e **1F9058** per lookup;
- entrambi incontrano il medesimo gate chiuso:1F8C34→369400 e1F904C→3693EC,+14=369400;
- produce1A00003, rilascia il record con1F4340 e il wrapper con il generico; nessun oggetto privato FAT e nessun settore modificato.

Queste funzioni **non sono stub di ritorno** nel banco: le istruzioni originali vengono eseguite fino al ramo di gate e al ritorno. Gli assert contano una create e una lookup per ciascuna prova,40entry libere alla fine e card invariata.

Il risultato dimostra il routing comune n/w e il rifiuto a volume non pronto. **Non dimostra troncamento, collisione o esclusività con backend7 attivo.** Per il prossimo passo occorre un contesto backend7 coerente inizializzato dal percorso originale, non il semplice cambio del gate a1: i percorsi aperti entrano in1F7058,1F69AC e1F70E4 con struttura/metadata propri. Non applicare il layout dell'oggetto FAT backend1 a queste strutture.

## Confini e implicazioni

La geometriaFAT e il contesto kernel/volume sono predisposti come nel gruppo lifecycle; mount completo assente. Heap/pool,clock,cache,delay,recovery/query e ioctl3 conservano le fixture dichiarate. Il backend7 non viene montato. Le registrazioni,il parser,i corpi di apertura/close e i percorsiFAT provati sono originali. Nessuna DMA,IRQ o persistenza fisica è certificata da queste prove di apertura.

Le stime restano quelle del checkpoint lifecycle: filesystem88%(7/8),write75%(6/8),eventi63%(5/8),adapter20%(1/5),hardware0%(0/5),tappe offline a peso uguale. I modi backend1 sono ora eseguiti, ma backend7 attivo ed errori completi restano aperti; non assegnare una tappa completa soltanto per il gate chiuso.

Il prossimo componente mancante dell'adapter è una gestione verificata di sessione/backend e degli esiti di close: non basta leggere cella0, perché il [caso ready0](S33_Dumper_RAM_SD_Registro_Apertura_Close_e_Ownership_Integrati.md) consuma il wrapper ma conserva l'oggetto privato. Conservare l'obiettivo intero42b56cc8; nessun nuovo firmware dumper prodotto e nessun indirizzo RAM fisico assegnato.
