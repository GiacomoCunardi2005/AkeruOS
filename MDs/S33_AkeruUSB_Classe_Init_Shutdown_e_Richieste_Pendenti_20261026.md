# AkeruUSB — inizializzazione, shutdown e richieste pendenti della classe

26 ottobre 2026. Ricerca offline verso il dump RAM. **NON_INSTALLARE**.

Eseguiti sulla CPU GNU ARC700 il costruttore originale della tabella di
classe `190408`, la registrazione `278578`, l'inizializzazione `191A04`,
la creazione richiesta `278790`, lo shutdown `1919D4` e il rilascio
richiesta `278808`. Dieci scenari coprono errori di allocazione, successo,
callback opzionale e deregistrazione con richiesta deliberatamente pendente.

**PASS, 3.097.387 istruzioni, uscita0, nessun fault.** Nel medesimo eseguibile
passa anche la regressione precedente dei36 scambi AkeruRAM e delle guardie
host ASan/UBSan e GNU. I nuovi scenari di classe sono separati dagli scambi
del protocollo: non dimostrano ancora un servizio AkeruRAM avviato dalla
classe originale né un trasferimento fisico.

## Evidenze e riproduzione

```sh
PYTHONDONTWRITEBYTECODE=1 make -C AkeruOS usb-ram-class-lifecycle-verify
```

- [Banco C](../AkeruOS/tests/usb_class_lifecycle_gnu_test.c).
- [Verificatore](../Python_Trace_Scripts/s33_verify_akeru_usb_class_lifecycle.py).
- [Esito CPU, contatori, hash e limiti](../Risultati/AkeruUSB_RAM_Debug/Class_Lifecycle/20261026T190434Z/verified_evidence.json).
- SHA256 esito: `3c4fcfa0fe085b35b5bdf81235c90d245bd357d4e2c83c53bf9b7245a8d32e31`.

Ricontrollati175 artefatti,36 input e contenuto decompresso della traccia
gzip. Sezioni originali estratte dall'ELF identiche ai byte del payload
V1.1. GNU e firmware originali restano invariati. Il verificatore riusa il
banco applicativo precedente rinominandone soltanto l'entrata nel file
fixture generato; non altera il sorgente precedente o le istruzioni Nikon.

## Oggetti creati dall'originale

`190408` costruisce la tabella RAM47DA9C, inclusi callback191A04/1919D4,
poi passa direttamente all'API278578. Questa invoca191A04 con pubblico+4.

L'inizializzazione:

1. Alloca32 byte e ne richiede l'azzeramento.
2. Memorizza il contesto nel globale368114 e in interfaccia+0x3C,
   cioè pubblico+0x40; contesto+4 riceve interfaccia.
3. Usa interfaccia+4, che punta all'oggetto endpoint0 pubblico+0x4C.
   La sua vtable originale conduce a278790, che alloca e azzera40 byte.
4. Salva la richiesta a contesto+8 e installa1910C0 a richiesta+16.
5. Se presente, invoca lo slot+8 della vtable dell'interfaccia con
   `(interfaccia,1)`; infine scrive il contesto nel primo campo endpoint0.

Il banco verifica le dimensioni, l'ordine e l'azzeramento usando storage
inizialmente A5. Allocatore e helper di azzeramento restano fixture.
Il corpo1910C0 è un ritorno immediato nell'analisi statica; non è stato
invocato nei nuovi scenari, perché non viene consegnato alcun completamento
alla richiesta della classe.

Lo slot opzionale dell'interfaccia a51A390 non viene scritto dal costruttore
qui eseguito: il test lo imposta esplicitamente a0 oppure a un callback
fixture. Con il callback presente, la chiamata avviene dopo la creazione
della richiesta; l'esito-23 del callback non impedisce il ritorno0
dell'inizializzazione. Questo non prova il valore dello slot su hardware.

## Matrice: cinque casi per maxpacket64/512

| Caso | Scenari | Risultato verificato |
|---|---:|---|
| Fallisce allocazione contesto32 | 2 | -16, nessuna richiesta creata; associazioni API azzerate |
| Fallisce allocazione richiesta40 | 2 | -16; shutdown interno libera il contesto e azzera i riferimenti principali; rollback API |
| Successo, slot opzionale0 | 2 | Una richiesta40 e un contesto32; deregistrazione libera prima richiesta, poi contesto |
| Successo, callback opzionale presente | 2 | Stesso ordine; due chiamate opzionali complessive, ritorno-23 ignorato |
| Successo e richiesta accodata prima della deregistrazione | 2 | La richiesta viene liberata mentre il nodo resta in coda con count1 |

Totali dei nuovi casi:10 tentativi di allocazione contesto,8 tentativi
richiesta,8 rilasci contesto,6 rilasci richiesta. Lo shutdown1919D4 entra
otto volte, incluse le due pulizie interne dopo il fallimento della
richiesta40. Nessun task o oggetto evento viene creato in questo percorso
di inizializzazione con lo slot opzionale fornito dal banco.

## Cosa fa e cosa non garantisce lo shutdown

`1919D4` prende il contesto da interfaccia+0x3C. Se contesto+8 è nonzero,
chiama lo slot+C della vtable endpoint0, cioè278808. Quest'ultima verifica
solo che endpoint e richiesta siano nonnulli e passa la richiesta al free;
non ne controlla stato, appartenenza a una coda o completamento.
Poi1919D4 libera il contesto e azzera interfaccia+0x3C e globale368114.

La deregistrazione278610 azzera pubblico+0x48. Rimangono invece:

- pubblico+0x38 uguale a tabella+32, già osservato nel banco applicativo;
- il primo campo dell'endpoint0 uguale all'indirizzo del contesto appena
  rilasciato. Non si assume che quel campo venga poi dereferenziato.

Questi riferimenti non autorizzano il riuso dei relativi oggetti. Il test
conserva i byte dello storage rilasciato per osservare gli indirizzi; non
è un allocatore reale né una prova della durata fisica dei dati.

## Prova avversa di richiesta pendente

Il banco usa deliberatamente la richiesta40 creata per la classe e la
accoda all'endpoint bulkOUT tramite278854, dopo notifica di stato e apertura
originali. È una sequenza sintetica che omette gli eventuali arresti
richiesti dal normale ciclo Nikon, non una riproduzione del suo shutdown.

Prima della deregistrazione: richiesta+32=-10, nodo allocato che punta
alla richiesta, count dispositivo1. Durante il free della richiesta,
il banco registra ancora esattamente queste condizioni. Dopo il free
di richiesta e contesto e il ritorno0 della deregistrazione:

- count dispositivo resta1 e il nodo resta nella coda OUT;
- il nodo punta ancora all'indirizzo della richiesta rilasciata;
- nessun callback di completamento o free del nodo è avvenuto.

I due casi terminano qui, prima di un IRQ che possa usare la richiesta
rilasciata. Il reset delle fixture tra scenari non equivale a cancel o
quiescenza del controller. Questa prova dimostra il limite del contratto
di rilascio, non un difetto hardware o un errore nel normale ordine Nikon.
Per il binding del dumper resta necessario arrestare l'I/O e stabilire la
quiescenza prima di liberare richieste, contesto o buffer.

## Regressione e limiti

La regressione AkeruRAM mantiene36 scambi,72 completamenti/free, risposte
identiche a Python, segmentazione4128IN, trasferimento vuoto IN e guardie
di ownership/errore. I due submit avversi portano il totale a74, con72
completamenti. Le notifiche aggiuntive portano il totale a97 chiamate del
callback registrato. I contatori PC sono controllati dal verificatore.

Risorse, allocator/free, azzeramento, MMIO/capability, IRQ delivery,
callback opzionale e dati RAM restano modellati. Il modello DSP GNU
preesistente resta provvisorio;128 MiB sintetici non sono una mappa fisica.
Non sono stati eseguiti i callback191570/19199C/191A60 né il normale
passaggio evento/task della classe.

Prossimo lavoro: seguire19199C→1910C4 e l'ordine di chiusura/cancellazione
degli endpoint, poi consegna al task e contratto cache. Whitelist RAM
fisica, residenza, boot, recupero e funzionamento hardware restano aperti.
Nessun comando USB/NAND/SD o installazione eseguito. **NON_INSTALLARE**.
