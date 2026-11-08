# S33 — produttori dei descrittori e callback concreti

Analisi statica V1.1, 19 ottobre 2026. Continuazione dell'[installazione callback](S33_Installazione_Callback_da_Configurazione.md). Nessuna esecuzione sulla fotocamera.

## Risultato

Risolti i puntatori al descrittore per due percorsi di preparazione: **`0x442630`** per input `0x4424B8`, e **`0x445A6C`** per input `0x445510`. Nel secondo percorso i rami scrivono **`0x1653C0`** come callback preferita oppure **`0x165338`** come fallback. Il significato dell'elaborazione svolta da queste funzioni resta da ricostruire. Stima funzionale invariata: circa 10%.

## 1. Primo oggetto: pubblicazione attraverso un indirizzo intermedio

A `0x12F5AC`, il pool `0x12F60C` carica r2 con `0x442600`. Nel ramo verificato a `0x12F672`, `add r0,r2,0x30` costruisce **`0x442630`**; il puntatore viene conservato in r20 e passato a `0x1FC48C`.

Quest'ultima routine scrive **`0x1FC4E0`** a descrittore+`0x10`, usando il pool `0x1FC4A4`. Il chiamante riprende il puntatore da r20 e, a `0x12F682`, lo scrive a **`0x4425B0+0x18 = 0x4425C8`**. Questo indirizzo coincide con **input `0x4424B8+0x110`**. Il pool della base intermedia è `0x12F910`.

La pubblicazione dipende dal ramo a `0x12F664`, che confronta il byte dell'oggetto r14+69 con 1. Gli altri rami non sono qui dichiarati equivalenti. Le prime quattro parole del descrittore, compresi i callback +8/+12, restano da attribuire.

Un dettaglio utile per evitare una falsa attribuzione: il pool `0x12F608` contiene `0x442454`. Le scritture `.as` con offset 108, 110, 111 e 112 incontrate prima appartengono a campi diversi: **non sono la scrittura a input+0x110**.

## 2. Secondo oggetto: descrittore e due rami di callback

Il pool `0x1647C0` contiene **`0x445A64`**. Il descrittore passato alla preparazione è **`0x445A6C`**, caricato in r16 dal pool `0x164834` con un normale `ld` relativo a PCL. Si tratta della base precedente+8.

Il tratto `0x164760` verifica il byte r14+38: se diverso da 1, salta a `0x16483E`, oltre la pubblicazione del descrittore. Nel tratto ammesso, il byte r14+20, caricato poco prima e confrontato anche a `0x164768`, seleziona due rami. Il significato di questi byte rispetto alle modalità della fotocamera resta aperto.

| Campo | Ramo confronto uguale a 1 | Ramo alternativo |
|---|---|---|
| Descrittore+0, base `0x445A64+8` | `0x1FE960` | valore r15, inizializzato a zero nel prologo |
| Descrittore+4, base+12 | non attribuito in questa finestra | `0x1FD38C` |
| **Descrittore+8, base+16** | **`0x1653C0`** | valore r15 |
| **Descrittore+12, base+20** | non attribuito in questa finestra | **`0x165338`** |

Le scritture sono a `0x164770/774` e `0x16477C..784`; i valori provengono dai pool `0x164824..830`. r15 viene inizializzato a zero a `0x1640B6`; la scansione candidata del corpo precedente non mostra altre assegnazioni locali a r15, ma non sostituisce un audit completo di tutte le chiamate e dell'ABI.

A `0x16479E`, la routine `0x252694` riceve il descrittore anche in r5. Il corpo verificato scrive la quinta parola (+16). La pubblicazione successiva, a **`0x16483A`**, scrive r16 a **`0x445608+24 = 0x445620`**, cioè **input `0x445510+0x110`**. Non si tratta di una lettura di contenuti RAM già presenti nel file del firmware: sono assegnazioni ricostruite dal codice.

## 3. Collegamento al worker

I due chiamanti entrano poi nell'inizializzatore `0x15DF98` dai siti `0x12F77C` e `0x1649AE`. Nel ramo di copia già verificato, descrittore+8/+12 alimentano **`0x3674C8/CC`**. Il builder e la chiamata del worker sono documentati nel [rapporto sul descrittore di lavoro](S33_Descrittore_Worker_e_Selezione_Callback.md).

La catena statica selezionata è quindi:

```text
input 0x445510 → campo 0x445620 → descrittore 0x445A6C
→ +8: 0x1653C0 / +12: 0x165338, secondo ramo
→ controlli 0x3674C8/CC → richiesta → chiamata indiretta worker
```

Le destinazioni `0x165338/0x1653C0` iniziano entrambe con un prologo di funzione e conservano diversi argomenti. Non vengono ancora chiamate funzioni JPEG: né i prologhi né il collegamento al worker stabiliscono formato, proprietà dei buffer o significato del ritorno.

## Evidenze, limiti e prossimo passo

[Script](../Python_Trace_Scripts/s33_trace_worker_descriptor_producers.py), [JSON](../Ghidra_Results/ghidra_reports/worker_descriptor_producers/verified_evidence.json), [disassemblaggio GNU](../Ghidra_Results/ghidra_reports/worker_descriptor_producers/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_worker_descriptor_producers.py`.

Verificati **16 SHA-256, roundtrip ELF del blocco 00, 13 finestre, 4 collegamenti diretti, 39 istruzioni chiave e 14 valori di pool**. Le finestre mirate non rappresentano una copertura completa dei corpi, dei rami o degli scrittori RAM. Nessuna prova di esecuzione effettiva, persistenza JPEG o riuso sicuro del buffer.

Prossimo passo: ricostruire gli argomenti, il corpo e gli esiti di `0x1653C0/0x165338`, collegarli ai lettori della risposta del worker e trovare i produttori delle prime quattro parole di `0x442630`. Restano aperte ammissione delle modalità e gestione delle installazioni parziali.


## Continuazione: contratto e codici

Il [rapporto sul contratto callback](S33_Contratto_Callback_Worker_e_Codici_Ritorno.md) risolve backend, guardia costante, argomenti e codici locali restituiti. La semantica delle elaborazioni e il lettore finale del risultato restano aperti.
