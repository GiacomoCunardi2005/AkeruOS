# S33 — notifiche del dispositivo e attesa evento

Analisi statica V1.1, 19 ottobre 2026. Continuazione dell'[handshake di attivazione](S33_Handshake_Attivazione_e_Polling_Dispositivo.md). Nessun accesso hardware.

## Risultato

Collegata una notifica del dispositivo al relativo evento software. Nel percorso banca1, il gestore **`0x29615C`** controlla **`0x0FE9813C & 0x2`**, esegue un'operazione sullo stato e segnala **evento `0x03F00002`, maschera `0x10000`**. La routine **`0x2ED4C4`**, per la stessa banca, attende esattamente quell'evento e quella maschera.

Risolta anche la richiesta di registrazione **ID `0x090A` → `0x29615C`**, con cella callback **`0x424C70`** nella tabella del registrar. Tuttavia, l'attesa non confronta localmente il suo ritorno prima di proseguire; il wrapper esterno termina con zero. La catena non è quindi una prova sufficiente di ultimo uso del buffer. Stima funzionale invariata: circa 10%.

## 1. Richiesta di registrazione del gestore

Il consumatore, a **`0x2487B0`**, chiama `0x295EC8` con argomento1 nel delay slot. Nel ramo corrispondente, questa funzione prepara:

- r0 = **`0x090A`**, dal pool `0x295F40`;
- r1 = **`0x29615C`**, dal pool `0x295F3C`;
- chiamata al registrar **`0x16D898`**, con successivo controllo del ritorno nel percorso verificato.

Il registrar riconosce il gruppo alto `0x0900`, seleziona la tabella **`0x424C30`** e cerca l'identificatore nei record da otto byte. La tabella contiene 14 record; **indice6** contiene ID `0x090A` a `0x424C6C` e callback a **`0x424C70`**, inizialmente zero nel payload.

Lo store `0x16D9A6` scrive il puntatore callback nel record trovato. Questa è una richiesta e un percorso statico di installazione: le guardie del registrar e l'ordine delle installazioni runtime restano rilevanti.

Un ramo alternativo prepara **`0x2961C0`** per lo stesso ID `0x090A`. Non si assume pertanto che il primo gestore sia immutabile per tutta la sessione della fotocamera.

## 2. Dal bit di stato all'evento

| Percorso | Gestore | Bit di stato verificato | Evento / maschera | Callback opzionale |
|---|---|---|---|---|
| banca1 | `0x29615C` | `0x0FE9813C & 2` | `0x03F00002 / 0x10000` | cella `0x36C390` |
| banca0 | `0x296190` | `0x0FE9013C & 2` | `0x03F00002 / 1` | cella `0x36C390` |
| variante banca1 | `0x2961C0` | `0x0FE9813C & 2` | `0x03F00002 / 0x10000` | cella `0x36C394` |

I gestori usano il servizio `0x2EE9C4`, **indice stato1, operazione1**, per leggere il valore mascherato. Se zero saltano oltre la segnalazione. Se nonzero eseguono **indice1, operazione0**, poi chiamano `0x158CBC` con l'evento e la maschera indicati.

L'operazione0 è una scrittura sullo stato, come ricostruito nel rapporto precedente; non viene etichettata automaticamente come write-one-to-clear. La chiamata alla callback opzionale segue la segnalazione solo se la cella contiene un puntatore nonzero. I produttori e il contratto di quelle callback restano aperti.

Il bit2 qui letto è distinto dalle maschere8/80/400 attese dall'handshake di attivazione. La sua semantica fisica non viene dedotta dal solo ordine delle chiamate.

## 3. Attesa corrispondente e ritorno non controllato

`0x2ED4C4` normalizza l'argomento banca. Il ramo zero attende evento **`0x03F00002/1`**; il ramo nonzero prepara **`0x03F00002/0x10000`**. Le chiamate all'attesa `0x158D04` sono a `0x2ED4D8/4F0`, con r2=0 e r3=0 nei delay slot verificati.

Dopo la chiamata, **non compare un confronto del ritorno dell'attesa**. Il codice entra in una sezione critica e sovrascrive r0; conserva in r13 il risultato di quella chiamata successiva. Prosegue con un servizio relativo all'ID logico (`0x040C` oppure `0x090A`), un'altra operazione sullo stato e il tratto di ripristino. Il ritorno dell'attesa non viene propagato direttamente.

Il wrapper **`0x2956F0`** chiama questa routine, poi imposta **r0=0 nel delay slot del ritorno**. Di conseguenza un suo ritorno zero non è, da solo, una prova che l'evento sia stato effettivamente osservato con esito valido.

Non viene assegnato un significato di timeout ai parametri zero senza ricostruire il contratto completo dell'API. Il risultato verificato è più limitato: l'esito locale dell'attesa non viene confrontato prima di proseguire nel tratto esaminato.

## 4. Preparazione e limiti della catena

La funzione inferiore `0x2ED450` contiene anche la pulizia delle corrispondenti maschere evento e una preparazione dello stato/ID logico, prima dell'attivazione. Questo rafforza la corrispondenza fra maschera attesa e maschera segnalata, senza dimostrare che ogni percorso della pipeline attraversi la stessa sequenza o che non esistano eventi precedenti.

La catena consolidata è:

```text
richiesta registrazione ID090A → callback tabella0x424C70
→ test stato banca1, maschera2 → operazione sullo stato
→ evento0x03F00002, maschera0x10000
→ attesa banca1 con la stessa coppia → continuazione senza confronto locale dell'esito
```

La ricerca candidata dei chiamanti diretti di `0x2956F0` nel blocco00 individua `0x249D1A`, `0x24A230` e `0x24A3B0`. Questi siti sono piste per la continuazione, non sono ancora promossi a un percorso completo fino alla cancellazione del flag dello slot.

Rimangono da attribuire la causa hardware del bit, l'invocazione effettiva del gestore tramite il dispatcher IRQ, le callback opzionali e l'ultimo uso della destinazione. Le evidenze non provano correttezza dell'immagine, fine frame o sicurezza del riuso.

## Evidenze e prossimo passo

[Script](../Python_Trace_Scripts/s33_trace_device_status_notifications.py), [JSON](../Ghidra_Results/ghidra_reports/device_status_notifications/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/device_status_notifications/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_device_status_notifications.py`.

Verificati **16 SHA-256, roundtrip ELF del blocco00, 8 finestre, 12 collegamenti diretti, 31 istruzioni chiave e 11 pool**, più il record ID090A fra14record e la maschera stato1 della banca1. Nessuna registrazione o attesa è stata eseguita sulla fotocamera.

Prossimo: collegare i chiamanti dell'attesa al task consumatore e seguire il dispatcher che invoca il record090A. Il confronto fra questa notifica e l'azzeramento del flag rimane necessario prima di sostenere una garanzia di ultimo uso.


## Continuazione: callback configurate e task consumatore

Il [rapporto sulle callback annidate](S33_Callback_Annidate_e_Attese_Consumatori.md) identifica setter e callback opzionali del dispositivo, tre chiamanti dell’attesa e una distinta attesa del task. Il ponte tramite input+C4/C8 resta da chiudere.
