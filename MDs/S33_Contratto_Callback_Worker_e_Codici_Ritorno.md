# S33 — contratto dei callback worker e codici di ritorno

Analisi statica V1.1, 19 ottobre 2026. Prosegue l'[identificazione dei callback concreti](S33_Produttori_Descrittori_e_Callback_Concreti.md). Nessuna esecuzione hardware.

## Risultato

I callback **`0x165338`** e **`0x1653C0`** inoltrano il lavoro rispettivamente a **`0x1FE470`** e **`0x200620`**. Entrambi hanno un controllo iniziale che chiama **`0xC7870`**, una funzione di due istruzioni che restituisce sempre **1** nel campione verificato. Ne consegue che, seguendo questi ingressi nel codice immutato e con normali ritorni delle chiamate, il controllo passa direttamente ai backend.

Il backend fallback sceglie localmente valori **0 / `0x2AF9` / `0x2AFA`**; quello preferito sceglie **0 / 1002 (`0x3EA`)**. I rispettivi tratti finali sovrascrivono il ritorno immediato dell'ultima chiamata interna con il valore conservato localmente. La risposta del worker conserva quindi questo codice; la successiva notifica dell'evento non lo confronta con zero.

Questo chiarisce il contratto statico del risultato. Non attribuisce ancora alle funzioni un formato immagine o una garanzia di salvataggio. Stima funzionale: circa 10%.

## 1. Controllo costante e ramo escluso nel campione

`0xC7870` contiene:

```text
mov_s r0,1
j_s [blink]
```

Le chiamate dei due callback sono a `0x165360` e `0x1653E8`. Dopo il ritorno, confrontano r0 con zero; i rami nonzero a `0x165368/0x1653F0` vanno a `0x16538C/0x165414`, dove preparano gli argomenti del backend.

L'altro percorso contiene una chiamata a `0xD2E40`, confronti con 7, 9, 10, 11 e un'uscita r0=0 che salta il backend. **Questo percorso non viene raggiunto dagli ingressi analizzati se `0xC7870` mantiene i byte verificati.** I confronti presenti nel disassemblaggio non dimostrano che il filtro operi su questa versione. Nessuna conclusione sulla fotocamera in esecuzione o su eventuali modifiche del codice in RAM.

## 2. Argomenti dalla richiesta al backend

Nel worker `0x343280`, il puntatore al payload viene letto da richiesta+8. Il campo payload+`0x38` sceglie la callback preferita quando nonzero; altrimenti viene letto payload+`0x34`. Il secondo tratto ha il controllo di null già documentato.

La chiamata indiretta **`jl_s.d [r13]` a `0x3432E0`** esegue nel delay slot l'assegnazione **r5=r15**. Omettere questa istruzione farebbe perdere uno degli argomenti.

| Argomento alla callback | Sorgente, percorso preferito | Sorgente, fallback |
|---|---|---|
| r0 | payload+0, parola | uguale |
| r1 | payload+4, parola | uguale |
| r2 | payload+`0x10`, parola | uguale |
| r3 | payload+`0x14`, halfword | uguale |
| r4 | payload+`0x16`, halfword | uguale |
| r5 | payload+`0x20` | payload+`0x18` |
| r6 | payload+`0x24` | payload+`0x1C` |
| r7 | payload+`0x28` | payload+`0x20` |
| stack+0 | payload+`0x2C`, parola | payload+`0x24`, parola |
| stack+4 | payload+`0x30`, byte | uguale |

I due wrapper conservano gli otto argomenti nei registri prima del controllo e li ricaricano per il backend. Il prologo condiviso `0x334110` salva dieci registri, a cui si aggiungono blink e fp: **fp+48** corrisponde alla prima parola in ingresso sullo stack, **fp+52** al byte successivo letto dal wrapper. I due valori vengono riscritti sullo stack della chiamata al backend.

Non sono ancora assegnati nomi come larghezza, buffer o formato a questi campi: gli offset e le ampiezze delle letture sono osservazioni, la semantica richiede di seguire i consumatori.

## 3. Backend e valori restituiti

### Fallback `0x1FE470`

Il corpo verificato comprende diversi confronti e operazioni attraverso helper. Prima della parte finale, le vie ordinarie convergono sulle assegnazioni del registro r23:

- `0x1FE572`: `0x2AF9`;
- `0x1FE588`: 0;
- `0x1FE5C0`: `0x2AFA`, raggiungibile anche come sostituzione del valore precedente.

A `0x1FE6FC` viene chiamato `0x1FD614`, con r7 preparato nel delay slot. Subito dopo, **`0x1FE704` imposta r0=r23** prima del ripristino dei registri e del ritorno. Il valore immediatamente restituito da `0x1FD614` non viene propagato come r0 del backend.

### Preferito `0x200620`

I confronti iniziali convergono su **r20=0** a `0x200708` oppure **r20=1002** a `0x20070E`. A `0x2007DC` viene chiamato `0x1FEAA0`, con r7 preparato nel delay slot. **`0x2007E2` imposta poi r0=r20**, prima del ripristino e del ritorno.

Sono codici scelti dai rami locali. Non vengono attribuiti nomi simbolici agli errori né dedotta l'effettiva riuscita dell'operazione inferiore. Il contratto presuppone i normali ritorni e la conservazione dei registri prevista dal codice chiamante; le implementazioni di tutti gli helper restano fuori da questo audit.

## 4. Dal ritorno all'evento

Il worker copia r0 a risposta **`0x424800+4`** a `0x3432F0`. Il successivo handler **`0x247364`**, per risposta tipo 1, legge +4 e lo conserva a **`0x36AD58`**.

L'handler imposta poi lo stato e segnala **evento `0x09900020`, bit 2** senza un confronto di successo del codice salvato. La catena aggiornata è:

```text
backend → codice locale → callback r0 → risposta+4
→ 0x36AD58 → notifica evento indipendente dal valore
```

Quindi l'evento da solo non prova che il codice sia zero. Il lettore finale di `0x36AD58` rimane da collegare; si veda anche il [rapporto sulle risposte](S33_Risposte_Worker_e_Eventi_Fine_Lavoro.md).

## Evidenze e prossimo passo

[Script](../Python_Trace_Scripts/s33_trace_worker_callback_contract.py), [JSON](../Ghidra_Results/ghidra_reports/worker_callback_contract/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/worker_callback_contract/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_worker_callback_contract.py`.

Verificati **16 SHA-256, roundtrip ELF del blocco 00, 9 finestre, 14 collegamenti diretti e 39 istruzioni chiave**. Le finestre includono i due wrapper e i due backend fino al rispettivo ritorno. Lo script esplora anche i rami interni ordinari dei due backend e verifica che i percorsi di ritorno attraversino le assegnazioni dei codici elencati: 518 stati di visita nel fallback e 263 nel preferito. Il modello assume che le chiamate ritornino normalmente e preservino il registro del codice; segue la selezione del codice, senza emulare gli helper. Le chiamate inferiori non sono tutte ricostruite e la verifica non esegue il firmware.

Prossimo: identificare operazioni e buffer di `0x1FD614/0x1FEAA0`, trovare i lettori del codice `0x36AD58` e ricostruire i callback del primo descrittore `0x442630`. Persistenza JPEG, ammissione delle modalità e sicurezza del riuso buffer restano aperte.


## Continuazione: dati e reset risultato

Il [rapporto sui campioni](S33_Cicli_Campioni_Configurazione_e_Reset_Esito.md) collega i cicli CPU agli argomenti sorgente/destinazione, ricostruisce i due setter del controllo condiviso e trova l’azzeramento preventivo di `0x36AD58`. Lettore finale, algoritmo completo e durata buffer restano aperti.
