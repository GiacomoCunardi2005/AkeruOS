# S33 — Load Later, attese e limite del segnale finale

20 ottobre 2026 — R0/R3/R4. Continuazione dei [gruppi C2/C3/C4 e risorse](S33_Gruppi_C2_C3_C4_Risorse_e_Segnali_Caricamento.md), con byte del Main fornito e PerfLog dello stesso avvio. Analisi locale, nessun comando alla fotocamera.

Il task che esegue i caricamenti differiti è associato alla stringa **Load Later**. L’evento `0x42700002` serve sia al protocollo richiesta/fine lavoro sia alle notifiche dei payload. Il consumatore a `0x134EFC` aspetta il segnale parziale `0x08` di C3; due helper distinti aspettano o interrogano il bit finale `0x80`.

**Il bit `0x80` indica che il coordinatore ha raggiunto la propria fine, senza certificare tutti i caricamenti.** Otto prove sul coordinatore originale, con letture simulate e operazioni reali sui bit, lo verificano anche dopo errori iniettati. Se fallisce Resource/TBM9, i bit finali sono esattamente gli stessi del caso riuscito. È un limite del contratto da rispettare per AkeruOS, non un guasto hardware osservato.

## Evidenze e riproduzione

- [Script](../Python_Trace_Scripts/s33_verify_load_event_consumers.py), [ultimo controllo](../Risultati/Dump_fotocamera/Eventi_Caricamento/latest.json).
- [Evidenze del controllo riuscito](../Risultati/Dump_fotocamera/Eventi_Caricamento/20261020T162907Z/verified_evidence.json), [22 finestre GNU](../Risultati/Dump_fotocamera/Eventi_Caricamento/20261020T162907Z/gnu_verified.txt).
- [790 casi dei consumatori](../Risultati/Dump_fotocamera/Eventi_Caricamento/20261020T162907Z/consumer_cases.json), [sei iterazioni del task](../Risultati/Dump_fotocamera/Eventi_Caricamento/20261020T162907Z/task_loop_cases.json), [otto casi del coordinatore](../Risultati/Dump_fotocamera/Eventi_Caricamento/20261020T162907Z/orchestrator_cases.json).
- [Modifiche delle sole copie di laboratorio](../Risultati/Dump_fotocamera/Eventi_Caricamento/20261020T162907Z/laboratory_patches.json), [501 PC originali controllati](../Risultati/Dump_fotocamera/Eventi_Caricamento/20261020T162907Z/executed_original_pcs.json). I file con nome `NOT_FIRMWARE` non sono immagini da installare.

```bash
python3 Python_Trace_Scripts/s33_verify_load_event_consumers.py
```

Esito `PASS_LOAD_EVENT_CONSUMERS_AND_PERSISTENT_BITS`. Nove esecuzioni GNU terminano con exit0 senza fault. Il controllo riguarda 790 casi dei consumatori, 3.072 predicate, sei iterazioni limitate del task e otto scenari del coordinatore. I 16 payload sono verificati dagli helper; finestre, pool e istruzioni originali eseguite coincidono con MainCode fornito. I 41 input registrati e gli strumenti GNU sono ricontrollati prima/dopo. Nessuna nuova scansione ECC o osservazione fisica viene dichiarata in questo rapporto.

## Oggetti e configurazione

| Oggetto | Byte o collegamento verificato |
|---|---|
| Record del task | `0x3729C8`, ID `0x42700001`, ingresso `0xC5830`, nome puntato a `0x3766D2`: Load Later |
| Callback del lavoro | cella `0x365614`, scritta dal richiedente e letta dal task |
| Callback aggiuntiva dopo C2 | cella distinta `0x365618`, letta dal coordinatore `0xC58C8` |
| Evento | ID `0x42700002`, indice82 della tabella `0x372A48` con stride56 |
| Record evento | `0x373C38`, magic `0x45564E4C`, flags statici2 |
| Bit pendenti | record+`0x24` = `0x373C5C` |
| Opzione auto-clear | record+`0x28` = `0x373C60` |

L’inizializzatore `0x158C30` passa il solo bit0 dei flags al servizio inferiore: per flags2, auto-clear0. Il resolver `0x158C8C` richiede inoltre il bit31 dei flags runtime. Quel bit non è impostato nel file originale; nei test viene impostato esplicitamente come condizione di laboratorio. Il record statico non è una lettura dello stato corrente della macchina.

La semantica generale all/any e l’accodamento sono già descritti in [attesa eventi](S33_Semantica_Attesa_Eventi_e_Bit_Persistenti.md) e [switch e risveglio](S33_Attesa_Task_Switch_e_Risveglio.md). Questa verifica esegue nuove prove delle operazioni sui bit, senza ripetere quei vecchi risultati come se fossero appena prodotti.

## Richiesta e ciclo del task

`0xC5718` prepara il protocollo: azzera la callback `0x365614`, imposta `0x02`, poi cancella separatamente `0x01/04/08/10/20/40/80`. Infine chiama il servizio distinto `0x158E78` con ID `0x42700001`, argomento1 zero e un parametro d’uscita sullo stack. Quest’ultimo servizio è simulato nel test; non viene confuso con l’evento `0x42700002`.

L’effetto sui bit è verificato per tutti i 256 valori del byte basso, conservando anche una sentinella nei bit alti: il risultato è `0xA5000002`. Si tratta della pulizia del protocollo studiato, non di un azzeramento universale della memoria o dell’evento.

Il richiedente `0xC578C(callback)`:

1. Con callback nulla restituisce0, senza pubblicare lavoro.
2. Con callback non nulla chiama l’attesa di `0x02`, opzione0 e quarto argomento0.
3. Scrive la callback in `0x365614`, cancella `0x02`, imposta `0x01`, restituisce1.

**Non confronta il ritorno dell’attesa prima di sostituire la callback.** Le prove con ritorni predisposti0, `0x200304` e `0x345` confermano lo stesso percorso per callback non nulla. Non è una prova che un errore simile si sia verificato sulla macchina: mostra quale comportamento avrebbe questo chiamante se ricevesse quell’esito.

Nel task `0xC5830`, il ciclo attende `0x01`, cancella `0x03`, legge la callback, la chiama se non nulla, imposta `0x02` e ripete. Anche qui il ritorno dell’attesa non viene confrontato. Sei prove eseguono **una vera iterazione del corpo originale**, con callback nulla/non nulla e i tre ritorni di laboratorio; si fermano alla seconda chiamata d’attesa. Con callback non nulla c’è una chiamata, negli altri casi nessuna. I bit passano da `0xA50000FD` a `0xA50000FE`; il puntatore callback resta memorizzato.

Non sono simulate esecuzione concorrente, durata dell’attesa o una sessione continua del task. La callback delle prove è un registratore, non il codice di acquisizione o il loader fisico.

## I bit di avanzamento appartengono alla fase, non a una generazione implicita

Le operazioni originali impostano i bit mediante OR e li cancellano mediante BIC. Con auto-clear0, un controllo riuscito non li consuma. Il richiedente cancella soltanto `0x02`; il ciclo del task cancella soltanto `0x03`. **Nessuno dei due ripulisce `0x04..0x80` per il solo fatto di avviare un altro lavoro.**

Questo non dimostra un errore nella sequenza Nikon: nei due chiamanti studiati, `0xC5C02→C5C06` e `0xC5E8C→C5E96`, la preparazione `0xC5718` precede la richiesta `0xC578C`. Nel primo caso viene pubblicato il coordinatore `0xC58C8` e subito dopo viene chiamato l’helper di attesa finale. Una nuova richiesta fatta senza rispettare la preparazione potrebbe invece vedere bit di avanzamento precedenti. Non sono stati esclusi tutti gli altri chiamanti indiretti o tutti gli scrittori runtime dei flags.

Per un futuro task AkeruOS servono oggetto di sincronizzazione proprio, lifetime e gestione errori espliciti; nessuno di questi oggetti Nikon è stato assegnato alla nuova applicazione.

## Consumatori parziale e finale

| Funzione o sito | Condizione e comportamento locale |
|---|---|
| `0x134EFC` | attesa evento `0x42700002`, maschera `0x08`, opzione0, quarto argomento0 |
| `0x134F00` | sovrascrive subito r0 con callback `0x13574C`; chiama `0xD3E38` con secondo callback `0x135760`, senza confronto dell’attesa |
| `0xC57D8` | attesa `0x02`; restituisce1 se il servizio ritorna zero, altrimenti0 |
| `0xC57F8` | interroga lo stato evento; restituisce il bit1 solo se la query riesce |
| `0xC5870` | attesa `0x80`; restituisce1 se il servizio ritorna zero, altrimenti0 |
| `0xC588C` | interroga lo stato evento; restituisce il bit7 solo se la query riesce |

Le 516 prove di polling eseguono resolver e query originali: 256 valori bassi per ciascuno dei due helper, più record non inizializzato e magic invalido. I bit rimangono invariati; nei casi di ammissione fallita il risultato è0. Le sei prove degli helper d’attesa ne verificano il booleano con tre ritorni predisposti. Le tre prove del tratto `0x134EF4..134F08` confermano che raggiunge il servizio successivo anche dopo ritorno nonzero; il servizio successivo viene soltanto registrato, non eseguito.

Il segnale `0x08` corrisponde alla fine della prima lettura di C3, cioè payload4, **prima del payload5**. Il suo consumatore può quindi proseguire mentre il gruppo C3 non ha ancora finito. Non è un’attesa di tutti i payload.

Sono inoltre verificati tre chiamanti della query finale: `0x1EB270`, `0x1EB3C8` e `0x659C30`; confrontano il booleano prima di proseguire nei rispettivi rami. Questo è un inventario locale di consumatori concreti, non una classificazione completa di tutte le loro funzioni. La ricerca di parole LE dell’ID nei 16 payload produce sette candidati, distinti dalla prova dei flussi e dai riferimenti calcolati o indiretti ancora possibili.

## Il coordinatore finale può pubblicare 0x80 dopo un errore

Sono eseguiti il coordinatore originale `0xC58C8`, i quattro wrapper e i servizi originali di impostazione dei bit. Le sette letture sono simulate; una alla volta restituisce zero all’offset del payload selezionato. Profiler, acquisizione/rilascio, configurazione del lettore e fase `0x159128` sono stub a ritorno zero. La modalità0x10 e la callback aggiuntiva nulla sono condizioni dichiarate del test.

| Lettura fatta fallire | Bit finali osservati | Letture tentate | Ritorno del coordinatore |
|---|---:|---:|---:|
| nessuna | `0xFC` | 7 | 0 |
| payload2 | `0xF8` | 6 | 0 |
| payload3 | `0xF8` | 7 | 0 |
| payload4 | `0xE4` | 6 | 0 |
| payload5 | `0xEC` | 7 | 0 |
| payload9 / Resource | `0xFC` | 7 | 0 |
| payload6 | `0x9C` | 6 | 0 |
| payload7 | `0xBC` | 7 | 0 |

In tutti i casi il bit `0x80` è presente. Gli errori del primo blocco di C2/C3/C4 saltano il secondo blocco del relativo gruppo, ma non arrestano i gruppi successivi. Resource non pubblica un bit proprio nel wrapper: il suo fallimento lascia la stessa maschera `0xFC` del successo.

Il test **non ha letto male la NAND**: ha fatto restituire un fallimento allo stub del lettore e osservato il flusso originale successivo. Non certifica il recupero dagli errori reali né esclude log, diagnostica, controlli o reazioni in altri rami. Dimostra che questi bit e il ritorno finale, isolatamente, non sono una prova sufficiente di tutti i trasferimenti riusciti.

## Portata dei test e prossimo punto utile

Nel controllo principale restano originali resolver, set/clear/query, helper e corpo dei consumatori. Il kernel di laboratorio contiene puntatore al task corrente, lista pronta coerente con quel task, contatore di annidamento1 e nessun waiter. Questo evita di entrare nello scheduler: non è stato ricostruito uno stato runtime della fotocamera. Sono controllate anche le modifiche alla copia Main1: nel test principale sono ammesse soltanto le celle dichiarate per puntatore kernel, magic/flags/bits dell’evento e callback.

Le 3.072 prove separate eseguono la sola decisione originale `0x2C99E0..2C9A08`: tutti i 256 valori bassi, maschere `0x08/80/88`, opzioni any/all e auto-clear0/1. I due confini sono intercettati prima del ritorno completo o dell’accodamento. Per auto-clear0 i bit persistono; auto-clear1 è una variante diagnostica, non una configurazione osservata sulla macchina.

**Prossimo:** seguire il caricamento del payload10 e dei payload11–15 alla base condivisa `0x01044800`, ricostruendo selezione, checksum, ownership e ultimo uso. Per il task AkeruOS rimangono memoria e oggetto di sincronizzazione propri, errori e lifetime; per R4 rimane il recupero fisico. Nessuna nuova RAM libera, misura di clock, foto o avvio AkeruOS: circa10% funzionale invariato.
