# S33 — tre stadi, callback di configurazione e dispatch

Analisi statica V1.1, 19 ottobre 2026. Continuazione del [protocollo evento del task](S33_Protocollo_Evento_Task_Azzeramenti_e_Bypass.md). Nessun accesso hardware.

## Risultato

Ricostruite tre catene condizionali dalla configurazione alla notifica del task: **`0x2000`, `0x800` e `0x1000`**. Ogni percorso usa uno stato software inizializzato a1, portato a2 dall'avvio e a3 dal gestore. Questi numeri sono valori osservati; non costituiscono una specifica universale di completamento fisico.

Il registrar `0x266234` e il dispatcher `0x26627C` collegano le richieste ID `0x600A/0x600C/0x600B` ai gestori concreti attraverso la tabella `0x424E00`. Il dispatcher controlla due halfword MMIO a `0x0FEF0228/22C`. I nomi fisici dei tre stadi rimangono aperti. Circa 10% funzionale AkeruOS, invariato.

## 1. Configurazione, callback e avvio

| Bit evento `0x08200011` | Campo callback in input | Copia configurazione | Callback effettiva | Cella invocata | Stato |
|---|---|---|---|---|---|
| `0x2000` | +`0x48` | `0x50C1F8`, 0x4C byte | `0x2444D8` | `0x50C240` | `0x36ADC8` |
| `0x800` | +`0x38` | `0x50C254`, 0x3C byte | `0x2444A0` | `0x36ADD4` | `0x36ADCC` |
| `0x1000` | +`0x4C` | `0x50C290`, 0x50 byte | `0x2444CC` | `0x36ADD8` | `0x36ADD0` |

Per `0x800`, il puntatore copiato è anche a `0x50C28C`; per `0x1000`, a `0x50C2DC`. I due inizializzatori conservano inoltre la callback separatamente nel controllo a `0x36ADCC+8/+C`.

Produttori verificati:

- builder `0x244234`: pool `0x2444B4 → 0x2444D8`, store a input+`0x48` nel tratto `0x2442D8/2DE`;
- builder `0x243F48`, ramo formato 0x3C: pool `0x244058 → 0x2444A0`, store a input+`0x38` a `0x244020`;
- stesso builder, ramo formato 0x50: pool `0x2444AC → 0x2444CC`, store a input+`0x4C` a `0x2440C4`. Altri rami del builder possono preparare lo stesso campo.

| Bit | Inizializzatore | Scrittura stato1 | Avvio | Scrittura stato2 | Gestore | Scrittura stato3 |
|---|---|---|---|---|---|---|
| `0x2000` | `0x24A488` | `0x24A5C0` | `0x24A6CC` | `0x24A738`, delay slot | `0x24A97C` | `0x24A986` |
| `0x800` | `0x24B004` | `0x24B222` | `0x24B230` | `0x24B282` | `0x24BCB8` | `0x24BCE4` |
| `0x1000` | `0x24B7A0` | `0x24BA52` | `0x24BA5C` | `0x24BACE` | `0x24BCF4` | `0x24BD20` |

Gli avvii corrispondono ai servizi raggiunti dal task nel rapporto precedente. Configurazioni, avvii e gestori hanno guardie: la presenza dei puntatori nel binario non dimostra che tutti e tre gli stadi siano attivi per ogni modalità. Le finestre verificate provano i passaggi elencati, senza trasformare l'analisi in una prova completa di tutti i rami di inizializzazione.

## 2. Registrar e tabella del gruppo 0x6000

`0x266234` conserva ID in r14 e callback in r15; richiede `(ID & 0x6000) == 0x6000`, scorre il conteggio halfword a tabella+8 e confronta gli ID a tabella+`0xC+8*indice`. Se trova la voce, scrive il puntatore a tabella+`0x10+8*indice`. Il ritorno finale è0 anche quando non trova una voce: da solo non prova l'installazione.

La tabella statica **`0x424E00`** contiene:

```text
+0x00: 0x0FEF0228
+0x04: 0x0FEF022C
+0x08: conteggio16
+0x0C: 16 record da8byte: ID16, bit sorgente8, bit abilitazione8, callback32
```

Tutti i 16 record sono stati letti e verificati: ID decrescenti `0x6010..6001`, indici bit `15..0`, callback iniziali0. Per i tre stadi:

| Bit task | Richiesta registrazione | ID | Indice | Record | Cella callback | Bit globale |
|---|---|---|---:|---|---|---|
| `0x2000` | `0x24A57A`: handler `0x24A97C` | `0x600A` | 6 | `0x424E3C` | `0x424E40` | 9, maschera `0x200` |
| `0x800` | `0x24B0E6`: handler `0x24BCB8` | `0x600C` | 4 | `0x424E2C` | `0x424E30` | 11, maschera `0x800` |
| `0x1000` | `0x24B8A0`: handler `0x24BCF4` | `0x600B` | 5 | `0x424E34` | `0x424E38` | 10, maschera `0x400` |

Le maschere globali della colonna finale **non sono** le maschere dell'evento task: appartengono a registri e livelli diversi.

Il dispatcher legge entrambi gli indirizzi del record di testa, controlla i bit indicati dalla voce, poi chiama la callback se nonzero. Dopo il ritorno scrive una halfword con il solo bit sorgente al registro `0x0FEF0228`. Il ruolo sorgente/abilitazione è dedotto dal test congiunto; non si assume una semantica elettrica W1C senza ulteriore evidenza.

## 3. Condizioni nei gestori

### Notifica 0x800

`0x24BCB8` chiama `0x2E39FC`, che legge halfword a **`0x0FFC4008`**, conserva il risultato in r13, poi `0x2E3A60`, che legge **`0x0FFC400C`**. Richiede bit4 in entrambe le letture. Se uno manca, salta aggiornamento dello stato e callback.

Se entrambi sono presenti, scrive `0x10` al primo registro tramite `0x2E3A10`, chiama altri controlli, pubblica stato3 e invoca il puntatore `0x36ADD4` se nonzero. Il callback configurato `0x2444A0` emette `0x08200011/0x800`.

### Notifica 0x1000

`0x24BCF4` segue la stessa struttura, con **`0x0FFC3008/300C`** e bit4. Scrive `0x10` a `0x0FFC3008` tramite `0x2E3D60`, pubblica stato3 a `0x36ADD0` e invoca `0x36ADD8`, se nonzero. Il callback `0x2444CC` emette `0x08200011/0x1000`.

### Notifica 0x2000

`0x24A97C` chiama `0x2E3578`, che scrive halfword1 a **`0x0FFC20B4`**, poi pubblica stato3 a `0x36ADC8` e invoca la callback `0x50C240`, se nonzero. Il callback configurato `0x2444D8` emette `0x08200011/0x2000`.

Nel corpo di questo gestore non compare il doppio test bit4 dei due precedenti; l'ammissione esterna passa comunque dal dispatcher verificato. La scrittura1 al registro non viene denominata automaticamente «ack fine frame».

## Evidenze e continuazione

[Script](../Python_Trace_Scripts/s33_trace_stage_event_callbacks.py), [JSON](../Ghidra_Results/ghidra_reports/stage_event_callbacks/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/stage_event_callbacks/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_stage_event_callbacks.py`.

Verificati **16 hash dei payload, roundtrip ELF del blocco00, 37 finestre, 16 collegamenti diretti, 81 istruzioni chiave, 27 pool, 16 record del registrar e 3 catene callback**. Le finestre dei servizi MMIO saltano esplicitamente i pool letterali: i dati non vengono usati come istruzioni.

Restano aperti: installazione/esecuzione runtime, collegamento del dispatcher al vettore CPU in questa modalità, nomi fisici degli stadi, effetti precisi dei controlli MMIO e ultimo uso del buffer. Prossimo passo: seguire attivazione e controlli dei tre stadi dai servizi `0x2E34xx/0x2E38xx/0x2E3Bxx`, mantenendo distinta la notifica software dal termine fisico del lavoro.


## Continuazione — controlli di avvio e disattivazione

Il [rapporto sulle transizioni dei controlli](S33_Transizioni_Controlli_Stadi_Avvio_e_Arresto.md) risolve 12 accessor e il loro ordine negli avvii, nei gestori e in due percorsi di disattivazione. I controlli sono scritture dirette senza polling locale; il significato hardware e la fine dell’uso fisico dei buffer restano aperti.


## Continuazione — interrupt padre e slot CPU

Il [rapporto sul gruppo6000](S33_Gruppo_6000_Abilitazione_e_Interrupt_Padre.md) risolve il padre090D, la bitmap `0x36B330` e il raccordo statico attraverso slot runtime9 e relativo stub CPU. Restano aperte installazione/esecuzione reali, stato corrente dei vettori e fine dell’uso fisico dei buffer.
