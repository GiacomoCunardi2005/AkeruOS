# S33 — protocollo dell'evento task, azzeramenti e bypass

Analisi statica V1.1, 19 ottobre 2026. Continuazione della [semantica degli eventi](S33_Semantica_Attesa_Eventi_e_Bit_Persistenti.md). Nessun accesso hardware.

## Risultato

L'evento `0x08200011` coordina anche segnali prodotti direttamente dal task. **Non tutti i bit della maschera finale `0x3F80` provengono necessariamente da callback hardware.** In un percorso alternativo il task imposta da solo l'intera maschera prima di altre operazioni software.

È individuato l'azzeramento normale **`0x3980`**, che cancella cinque bit e conserva `0x200/0x400`. Un percorso intermedio cancella invece `0x3080`. Le maschere descrivono un protocollo dipendente dal ramo: la sola soddisfazione dell'attesa non identifica univocamente lavoro fisico appena completato. Non si dichiara un difetto né si prova il riuso sicuro dei buffer. Circa 10% funzionale AkeruOS, invariato.

## 1. Base dei controlli e azzeramento normale

`0x15D02C` carica r14 dal pool `0x15CFA8 → C=0x367490`.

A `0x15D1AC`, il task carica evento `0x08200011`; prepara r1=`0x73` e lo sposta di sette bit nel delay slot `0x15D1B4` della chiamata a cancellazione `0x158CE0`.

```text
0x73 << 7 = 0x3980 = 0x80 | 0x100 | 0x800 | 0x1000 | 0x2000
0x3F80 & ~0x3980 = 0x600 = 0x200 | 0x400
```

L'azzeramento avviene prima del controllo C+`0x5C`. Se tale byte è diverso da1, il ramo `0x15D1BC` va a `0x15D7DC`, dove il task segnala **tutti i bit `0x3F80`**. Il ramo prosegue poi con operazioni di copia e raggiunge l'attesa finale. Non si interpreta quel prefilling come completamento hardware.

## 2. Produttori software dei bit rimanenti

Le condizioni seguenti sono locali ai tratti verificati: non costituiscono un modello temporale completo del task.

| Bit | Produttore diretto | Condizione locale / significato osservato |
|---|---|---|
| `0x200` | `0x15D2F0` | C+`0x8C` diverso da0; poi salta al segnale `0x400` |
| `0x200` | `0x15D370` | percorso C+`0x8C`=0 e byte C+`0x5D`=0 |
| `0x400` | `0x15D38A` | raggiunto dal ramo precedente oppure, con C+`0x8C`=0, byte C+`0x5E`=0 e parola `0x391E68+0x74`=0 |
| `0x2000`, `0x800`, `0x1000` | `0x15D3A2/3AC/3B6` | C+`0x84` vale1 o2; segnala tre bit e salta a selezione slot/invio |
| `0x2000` | `0x15D410` | altro percorso che salta uno stadio; guardia superiore C+`0x90` da completare nella catena intera |
| `0x200/0x400/0x100/0x800` | `0x15D4BA/4C4/4CE/4DA` | ingresso alternativo selezionato da C+`0xA8` diverso da0 |
| `0x3F80` intero | `0x15D7E0` | ramo C+`0x5C` diverso da1 |

Le maschere sono spesso preparate nei delay slot, con `mov` o `bset_s`: sono parte degli argomenti effettivi della chiamata. Il significato fisico dei campi di controllo e i nomi degli stadi restano da attribuire.

Per il percorso che raggiunge `0x15D496`, il task attende uno slot, chiama `0x24863C` a `0x15D4A8` e, se il ritorno è zero, salta direttamente all'attesa finale `0x15D8D2`. Il controllo del ritorno dell'invio è distinto dall'esito della successiva attesa, che non è confrontato localmente.

## 3. Attese intermedie e cancellazione parziale

Nel percorso alternativo, dopo un altro invio a `0x24863C`, il task esegue tre attese singole:

- `0x15D602`: maschera `0x80`;
- `0x15D610`: maschera `0x1000`;
- `0x15D61E`: maschera `0x2000`.

Tutte preparano r2=0 e r3=0. Per maschere a un solo bit la distinzione all/any non cambia la condizione. Gli esiti delle tre attese non sono confrontati nel tratto locale prima di proseguire.

A `0x15D628`, viene cancellata **`0x61 << 7 = 0x3080`**, proprio l'unione dei tre bit appena attesi. All'interno della maschera finale resta `0xF00`. Il codice avvia poi ulteriori stadi. Questo azzeramento intermedio impedisce di modellare il task come una singola attesa finale senza fasi.

Un chiamante di inizializzazione distinto, `0x15F0F0`, cancella invece tutti i bit dell'evento usando r1=`0xFFFFFFFF` nel delay slot. Non è dimostrato che tale inizializzazione venga rieseguita a ogni lavoro.

## 4. Altre callback di notifica decodificate

Oltre alle callback `0x24448C/494 → 0x80/0x100` già collegate al dispositivo, sono decodificati questi stub:

| Stub | Evento | Maschera | Preparazione finale |
|---|---|---|---|
| `0x2444A0` | `0x08200011` | `0x800` | bit11 nel delay slot `0x2444A8` |
| `0x2444CC` | stesso | `0x1000` | bit12 nel delay slot `0x2444D6` |
| `0x2444D8` | stesso | `0x2000` | bit13 nel delay slot `0x2444E2` |

Gli stub saltano al servizio di segnalazione `0x158CBC`. La loro esistenza non completa le catene di registrazione e le cause hardware: queste sono il prossimo punto d'indagine. I bit `0x200/0x400` hanno già produttori software concreti; non si presume che siano esclusivamente indicatori hardware.

## Evidenze e limiti

[Script](../Python_Trace_Scripts/s33_trace_event_protocol_masks.py), [JSON](../Ghidra_Results/ghidra_reports/event_protocol_masks/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/event_protocol_masks/gnu_verified.txt).

Riproduzione: `python3 Python_Trace_Scripts/s33_trace_event_protocol_masks.py`.

Verificati **16 hash, roundtrip blocco00, 13 finestre, 25 collegamenti, 40 istruzioni chiave e 7 pool**. Un interprete limitato alle sequenze rettilinee decodificate ricostruisce anche i delay slot e le chiamate set/clear: **768 casi**, sei sequenze per tutti i 128 sottoinsiemi della maschera finale, preservando bit esterni durante le operazioni parziali. Non esegue i dispositivi o lo scheduler.

Non sono risolti globalmente gli altri scrittori, le corse fra segnalazioni, la modalità realmente attiva, l'ultimo uso fisico del buffer o il salvataggio JPEG. Prossimo: catene di registrazione delle callback `0x2444A0/CC/D8` e servizi `0x24A6CC/0x24B230/0x24BA5C`, per associare i bit agli stadi effettivamente avviati e a quelli saltati.


## Continuazione — catene callback risolte

Il [rapporto sui tre stadi](S33_Tre_Stadi_Callback_Configurazione_e_Dispatch.md) collega gli stub `0x2444A0/CC/D8` alle configurazioni, ai gestori e al registrar ID600C/B/A. Ricostruiti stati1→2→3, tabella e test MMIO locali; restano aperti nomi fisici, vettore CPU della modalità e prova runtime.
