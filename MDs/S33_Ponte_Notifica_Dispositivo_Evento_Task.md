# S33 — ponte tra notifica dispositivo ed evento del task

Analisi statica del firmware V1.1, 19 ottobre 2026. Continuazione delle [callback annidate](S33_Callback_Annidate_e_Attese_Consumatori.md). Nessun accesso hardware.

## Risultato verificato

Risolti i due puntatori di configurazione rimasti aperti: il costruttore `0x243ECC` installa **`0x24448C` e `0x244494`** nell'oggetto `0x44519C`, ai campi +`0xC4/C8`. Queste funzioni segnalano **evento `0x08200011`**, rispettivamente con maschere **`0x80` e `0x100`**. Entrambe appartengono alla maschera `0x3F80` richiesta dal task.

Il ponte software è ricostruito staticamente, sotto le condizioni di configurazione e di esecuzione dei rami già documentati. Questo risultato non prova che un singolo bit soddisfi l'attesa, né che il buffer abbia terminato ogni uso fisico. Avanzamento funzionale AkeruOS: circa 10%, invariato.

## 1. Oggetto concreto e costruttore

A `0x15EE46`, il pool `0x15F224` fornisce `0x44519C` a r13. Il chiamante richiede l'azzeramento di `0xCC` byte. A `0x15EF30` passa lo stesso oggetto al costruttore `0x243ECC`; nel percorso ammesso dopo il controllo del ritorno, lo passa a `0x248094` tramite r0 nel delay slot `0x15EF8E` della chiamata `0x15EF8A`.

Il costruttore mantiene la base in r13 e scrive la dimensione `0xCC` come halfword iniziale. Dopo `0x243E28`, il ramo `0x243F08` salta gli store delle callback se il ritorno è diverso da zero.

| Store | Valore dal pool | Campo | Cella concreta |
|---|---|---|---|
| `0x243F30` | `0x24404C → 0x24448C` | oggetto+`0xC4` | `0x445260` |
| `0x243F36` | `0x244050 → 0x244494` | oggetto+`0xC8` | `0x445264` |

La libreria copia questi campi nelle celle `0x36ADB8/BC`, già risolte nel rapporto precedente. Il secondo campo è copiato nel secondo percorso di configurazione; la sua presenza nell'oggetto non implica l'attivazione universale di quel percorso.

## 2. Callback che producono i bit del task

| Funzione | Evento caricato | Salto finale | Maschera impostata nel delay slot |
|---|---|---|---|
| `0x24448C` | pool `0x2444C8 → 0x08200011` | `0x24448E → 0x158CBC` | `0x244492`: r1=`0x80` |
| `0x244494` | stesso pool/evento | `0x244496 → 0x158CBC` | `0x24449A`: r1=`0x100` |

Entrambe sovrascrivono r0 e r1 prima di inoltrare al servizio evento: il dato passato dalla callback superiore non determina qui evento e maschera. Le istruzioni nei delay slot fanno parte delle chiamate effettive.

La catena normale condizionale diventa:

```text
stato dispositivo banca1 & 2
→ handler 0x29615C
→ callback opzionale 0x36C390 = 0x24A3D0
→ callback configurata 0x36ADB8 = 0x24448C
→ evento 0x08200011, maschera 0x80
→ evento richiesto dal task a 0x15D8DA, maschera 0x3F80
```

La variante passa da `0x2961C0 → 0x36C394 → 0x24A428 → 0x36ADBC → 0x244494`, producendo maschera `0x100`. Le guardie delle callback superiori rimangono applicabili.

## 3. Cosa resta aperto

Il task prepara `r2=1, r3=0` per l'attesa `0x158D04`. È verificato che `0x80 & 0x3F80 = 0x80` e `0x100 & 0x3F80 = 0x100`; **la semantica delle opzioni RTOS non è ancora ricostruita**. Non si attribuisce quindi a questi bit, da soli, un risveglio garantito.

Il task prosegue caricando controllo+`0xD4` senza confrontare immediatamente il ritorno dell'attesa. Più avanti azzera i flag degli slot sotto ulteriori guardie. Rimangono da provare la freschezza/consumazione dei bit, gli altri produttori della maschera e ogni percorso che autorizza il riuso del buffer. La causa fisica del bit hardware e il completamento JPEG/salvataggio non sono stabiliti da questa catena.

## Evidenze riproducibili

[Script](../Python_Trace_Scripts/s33_trace_task_event_bridge.py), [JSON](../Ghidra_Results/ghidra_reports/task_event_bridge/verified_evidence.json), [disassemblaggio GNU](../Ghidra_Results/ghidra_reports/task_event_bridge/gnu_verified.txt).

Riproduzione: `python3 Python_Trace_Scripts/s33_trace_task_event_bridge.py`.

Verificati **16 hash dei blocchi, roundtrip ELF del blocco00, 10 finestre, 8 collegamenti diretti, 30 istruzioni chiave e 8 pool**. Il JSON contiene anche gli alias dei campi e le maschere. Analisi offline: nessuna callback o attesa eseguita sulla fotocamera.

Prossimo passo: ricostruire `0x158D04` e il servizio inferiore per interpretare `r2=1`, esito e consumazione dell'evento, poi collegarli alle guardie di rilascio dello slot.


## Continuazione — opzioni d’attesa risolte

Il [rapporto sulla semantica eventi](S33_Semantica_Attesa_Eventi_e_Bit_Persistenti.md) verifica che opzione1 richiede tutti i bit di `0x3F80`. Le due callback non bastano da sole; configurazione iniziale senza auto-clear, quindi i bit possono accumularsi. Da ricostruire gli altri produttori e la cancellazione esplicita prima di attribuire freschezza o riuso sicuro.
