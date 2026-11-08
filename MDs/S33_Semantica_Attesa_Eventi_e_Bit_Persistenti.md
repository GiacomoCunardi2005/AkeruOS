# S33 — semantica dell'attesa e persistenza dei bit evento

Analisi statica V1.1, 19 ottobre 2026. Continuazione del [ponte dispositivo→task](S33_Ponte_Notifica_Dispositivo_Evento_Task.md). Nessun accesso hardware.

## Risultato

L'opzione **r2=1 richiede tutti i bit** della maschera. Il task che attende `0x08200011/0x3F80` richiede quindi i sette bit 7..13: le callback `0x24448C/494`, che producono `0x80/0x100`, non bastano né singolarmente né insieme.

La configurazione iniziale osservata disabilita la cancellazione automatica dei bit per questo evento e per quello dispositivo `0x03F00002`. I bit possono accumularsi fra segnalazioni, fino a una cancellazione esplicita o a una modifica dello stato/configurazione. Questo non dimostra un difetto: resta da ricostruire l'intero protocollo. Avanzamento funzionale AkeruOS circa 10%, invariato.

## 1. Inoltro delle opzioni e condizione all/any

`0x158D04` conserva maschera in r17, opzione r2 in r16 e quarto argomento in r14. A `0x158DB8` chiama `0x23C938`, ripristinando **r2=r16 nel delay slot** `0x158DBC`. Il trampolino inoltra a `0x2C9994`, con r4=0 nel proprio delay slot.

Il corpo inferiore legge i bit pendenti a oggetto+`0x18`:

| Opzione | Tratto | Condizione di soddisfazione |
|---|---|---|
| r2 diverso da 0 | `0x2C99E0..EA` | `(bit_pendenti & maschera) == maschera` |
| r2 uguale a 0 | `0x2C99EE..F8` | `(bit_pendenti & maschera) != 0` |

Se la condizione è falsa, il codice pubblica maschera in task+`0xC4` e imposta/cancella bit `0x80` in task+`0x6C`, conservando il tipo d'attesa. Il servizio di segnalazione `0x23C758` usa questo bit: per all confronta l'intera maschera, per any verifica un'intersezione nonzero, prima di rimuovere il waiter dalla coda.

Le predicate d'ingresso sono state eseguite da un piccolo interprete sulle istruzioni GNU effettivamente decodificate: **256 casi**, tutti i 128 sottoinsiemi di `0x3F80` per entrambe le opzioni. I casi `0x80`, `0x100` e `0x180` non soddisfano all; `0x3F80` sì. Questa è una verifica offline del tratto, non una simulazione del kernel completo.

## 2. Tabella e configurazione iniziale

Il resolver `0x158C8C` scorre record da **56 byte**, base `0x372A48`, confrontando ID a +4, magic `0x45564E4C` e bit31 di +8 per l'ammissione runtime. Nel campione sono stati letti 85 record con magic e un terminatore nullo.

| Evento | Indice | Record | Flags statici +8 | Oggetto inferiore +C | Bit pendenti, record+24 | Auto-clear, record+28 |
|---|---:|---|---:|---|---|---|
| `0x03F00002` | 19 | `0x372E70` | 2 | `0x372E7C` | `0x372E94` | `0x372E98` |
| `0x08200011` | 47 | `0x373490` | 2 | `0x37349C` | `0x3734B4` | `0x3734B8` |

Gli offset di questa tabella sono esadecimali. I flags iniziali 2 non hanno bit31 impostato: il campione statico non rappresenta un oggetto già inizializzato.

L'inizializzatore `0x158C30` ricava il solo bit0 dei flags con `bmsk_s r14,r14,0`, quindi passa tale valore a `0x23C674`. Questo azzera oggetto+`0x18` e memorizza l'opzione auto-clear a oggetto+`0x1C` nel delay slot `0x23C6A0`. Per flags2, auto-clear=0. L'inizializzatore superiore imposta bit31 solo dopo il ritorno ammesso.

## 3. Segnalazione, cancellazione e accumulo

- `0x158CBC → 0x23C758`: OR fra bit correnti e maschera segnalata, poi verifica dei waiter. Lo stato risultante viene scritto a oggetto+`0x18`.
- Se auto-clear bit0 è impostato, il ramo di risveglio cancella la maschera richiesta del waiter (`0x23C862/866`); il percorso di successo immediato dell'attesa fa lo stesso a `0x2C99FC..9A04`.
- Con auto-clear=0, questi rami non cancellano i bit.
- `0x158CE0 → 0x23C8AC` offre invece cancellazione esplicita: `bit_pendenti &= ~maschera` a `0x23C8CC..D0`.

Per la configurazione iniziale verificata, le due notifiche possono quindi restare presenti e combinarsi con altre. Non si conclude che rappresentino lo stesso frame/lavoro: occorre identificare chi cancella l'evento e in quale fase.

## 4. Quarto argomento zero ed esito

Nel task r3=0 salta la costruzione del termine temporale e diventa r3=0 nel servizio inferiore. Se i bit mancano, il ramo `0x2C9A6E → 0x2C9AC2` chiama `0xB2C74`, senza un timeout locale costruito da questo wrapper. Non si assegna una durata reale senza ricostruire lo scheduler.

Il wrapper salva il ritorno inferiore, esegue diagnostica e traduzione errori, quindi ritorna un esito: non è universalmente una funzione a ritorno zero. Il task a `0x15D8E0` carica subito controllo+`0xD4`, sovrascrivendo r0 senza confronto locale dell'esito. La presenza del ponte callback/evento non prova quindi da sola il successo dell'attesa o il termine di ogni uso hardware.

## Evidenze e prossimo passo

[Script](../Python_Trace_Scripts/s33_trace_event_wait_semantics.py), [JSON](../Ghidra_Results/ghidra_reports/event_wait_semantics/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/event_wait_semantics/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_event_wait_semantics.py`.

Verificati **16 hash, roundtrip blocco00, 10 finestre, 8 collegamenti, 33 istruzioni chiave, 4 pool, 2 record evento e 256 predicate decodificate**. Altri scrittori runtime dei flags non sono stati esclusi globalmente.

Prossimo: cercare i produttori dei cinque bit rimanenti (`0x200/400/800/1000/2000`) e i chiamanti della cancellazione esplicita su `0x08200011`; collegare poi questo protocollo alle guardie di rilascio degli slot.


## Continuazione — produttori e azzeramenti individuati

Il [rapporto sul protocollo evento](S33_Protocollo_Evento_Task_Azzeramenti_e_Bypass.md) risolve produttori software dei cinque bit rimanenti e azzeramenti `0x3980/0x3080`; mostra anche un ramo che preimposta l’intera maschera. Il requisito all è verificato, ma i bit non sono tutti necessariamente nuove notifiche hardware. Restano da chiudere le catene delle callback e il protocollo temporale completo.

## Continuazione — switch e scansione dei waiter

Il [rapporto attesa/switch](S33_Attesa_Task_Switch_e_Risveglio.md) segue il ramo senza termine fino a salvataggio, rimozione dalla lista pronta, reinserimento e ripresa. Aggiunge8predicate limite con maschera0 e due scenari con più waiter: auto-clear1 termina la scansione dopo il primo soddisfatto, mentre auto-clear0 può risvegliarli entrambi nel caso verificato. I256casi precedenti restano un'evidenza distinta; nessuna prova di risveglio immediato o esito fisico dell'operazione.
