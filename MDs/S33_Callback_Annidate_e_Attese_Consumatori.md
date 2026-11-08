# S33 — callback annidate e attese dei consumatori

Analisi statica V1.1, 19 ottobre 2026. Continuazione delle [notifiche dispositivo](S33_Notifiche_Dispositivo_e_Attesa_Evento.md). Nessun accesso hardware.

## Risultato

Risolti i produttori delle callback opzionali del dispositivo: **`0x295EAC`** installa `0x24A3D0/0x24A428` nelle celle `0x36C390/394`. Queste callback aggiornano uno stato di libreria e possono invocare altre funzioni ricevute in configurazione.

Nel ramo normale verificato, l'invio scrive **stato2**, poi la callback del dispositivo riporta lo stesso campo a **stato1**. Il task consumatore attende però **evento `0x08200011`, maschera `0x3F80`**, distinto dall'evento dispositivo `0x03F00002`. Il collegamento tramite la callback configurata resta da chiudere: non viene ancora dichiarato sicuro il riuso del buffer. Circa 10% funzionale invariato.

## 1. Installazione delle due callback opzionali

`0x295EAC` riceve due puntatori e usa la base `0x36C340`:

| Sorgente | Destinazione | Istruzione |
|---|---|---|
| r0 | base+`0x50` = `0x36C390` | store a `0x295EAE` |
| r1 | base+`0x54` = `0x36C394` | store nel delay slot del ritorno a `0x295EB2` |

Il secondo store avviene prima del ritorno al chiamante: ometterlo darebbe una ricostruzione incompleta del setter.

Due chiamanti verificati:

- `0x24815E`: primo puntatore **`0x24A3D0`**, secondo zero;
- `0x2482F6`: primo **`0x24A3D0`**, secondo **`0x24A428`**.

Questi indirizzi provengono dai pool `0x24833C/35C`. La callback della cella `0x36C390`, già chiamata dall'handler `0x29615C` dopo la segnalazione dell'evento dispositivo, ha quindi un produttore concreto.

## 2. Secondo livello di callback e configurazione

Le routine di configurazione copiano due campi dell'oggetto in ingresso nel controllo della libreria **`S=0x36AD84`**:

| Campo in ingresso | Cella della libreria | Utilizzo |
|---|---|---|
| +`0xC4` (196 byte) | S+`0x34` = `0x36ADB8` | callback invocata da `0x24A3D0`, se nonzero |
| +`0xC8` (200 byte), nel secondo percorso | S+`0x38` = `0x36ADBC` | callback invocata da `0x24A428`, sotto ulteriori guardie |

`0x24A3D0` prepara un argomento halfword in base allo stato e ai record di libreria, quindi legge S+`0x34` e chiama indirettamente la funzione a `0x24A420`. Non si presume che la callback sia sempre presente.

`0x24A428` usa S+`0x38`, prepara l'argomento nel delay slot a `0x24A458` e chiama solo nei rami ammessi. Le identità concrete dei due puntatori ricevuti dall'input +`0xC4/C8` restano da ricostruire.

La catena statica ora è:

```text
handler dispositivo → cella0x36C390 → 0x24A3D0
→ aggiornamenti della libreria → callback configurata in0x36ADB8
```

Non viene ancora completata con l'evento del task senza risolvere l'ultimo puntatore.

## 3. Stato2 all'invio e stato1 nella callback

Nel percorso di invio già seguito, **`0x24882E/830`** prepara 2 e lo scrive a **S+8**, prima della chiamata di attivazione.

In `0x24A3D0`, quando S+`0x1C` è zero, il tratto **`0x24A3F8/3FA`** scrive 1 a **S+8**. Questa transizione collega l'invio alla notifica attraverso la callback installata. Gli altri rami coordinano anche flag di più notifiche e possono scrivere S+4 oltre a S+8.

Sono **stati software osservati**. Il nome «pronto», il significato del dato halfword passato alla callback e la validità di questa transizione per ogni modalità richiedono ancora gli invarianti dei chiamanti. Non si deduce dalla sola scrittura1 che ogni precedente accesso fisico al buffer sia terminato.

## 4. Chiamanti dell'attesa dispositivo

Sono verificati tre siti che chiamano `0x2956F0`, wrapper dell'attesa già studiata:

| Sito | Comportamento osservato |
|---|---|
| `0x249D1A` | attesa condizionata a un temporaneo positivo dentro un ciclo di elaborazione |
| `0x24A230` | per stato2, attende e torna al tratto che azzera uno stato/flag e chiama i servizi successivi |
| `0x24A3B0` | per stato2, attende, copia 32 byte e pubblica stato1 |

Nel terzo caso, il campo di stato è letto a **S+4+4*indice**. Dopo l'attesa, il codice costruisce la sorgente **`0x50C134+32*indice+4`**, copia 32 byte verso il puntatore ricevuto e scrive 1 al campo di stato. Non confronta localmente il ritorno del wrapper prima della copia o della pubblicazione.

Il wrapper restituisce zero nel proprio delay slot, come già provato. Questi chiamanti non aggiungono una verifica che ripristini l'esito originario dell'attesa. La loro continuità di esecuzione non costituisce da sola una prova dell'evento effettivamente osservato.

## 5. Evento del task e azzeramento dello slot

Il task consumatore, a **`0x15D8DA`**, chiama l'API d'attesa con:

```text
evento = 0x08200011
maschera = 0x7F << 7 = 0x3F80
r2 = 1, r3 = 0
```

Questa coppia è distinta da quella emessa direttamente dall'handler dispositivo. Nel tratto locale successivo non compare un confronto del ritorno dell'attesa prima di continuare con callback e altri rami. Più avanti si trovano gli azzeramenti dei flag degli slot già documentati a `0x15DAD8..DB28`, sotto le loro guardie.

Non si conclude che ogni percorso di azzeramento dipenda con successo dall'attesa dispositivo. Restano da risolvere le callback configurate, la produzione dei bit di `0x08200011`, le condizioni intermedie e gli eventuali percorsi alternativi.

## Evidenze e continuazione

[Script](../Python_Trace_Scripts/s33_trace_device_callback_bridge.py), [JSON](../Ghidra_Results/ghidra_reports/device_callback_bridge/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/device_callback_bridge/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_device_callback_bridge.py`.

Verificati **16 SHA-256, roundtrip ELF del blocco00, 11 finestre, 7 collegamenti diretti, 34 istruzioni chiave e 11 pool**, oltre agli alias delle celle callback e all'aritmetica della maschera evento. Nessuna attesa o callback è stata eseguita sulla fotocamera.

Prossimo: produttori dell'input +`0xC4/C8` e segnalazioni dell'evento `0x08200011`, per completare il ponte fra notifica del dispositivo e task consumatore. Ultimo uso fisico, risultato worker e ammissione runtime restano aperti.


## Continuazione — identità delle callback risolte

Il [rapporto sul ponte dispositivo→task](S33_Ponte_Notifica_Dispositivo_Evento_Task.md) risolve il punto lasciato aperto qui: `0x243ECC` installa `0x24448C/0x244494` nell’input concreto `0x44519C+C4/C8`. Queste segnalano `0x08200011/0x80` e `0x08200011/0x100`, entrambe incluse nella maschera del task `0x3F80`. Restano aperte la semantica delle opzioni d’attesa e la prova del rilascio sicuro in ogni percorso. Le frasi precedenti sul ponte aperto descrivono il checkpoint antecedente a questa continuazione.
