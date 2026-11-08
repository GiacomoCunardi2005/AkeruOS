# S33 — avvio del trasferimento e callback SD

Analisi statica V1.1, 18 ottobre 2026. Continuazione di [percorsi dati](S33_SD_Registri_Comando_e_Percorsi_Dati.md) e [rilascio](S33_Oggetto_Trasferimento_e_Rilascio.md). Nessuna esecuzione sulla fotocamera.

## Risultato

Collegato il parametro callback del servizio **`0x2C00E4`** a due slot globali e ai rispettivi consumatori. Nel ramo del primo oggetto fisso, il firmware sceglie **`0x36B364`** oppure **`0x36B3D8`**. Entrambi portano a chiamate indirette condizionate da registri MMIO; la callback SD **`0x304368`** pubblica **maschera `0x200` sull'evento `0x00E00005`**.

Si distingue quindi l'esito immediato del servizio di avvio dalla successiva notifica hardware/software. L'origine completa dell'interrupt, l'arbitraggio delle callback e la persistenza fisica restano aperti. Avanzamento funzionale orientativo: circa 10%, invariato.

## 1. Parametri conservati e ramo del primo oggetto

L'ingresso `0x2C00E4` conserva:

| Argomento | Uso nel tratto esaminato |
|---|---|
| r0 | Puntatore all'oggetto, conservato in r14 |
| r1 | Indirizzo del buffer, conservato in r18 |
| r2 | Callback, conservata in r17 |
| r3 | Puntatore a un'uscita byte, conservato in r16 |
| r4 | Quantità selezionata; se zero viene letta da oggetto+`0x0C` e conservata in r15 |

Il primo confronto riconosce **`0x512C5C`**. Il codice di questo ramo usa anche campo oggetto+8 e selettore oggetto+4. Non si attribuiscono unità universali al campo +8 né al conteggio senza il contratto completo dell'allocatore.

Nel tratto `0x2C0130..0x2C019E`, un confronto fra la quantità e campo +8, oppure il selettore **`0x10209`**, decide quale preparazione e setter usare. Il report conserva questa decisione come confronto e ramo macchina, senza imporre un'interpretazione fisica della soglia.

## 2. I due setter della callback

| Sito nel servizio | Setter | Slot scritto |
|---|---|---|
| `0x2C018C` | `0x268BC4` | `0x36B3D8` |
| `0x2C019E` | `0x267170` | `0x36B364` |

Entrambi i setter sono piccoli leaf: caricano il rispettivo indirizzo dal pool e salvano la parola ricevuta. Il delay slot dell'istruzione di ritorno contiene lo store, verificato nel disassemblaggio.

Prima della chiamata al servizio **`0x266FC8`**, la callback è quindi già pubblicata in uno dei due slot. A `0x2C01D2` il servizio riceve buffer, quantità e parametri 1/0; il suo risultato viene conservato in r17 nel delay slot del ramo e confrontato. Un risultato nonzero devia all'uscita `0x2C0656`, che ripristina la sezione critica e restituisce lo stato conservato.

Un ritorno immediato riuscito non è la prova che la callback sia già stata eseguita. Il corpo prosegue con configurazione MMIO, flag software e aggiornamenti condizionali di oggetto+8, in parte ancora da ricostruire.

## 3. Consumatore dello slot 0x36B364

Il ramo candidato del gestore a **`0x267F34`** controlla:

1. Bit 8 della halfword a **`0x0FEE0038`**: il ramo esaminato prosegue se non impostato.
2. Maschera **`0x100`** della halfword a **`0x0FEE0034`**: se presente, prosegue con le operazioni di notifica.

Il codice scrive il bit 8 nel primo registro, imposta **byte `0x36B3E4 = 1`** e scrive `0x100` nel secondo. Poi legge la callback da **`0x36B364`**; se non nulla raggiunge **`jl_s [r0]` a `0x2689F6`**.

Questa è una provenienza concreta della chiamata indiretta, collegata a un bit di stato. Non vengono dedotti da questi soli accessi il nome fisico del bit, la sorgente CPU dell'interrupt o una garanzia di persistenza SD.

## 4. Consumatore dello slot 0x36B3D8

Il tratto **`0x268A20`** legge una halfword a **`0x0FF00024`** e controlla il bit 1. Nel ramo attivo imposta il bit 8 a **`0x0FF00028`**, legge la callback da **`0x36B3D8`** e la invoca a **`0x268A50`** se non nulla. Dopo la chiamata scrive **2** al registro `0x0FF00024`.

L'ordine è verificato: il writeback finale avviene dopo la callback nel ramo con puntatore nonnullo. La semantica hardware del writeback rimane da attribuire; non si assume automaticamente un determinato schema di riconoscimento interrupt.

## 5. Dalla callback all'evento SD

Nel percorso dati SD già ricostruito, la callback passata al servizio per il selettore zero è **`0x304368`**. Questa carica **`0x00E00005`** e raggiunge **`0x158CBC`** con maschera **512 (`0x200`)**. Il consumatore in `0x3040DC` attende sullo stesso evento, insieme ai bit d'errore pubblicati dalle altre callback.

La catena statica ora collegata è:

```text
servizio SD → 0x2C00E4 → setter → slot callback
→ condizione MMIO del gestore → chiamata indiretta
→ 0x304368 → evento 0xE00005 / bit 0x200
```

Resta condizionale che l'istanza scelta a runtime e il valore dello slot coincidano con questa costruzione: non sono state misurate invocazioni reali né esclusi aggiornamenti concorrenti dello slot. La pubblicazione del bit, il ritorno dell'attesa, la pulizia dell'oggetto e il successo del salvataggio sono passaggi distinti.

## Evidenze e prossimo passo

[Script](../Python_Trace_Scripts/s33_trace_transfer_callbacks.py), [JSON](../Ghidra_Results/ghidra_reports/transfer_callbacks/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/transfer_callbacks/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_transfer_callbacks.py`.

Verificati **16 SHA-256**, roundtrip ELF del blocco 00, **15 finestre, 5 collegamenti diretti e 25 istruzioni chiave**, oltre ai pool degli slot e registri. I collegamenti indiretti sono ricostruiti mediante setter, celle e consumatori, senza presentarli come esecuzione osservata.

Prossimo: corpo completo di `0x266FC8`, registrazione CPU dei due gestori, arbitraggio delle callback e copertura dei rami con avanzamento parziale/errore prima del riuso del buffer.

## Continuazione sulle registrazioni dei gestori

Il [rapporto registrazione/buffer](S33_Registrazione_Gestori_e_Buffer_Trasferimento.md) risolve i due registratori, la voce `0x0402` e un dispatcher condizionato da due letture MMIO. Distingue lo slot dedicato `0x2001`, il cui consumatore resta aperto. Origine dei vettori CPU e consegna runtime non sono ancora provate.

## Continuazione — avvio receive e notifica originali

[S33_Dumper_RAM_SD_Avvio_Receive_Callback_e_Contatore_Originali.md](S33_Dumper_RAM_SD_Avvio_Receive_Callback_e_Contatore_Originali.md):33casi28080C/programmazione/MMIOdispatcher/callback e266E9C. Slotread36B358/35C/360 ecallbackADBC/ADC4→E00005/40o40000,distinti dal percorso write storico. Il bytefine del servizio avvio è calcolato prima della callback;getterprogress halfword×128nonvalidaownership. Evento158CBC ancora recorder e ingresso dispatcher esplicito; nessuntrasferimento fisico. Prossimo raccordare25A83C/oggetti/start/progress/callback/release e servizi evento originali. NON_INSTALLARE.
