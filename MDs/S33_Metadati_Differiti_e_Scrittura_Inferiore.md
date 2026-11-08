# S33 — metadati differiti e confine della scrittura inferiore

Analisi statica V1.1 del 18 ottobre 2026. Continuazione delle [callback filesystem](S33_Callback_Filesystem_e_Controlli_Close.md) e degli [handle/backend](S33_Handle_Logici_e_Backend_File.md). Nessuna esecuzione sulla fotocamera.

## Risultato

Il servizio **`0x2A1054`**, raggiunto dal tratto del close già ricostruito, non esegue sempre una scrittura: un ramo imposta **contesto+`0x1AC = 1`** e restituisce zero. La routine distinta **`0x2A10F4`** legge quel flag, tenta il trasferimento e lo azzera soltanto quando il trasferimento restituisce zero.

È stato inoltre collegato il trasferimento al dispositivo sottostante: **`0x2A0C60 → 0x2A0C14 → 0x1FA090 → callback dispositivo+0x18`**. Il puntatore è letto da contesto+`0x1A4`; appartiene a uno strato inferiore rispetto alla famiglia filesystem. Il destinatario finale della callback resta da attribuire sul volume fotografico.

Questa separazione chiarisce un altro motivo per cui «aggiornamento metadati riuscito» non dimostra la persistenza SD. Non è ancora una barriera completa di chiusura o spegnimento. R2 parziale, circa 10% funzionale invariato.

## 1. Contesto e strati distinti

Il contesto privato della famiglia filesystem contiene i campi usati da questi percorsi:

| Offset | Impiego verificato nel tratto esaminato |
|---|---|
| `0x1A4` (`105*4`) | Handle del dispositivo inferiore, ricevuto e conservato dall'installatore `0x1F3554`, scrittura `0x1F35AC` |
| `0x1AC` (`107*4`) | Flag pendente nel ramo differito |
| `0x1B0` (`108*4`) | Indice/posizione passato al trasferimento selezionato |
| `0x1B4` (`109*4`) | Buffer passato allo stesso trasferimento |
| `0x3C` | Se nonzero, seleziona il differimento nel ramo con stato +`0x2C4` diverso da 2 |
| `0x350` (`212*4`) | Controlla l'emissione dei comandi sul dispositivo inferiore prima e dopo il trasferimento |

L'indice del trasferimento non viene già identificato con un indirizzo fisico di settore SD; unità e conversioni dipendono dai campi di configurazione.

## 2. Tre rami del servizio metadati

Il chiamante **`0x2AC438`** raggiunge `0x2A1054` dopo preparazioni e un'eventuale copia del record. Quest'ultimo servizio distingue:

| Condizione | Azione locale |
|---|---|
| Stato a contesto+`177*4` uguale a 2 | Usa campi alternativi e chiama `0x2A0C60` con selettore 10; conserva il risultato |
| Stato diverso da 2 e campo +`0x3C` zero | Chiama `0x2A0C60` con selettore 10; se il risultato è zero azzera il flag +`0x1AC` |
| Stato diverso da 2 e campo +`0x3C` nonzero | A `0x2A10B6` scrive 1 nel flag e a `0x2A10B8` imposta risultato zero, senza attraversare la chiamata di trasferimento di questo ramo |

Il flag deriva dall'indirizzo `contesto+372+0x38`, che coincide con **`contesto+0x1AC`**. La corrispondenza è verificata aritmeticamente e sugli accessi delle due routine.

Restano aggiornamenti condizionali delle copie di memoria e altri campi. La tabella descrive le decisioni di trasferimento nel corpo esaminato, non un sostituto completo del servizio originale.

## 3. La routine che consuma il pendente

**`0x2A10F4`** legge il campo +`0x1AC`. Se è nonzero, passa a `0x2A0C60`:

```text
r0 = contesto
r1 = 10
r2 = parola a contesto+0x1B0
r3 = 1
r4 = parola a contesto+0x1B4
```

A `0x2A1116/1A` conserva e confronta il risultato. Soltanto se zero scrive zero al flag a **`0x2A111E`**. L'uscita restituisce il risultato conservato, dopo le operazioni condizionali sulle copie interne.

È quindi individuato un protocollo concreto **segna pendente → tenta trasferimento → cancella su ritorno zero**. Non è ancora dimostrato che ogni close, errore o spegnimento attraversi il consumatore, né che il risultato zero dello strato inferiore significhi persistenza sulla scheda.

## 4. Dal selettore 10 alla callback inferiore

`0x2A0C60` conserva il selettore, l'indice, il conteggio e il buffer. Può emettere i controlli **`0x2015`** e **`0x2016`** sull'handle inferiore tramite `0x1F2348`, prima e dopo il trasferimento. Questi numeri sono distinti dai controlli filesystem `0x3015/0x3038` già studiati; non viene attribuita loro una semantica di flush senza seguire il destinatario.

Il codice prepara la posizione tramite **`0x226204`** e adatta le unità in base ai campi di configurazione. In entrambi i rami esaminati il ritorno di quella preparazione non viene confrontato prima del passaggio alla scrittura.

Per il selettore 10 raggiunge **`0x2A0C14`**. Questo helper usa il conteggio residuo e il puntatore al buffer, poi chiama **`0x1FA090`** con l'handle letto a contesto+`0x1A4`. Il servizio generico legge la prima parola dell'handle per ottenere il dispositivo e invoca **dispositivo+`0x18`**, passando gli argomenti del trasferimento.

Il puntatore della callback non è automaticamente `0x1F4958`, la scrittura del filesystem superiore: qui l'handle appartiene al dispositivo che quel filesystem usa come base. Confondere i due strati produrrebbe un ciclo di chiamate falso.

## 5. Conteggio residuo, esito e limite del tentativo

Nel corpo di `0x2A0C14`, il contatore locale permette **al più una chiamata al driver**. Dopo un ritorno diverso da −1 aggiorna conteggio residuo e puntatore; la successiva iterazione evita un secondo tentativo.

Il chiamante `0x2A0C60` distingue quindi:

- residuo non positivo: imposta risultato zero;
- residuo positivo: legge il campo errore dell'handle inferiore a +`0x0C`, poi può tradurre alcuni valori prima del ritorno.

Nel solo corpo locale non viene imposto un errore nonzero alternativo se rimane lavoro ma il campo errore dell'handle vale zero. Questo non dimostra che un driver reale restituisca quella combinazione: può essere esclusa dal suo contratto. Impedisce però di considerare il wrapper, da solo, una prova universale di trasferimento completo.

Le unità del conteggio possono cambiare secondo la configurazione. Non vengono presentate sempre come byte, blocchi SD o durata misurata.

## Evidenze e prossimo passo

[Script](../Python_Trace_Scripts/s33_trace_metadata_writes.py), [JSON](../Ghidra_Results/ghidra_reports/metadata_writes/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/metadata_writes/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_metadata_writes.py`.

Verificati **16 hash, roundtrip ELF del blocco 00, otto finestre e dieci collegamenti diretti**, inclusi consumatore del flag e passaggio al dispositivo inferiore. Nessuna simulazione o prova di scrittura hardware.

**Prossimo passo R2:** individuare il dispositivo effettivo conservato a +`0x1A4`, risolvere callback e controlli `0x2015/0x2016`, e collegare i chiamanti di `0x2A10F4` al completamento e allo spegnimento. Occorre conservare separati stato pendente, quantità trasferita, risultato close e persistenza sul supporto. Compatibilità V1.0 e recupero completo restano aperti.

## Continuazione sul destinatario inferiore

Il successivo [rapporto backend SD](S33_Dispositivo_SD_e_Completamento.md) risolve la costruzione PMSD: → DEVSD: e il controllore `0x2A1270`, con secondo pendente +`0x318`. Riduce il punto aperto sul destinatario di +`0x1A4`; restano condizionali montaggio, uso dei modi di completamento e persistenza fisica.

## Continuazione — lettore e trasferimento eseguiti

[S33_Dumper_RAM_SD_Settori_Cache_e_Trasferimento_Originale.md](S33_Dumper_RAM_SD_Settori_Cache_e_Trasferimento_Originale.md): lettore/cache28casi, trasferimento25, lookup integrato20 fino a callback dispositivo sintetica. ProdottoDSP dichiarato e driver simulato; non prova persistenza fisica o r/open/close integrati. Il rapporto distingue regressioni e limiti; nessun hardware.
