# S33 — ingresso MMIO del tasto 2 e coda degli eventi

Analisi statica del 18 ottobre 2026 sul firmware V1.1. Nessuna lettura del dispositivo o esecuzione del firmware. Continuazione dei [marcatori S2](S33_S2_Marcatori_e_PTP_Vendor.md). Le associazioni seguenti sono percorsi condizionali del codice; non sono una misura del pulsante sulla V1.0.

## Risultato

È stata ricostruita una catena da un registro di ingresso fino al tasto logico 2 e alla coda elaborata da WindowMgr. Il tasto 2 genera gli ID interni `0x100` e `0x101`, compatibili con l'handler CaptureLiveview che contiene il marcatore S2. Registrazione, filtri, oggetto corrente e condizioni di stato possono interrompere la catena.

```text
registro 0x0FF04024, bit 0
  → lettura 0x17B5EC
  → stato software 0x3678C1 e callback 0x16E9E8 / 0x16EAAC
  → 0x16F72C, tasto logico 2
  → evento 0x100 oppure 0x101
  → filtri 0x16F6B0
  → coda 0x17BC7C / 0x17BD4C
  → WindowMgr 0x15AF0C
  → 0x169E1C → 0x169D78
  → callback dell'oggetto selezionato
```

## 1. Lettura del livello e registrazione della callback

`0x17B5EC` carica il letterale `0x17B5F4 = 0x0FF04024`, esegue `ldh.di` a `0x17B5F8` e conserva il bit 0. La routine termina attraverso l'epilogo comune `0x17B4C0`, che non modifica `r0`. La compagna `0x17B5D4` legge invece `0x0FF04020`, bit 15, nel percorso del tasto 1.

L'inizializzazione `0x16E838` registra, nel tratto `0x16E8AA..0x16E8B0`, **ID `0xFFFF800D`, callback `0x16E9E8`**, tramite `0x16D898`. Legge poi `0x17B5EC`, conserva il livello nel byte `0x3678C1` e chiama `0x16F72C(255,2,livello,0)`: lo zero finale aggiorna lo stato senza abilitare l'emissione di questo percorso.

Il ramo `0x8000` del registrar passa a `0x266444`. Quest'ultimo cerca l'ID nella tabella `0x424F00` e scrive la callback nel campo +4 della riga corrispondente. Il campione originale contiene:

| Indirizzo | Contenuto |
|---|---|
| `0x424F00` | registro pending `0x0FEF0048` |
| `0x424F04` | registro di abilitazione `0x0FEF0324` |
| `0x424F08` | conteggio 16 |
| `0x424F24` | ID `0x800D`, indice pending 12, indice abilitazione 12 |
| `0x424F28` | callback inizialmente nulla, popolata dalla registrazione |

Il gestore `0x266484` percorre questa tabella. A `0x2664A4..0x2664CC` controlla i due bit; a `0x2664DC` invoca la callback non nulla; a `0x2664EE` scrive il bit pending dopo il ritorno. Questo ricostruisce il backend della registrazione; il vettore CPU che entra nel gestore e l'effettiva abilitazione a runtime restano da seguire.

Le denominazioni pending/abilitazione derivano dall'uso dei bit nel codice. Non è stato attribuito un nome di periferica da un datasheet né identificato un piedino fisico.

## 2. Stato immediato e verifica differita

La callback `0x16E9E8`:

1. Passa `0xFFFF800D` a `0x16D840`.
2. Registra `0x16EAAC` tramite `0x145F28`, con campo timer nel contesto+48, valore letto da `0x16E9E4` e argomento 1. `0x145F28` conserva la callback nella propria struttura timer; non è stato attribuito un intervallo fisico al valore.
3. Legge il byte contesto+41, cioè `0x3678C1`, e lo porta a 0 se era 1, altrimenti a 1.
4. Chiama `0x16F72C(255,2,nuovo_stato,1)` a `0x16EA2A`.

La callback differita `0x16EAAC` legge il livello hardware tramite `0x17B5EC`. Se differisce dallo stato software, aggiorna **lo stesso byte `0x3678C1`** e invia il livello appena letto mediante `0x16F72C(255,2,livello,1)` a `0x16EAD4`. Poi chiama `0x14605C` con il campo timer e `0x16D7E8` con `0xFFFF800D`.

**Inferenza:** la sequenza è compatibile con una gestione immediata del fronte seguita da correzione/verifica del livello. Il solo codice non determina polarità del pulsante, durata del filtro, numero di transizioni reali o comportamento sotto rimbalzo. Non bisogna descrivere `r2` come il vecchio livello: le due callback lo leggono dopo aver aggiornato il byte.

Gli accessi ARC `.as` sono scalati: il caricamento a `0x16EAB6` legge il letterale a `(PC allineato) - 160*4 = 0x16E834`, contenente `0x367898`. Quindi contesto+41 = `0x3678C1`. Il commento non scalato di objdump indica erroneamente `0x16EA14` e non è stato usato come indirizzo del letterale.

## 3. Costruzione dell'evento e condizioni di emissione

`0x16F72C` aggiorna una tabella di stato a `0x446808 + 4*tasto`. Se il quarto argomento è zero, ritorna senza emettere. Per il percorso ordinario con tasto minore di `0x61`:

| Stato passato | Formula | Tasto 1 | Tasto 2 |
|---|---|---:|---:|
| nonzero | `tasto << 7` | `0x80` | `0x100` |
| zero | `(tasto << 7) | 1` | `0x81` | `0x101` |

Questo è un mapping del valore software, non una misura di premuto/rilasciato. La routine controlla anche eventi già in coda tramite `0x17C150` e può annullare l'emissione; per il tasto 2 esiste un ulteriore controllo su una sequenza di otto ID.

Passa quindi tasto, stato, ID e flag a `0x16F6B0`. Quest'ultima percorre fino a dieci callback, passando l'indirizzo dell'ID locale: gli hook possono modificarlo e/o interrompere l'inoltro. Sono controllati inoltre il byte globale `0x3678F9`, il flag di emissione e il bit di abilitazione della voce del tasto. Soltanto il ramo che supera questi controlli chiama `0x17BC7C(0,ID,argomento,1)` a `0x16F71E`.

## 4. Coda e destinatario effettivo

`0x17BC7C` usa un ring con indici modulo 128 a `0x367BBC` e record da 12 byte a `0x47A848`:

| Offset record | Campo |
|---:|---|
| +0 | destinatario a 32 bit |
| +4 | ID a 16 bit |
| +6 | padding, nessuna semantica attribuita |
| +8 | argomento a 32 bit |

Se il ring è pieno il produttore non scrive il record e restituisce zero. `0x17BD4C` estrae lo stesso layout. Il task **WindowMgr** a `0x15AF0C` estrae record a `0x15AF2E` e li inoltra a `0x169E1C` a `0x15AF42`.

Per un ID come `0x100` con destinatario zero, `0x169E1C` ottiene l'oggetto corrente tramite `0x1453F4`, poi passa a `0x169D78`. Quest'ultimo sceglie il wrapper di default `0x16A6E4`. Il wrapper può inoltrare a un altro oggetto o consumare l'evento secondo flag e stato; il ramo finale arriva a `0x16A028`, che ottiene e invoca la callback dell'oggetto. Non è garantito che l'oggetto corrente sia CaptureLiveview in ogni modalità.

Se viene selezionato CaptureLiveview e superati i filtri già documentati, la tabella associa `0x100 → 0x654CD4`; un ramo di questo handler emette `S2 event`.

## 5. Selezione di CaptureImage per indice

Il legame dati precedente è ora più preciso: `0x23D278` passa **tabella `0x3F5900`, conteggio `0xC5` (197)** a `0x145018`. Quest'ultima scrive puntatore e conteggio nel contesto del resolver `0x14507C`. La tabella originale contiene:

| Indice | Voce | Oggetto |
|---:|---:|---|
| 1 | `0x3F5904 → 0x7833CC` | CaptureLiveview |
| 4 | `0x3F5910 → 0x783D54` | CaptureImage |

Nel ramo finale dell'handler `0x654CD4`, il sito **`0x654FC0` chiama `0x1453E4(4, byte[contesto_liveview+59])`**. Il wrapper risolve l'indice 4 e chiama `0x145180`. Con questa registrazione attiva, il destinatario risolto è dunque CaptureImage, non più un'associazione dedotta dalla sola vicinanza della tabella.

La [continuazione sullo stato](S33_S2_Stato_CaptureImage.md) risolve il byte a `0x681EAF`, il produttore `0x0CBAF0` e il caso che vi scrive `0x0A`; segue inoltre la copia nello stato CaptureImage tramite `0x4401` e l'ingresso successivo `0x4405`. La presenza di questa catena condizionale non prova uno scatto incondizionato né il salvataggio riuscito.

## Evidenza conservata

Lo [script esistente](../Python_Trace_Scripts/s33_trace_recorder_dispatch.py) verifica i nuovi letterali, le istruzioni di lettura, l'alias del byte di stato, header/riga del backend IRQ e la registrazione della tabella oggetti. Legge e verifica i 16 blocchi, ricrea ELF con roundtrip identico e conserva **81 finestre** nel [disassemblaggio](../Ghidra_Results/ghidra_reports/s33_recorder_dispatch_disassembly.txt). Il campo `s2_input_path` del [JSON](../Ghidra_Results/ghidra_reports/s33_recorder_dispatch.json) riassume la catena. I controlli non simulano interrupt, task o hardware.

Prossimi confini: semantica dei discriminanti che selezionano lo stato `0x0A` e contratto della richiesta CaptureImage; ingresso del vettore CPU e abilitazione del backend; selezione dell'oggetto corrente; polarità e corrispondenza con il pulsante fisico sulla V1.0. Avanzamento complessivo invariato: circa 10%.
