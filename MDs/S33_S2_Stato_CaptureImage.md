# S33 — origine dello stato di CaptureImage nel percorso S2

Analisi statica del 18 ottobre 2026 sul campione V1.1. Nessuna comunicazione con la fotocamera V1.0, nessuna esecuzione o modifica del firmware. Continuazione del [percorso MMIO e coda eventi](S33_S2_MMIO_e_Coda_Eventi.md).

## Risultato

Aggiornamento: il [rapporto sui discriminanti e la preparazione](S33_Liveview_Discriminanti_e_Preparazione.md) individua i setter dei tre byte e chiarisce il ritorno ordinario zero di `0x1B9AA8`. Verifica anche il ramo locale stato 0/modo `0x2C` verso `0x65F378`: il percorso `0x0A` descritto sotto è una variante, non un requisito generale della fotografia normale.

Il byte che CaptureLiveview passa a CaptureImage è ora risolto: **contesto `0x681E74` + 59 = `0x681EAF`**. L'evento S2 esaminato non costruisce questo valore: lo legge da uno stato preparato in precedenza.

È stata identificata la routine che lo popola, **`0x0CBAF0`**, e il ramo che vi scrive **`0x0A`**. È inoltre verificato il raccordo con la scrittura dello stato CaptureImage a **`0x68200D`**, che seleziona un percorso verso CapMgr. Il collegamento rimane condizionale: hook, flag, modalità, controlli precedenti e sincronizzazione possono impedire l'esecuzione.

**Avanzamento orientativo verso il firmware essenziale: circa 10%, invariato.** È un avanzamento nella ricostruzione del protocollo originale, non un'applicazione nuova collaudata sul dispositivo.

## 1. Dove viene preparato il byte

La tabella originale CaptureLiveview contiene **`0x4405 → 0x652794`**, alla voce `0x7833F4`. L'handler carica `r15 = 0x681E74` dal letterale `0x65273C` a `0x6527B6`.

Nel tratto che raggiunge `0x652980`:

| Sito | Dato preparato |
|---|---|
| `0x652980..0x652984` | Ritorno di `0x0CA310`, conservato in `r20` |
| `0x652986..0x65298C` | Ritorno di `0x0CA38C(1)`, passato come secondo argomento |
| `0x65298E` | `r3 = r15 + 59`, cioè puntatore al byte `0x681EAF` |
| `0x652992` | Primo argomento ripreso da `r20` |
| `0x652994` | Terzo argomento zero |
| `0x652996` | Chiamata `0x0CBAF0(primo, secondo, 0, &byte_stato)` |

Un secondo chiamante, nel percorso che inizia a `0x654FE8`, carica lo stesso contesto in `r13` attraverso `0x65537C`. A `0x6556F2` prepara `r3 = r13+59` e a `0x6556F6` chiama nuovamente `0x0CBAF0`. Il primo e terzo argomento di questo secondo percorso provengono dal frame e non sono qui attribuiti interamente.

Questi sono due produttori verificati tramite lo stesso helper, non una ricerca esaustiva di tutti gli scrittori. Un altro tratto già individuato, `0x65390A..0x65390C`, usa il puntatore diretto `0x681EAF` per una scrittura distinta; durata e mutazioni dello stato devono essere considerate nel riuso.

## 2. Come viene prodotto `0x0A`

`0x0CBAF0` conserva il puntatore di uscita in `r13` e inizialmente vi scrive zero. Può poi scegliere stati speciali secondo il valore restituito da `0x0CAD30` e altri servizi; in seguito esamina il primo argomento e il ritorno del predicato `0x0D08EC`.

Nel ramo che non ha già selezionato un caso speciale, con primo argomento diverso da 1 e 2 e predicato nullo, il secondo argomento nell'intervallo 2–9 indicizza una tabella di **otto byte signed** a `0x0CBBB4`:

```text
indice = secondo_argomento - 2
destinazione = 0x0CBBB4 + 2 * int8(tabella[indice])
```

| Secondo argomento | Byte signed | Destinazione | Stato scritto |
|---:|---:|---|---:|
| 2 | 10 | `0x0CBBC8` | `0x0A` |
| 3 | 13 | `0x0CBBCE` | `0x0B` |
| 4 | −20 | `0x0CBB8C` | `0x01` |
| 5 | 4 | `0x0CBBBC` | `0x09` |
| 6 | 7 | `0x0CBBC2` | `0x02` |
| 7 | 16 | `0x0CBBD4` | `0x0C` |
| 8 | 19 | `0x0CBBDA` | `0x0D` |
| 9 | 24 | `0x0CBBE4` | `0x0E` |

Il caso 8 aggiorna anche un altro registro prima della scrittura del byte. Per lo stato richiesto, **`0x0CBBC8` prepara 10 e `0x0CBBCA` lo scrive attraverso il puntatore di uscita**. Il byte negativo `EC` è essenziale: interpretare tutti gli elementi come unsigned darebbe una destinazione errata per il caso 4.

Nel predicato `0x0D08EC`, un secondo argomento non nullo conduce al ritorno zero nel CFG esaminato. Per il caso secondo argomento 2, quindi, il predicato non impone un ulteriore risultato nonzero da escludere. La chiamata esegue comunque un servizio precedente: questa osservazione sul ritorno non autorizza a rimuoverla.

### Discriminanti del primo produttore

I getter chiamati dal primo percorso sono ora risolti nei loro accessi:

- `0x0CA310` legge il byte **`0x365751`**.
- `0x0CAD30` legge il byte **`0xC8E80C`** tramite un letterale PC-relative scalato.
- `0x0CA38C(1)` restituisce il byte **`0xC8EB06`** se il codice letto da `0x0CAD30` è 4 oppure `0x0A`; altrimenti restituisce zero.

Una combinazione coerente con il ramo che scrive lo stato `0x0A` è dunque: codice di modalità 4 oppure `0x0A` nelle letture rilevanti, byte `0xC8EB06 == 2`, primo discriminante diverso da 1 e 2, nessun ramo speciale precedente. Non è una misura della configurazione reale. Le letture ripetute e le possibili modifiche concorrenti non sono simulate; le etichette utente di questi valori non sono ancora attribuite.

Il **codice di modalità `0x0A`** e lo **stato CaptureImage `0x0A`** appartengono a domini distinti: l'uguaglianza numerica non prova che siano la stessa enumerazione.

## 3. Dalla lettura S2 allo stato di CaptureImage

Il contesto letto dall'handler S2 `0x654CD4` è stato verificato su un caricamento che il commento non scalato di objdump rappresentava in modo fuorviante:

```text
0x654D28: ld.as r14,[pcl,-135]
letterale effettivo = (PC & ~3) - 135*4 = 0x654B0C
[0x654B0C] = 0x681E74
```

Nel ramo che supera i controlli dell'handler:

```text
0x654FBA: r1 = byte[0x681E74+59]
0x654FBE: r0 = 4
0x654FC0: chiama 0x1453E4(4, stato)
```

Con la registrazione originale della tabella oggetti, indice 4 risolve il descrittore **CaptureImage `0x783D54`**, tramite la voce `0x3F5910`. Il wrapper `0x1453E4` conserva il secondo argomento durante la risoluzione e passa a `0x145180`.

La transizione conserva lo stato originale in `r16`. Nel ramo a `0x1452E4`, invia **evento `0x4401`** al nuovo oggetto con `r2=r16` nello slot di ritardo. Il dispatcher e i wrapper precedentemente verificati portano alla callback CaptureImage e alla tabella che associa **`0x4401 → 0x65ED38`**. L'handler scrive il byte basso di `r2` a **`0x68200D`** a `0x65ED4E`, poi chiama un ulteriore servizio originale.

Successivamente, nel ramo che raggiunge `0x145310`, la transizione invia **`0x4405`**, associato a **`0x65ED6C`**. Questa seconda chiamata ha un argomento derivato dagli oggetti, diverso dallo stato passato a `0x4401`: il protocollo usa due fasi e non va ridotto a una singola chiamata diretta.

## 4. Il raccordo con CapMgr è condizionale

Nell'handler CaptureImage, `0x65F200..0x65F204` legge il byte di contesto `0x681FF0+0x1D = 0x68200D` e richiede che valga `0x0A` per proseguire nel ramo esaminato. Poi prepara dati, chiama `0x1B9AA8` e ne richiede il ritorno zero prima di arrivare al marcatore `Recorder Capture Image Start` a `0x65F230` e alla chiamata **`0x65F262 → 0x1B9EA8`**.

La verifica successiva mostra che `0x1B9AA8` restituisce zero se i suoi servizi ritornano normalmente rispettando l'ABI originale; non propaga i loro esiti. La preparazione conserva effetti ancora da attribuire e non va eliminata.

La catena statica ora collegata è:

```text
ingresso di CaptureLiveview
  → 0x0CBAF0 scrive lo stato preparato in 0x681EAF
evento interno 0x100, nel ramo S2 di CaptureLiveview
  → legge 0x681EAF e seleziona CaptureImage per indice 4
  → transizione 0x4401: copia lo stato a 0x68200D
  → transizione 0x4405: entra nell'handler CaptureImage
  → se stato 0x0A e altri controlli superati, raggiunge 0x1B9EA8
  → percorso di acquisizione/CapMgr già ricostruito
```

Questo chiude il precedente vuoto sulla provenienza dello stato, senza provare uno scatto incondizionato. Il percorso MMIO → tasto logico 2 → coda → oggetto corrente resta soggetto ai filtri già documentati. Il nome del pulsante fisico, la polarità, il comportamento V1.0 e il successo di codifica/scrittura/chiusura restano requisiti separati.

## Evidenza riproducibile

Lo [script](../Python_Trace_Scripts/s33_trace_liveview_state.py), eseguito con `python3 s33_trace_liveview_state.py`, verifica hash e dimensioni dei **16 blocchi**, letterali e accessi selezionati, associazioni delle tabelle, gli **otto casi signed** e le chiamate del raccordo. Gli ELF 00/02 hanno roundtrip identico ai payload originali. Conserva **17 finestre GNU ARC700** nel [disassemblaggio](../Ghidra_Results/ghidra_reports/liveview_state/gnu_verified.txt) e hash, indirizzi e limiti nel [JSON](../Ghidra_Results/ghidra_reports/liveview_state/verified_evidence.json). Esecuzione completata con codice 0.

La [continuazione della richiesta e del completamento](S33_CaptureImage_Completamento_e_ImgMgr.md) risolve l'indirizzo della cella del descrittore, l'evento `0x7CE2` e l'invio differito a ImgMgr tramite UIAux. Prossimi confini: condizioni che garantiscono buffer validi e durata dei descrittori, limiti del contatore e propagazione degli esiti fino alla chiusura. La possibilità di avviare la nuova applicazione e la procedura di recupero restano aperte.
