# S33 — vettori interrupt e tabella runtime

Analisi statica V1.1, 19 ottobre 2026. Continuazione di [slot runtime e gruppi SD](S33_Dispatch_Interrupt_Runtime_e_Gruppi_SD.md). Nessuna esecuzione hardware.

## Risultato

Ricostruita la catena statica che mancava fra i vettori e i dispatcher SD:

```text
int_vector_base allineato → 16 salti assoluti
→ stub con indice → ingresso comune 0xB3054
→ tabella kernel+0x238 → handler registrato
```

Il bootstrap esaminato richiede gli indici **0..15**, alloca una tabella da **192 byte**, e il generatore scrive **16 voci da 8 byte** presso la base letta dal registro CPU. Gli stub 4 e 9 raggiungono lo stesso ingresso comune, che consulta la tabella dove sono registrati i dispatcher SD già ricostruiti.

Il bootstrap richiede base vettori `0x800`, ma altri percorsi possono sostituirla o modificare le voci 4/5. Base corrente e puntatore allocato non sono stati misurati a runtime. La catena statica non prova che ogni fase sia stata eseguita sulla fotocamera o che gli interrupt risultino abilitati. Circa 10% funzionale invariato.

## 1. Creazione della tabella runtime

Nel bootstrap a **`0x29F64C`**, `0x2F6E68` riceve limite inferiore **0** e superiore **15**. Dopo il controllo di ordine dei limiti, l'inizializzatore calcola il numero inclusivo di voci e richiede **12 byte per voce** tramite **`0x268EE4`**.

Pubblica nella struttura kernel, risolta attraverso `0x369348`:

| Campo kernel | Valore/uso |
|---|---|
| +`0x224` (`137*4`) | Ingresso comune `0xB3054` |
| +`0x228` (`138*4`) | Handler predefinito `0x319018` |
| +`0x22C` | Limite inferiore ricevuto |
| +`0x230` | Limite superiore ricevuto |
| +`0x238` | Puntatore della tabella allocata |

Il ciclo inizializza campo record+0 con il gestore predefinito e record+8 con l'indice. **Il campo +4 non è scritto da questo ciclo**; il suo significato non è attribuito qui.

Nel tratto esaminato il puntatore restituito dall'allocatore viene pubblicato e usato senza un confronto locale con zero. Questo è un limite del controllo locale, non una prova di un'allocazione fallita o del contratto globale di errore dell'allocatore.

## 2. Generazione delle voci del vettore

**`0x2F6F04`** chiama **`0x29F19C`**, che legge il registro ausiliario **`int_vector_base`** e azzera i dieci bit bassi. Il codice usa quindi la base allineata a 1.024 byte.

Il generatore scrive per ciascuna delle 16 voci quattro halfword:

```text
0x2020, 0x0F80, metà alta del target, metà bassa del target
```

Incrementa la destinazione di 8 e il target di **14 (`0x0E`)**. Il primo target è **`0xB2F74`**, il successivo **`0xB2F82`**. La decodifica GNU dei byte ricostruiti dal generatore conferma un **salto assoluto `j target`** di otto byte per voce.

La decodifica sintetica è stata eseguita in un file temporaneo offline, senza installare i byte nel firmware o sulla fotocamera. Verifica la forma dell'istruzione generata; non osserva la tabella in RAM.

| Indice | Offset dalla base vettori | Stub |
|---|---|---|
| 0 | `0x00` | `0xB2F74` |
| 4 | `0x20` | `0xB2FAC` |
| 9 | `0x48` | `0xB2FF2` |
| 15 | `0x78` | `0xB3046` |

Il valore concreto della base non viene dedotto dall'offset dei payload o da un indirizzo storico di caricamento.

## 3. Stub e ingresso comune

Ciascuno stub esegue **`flag 0`**, salva il precedente r1 sullo stack e salta a **`0xB3054`**, impostando r1 al proprio indice nel delay slot. Sono verificati tutti i 16 target e indici.

L'ingresso comune riserva un frame da **164 byte** e salva stato CPU, collegamenti interrupt, registri e stato dei loop. Il codice distingue rami con **`status32_l1`/`status32_l2`**, usa **`aux_irq_lv12`** e conserva l'indice ricevuto in r4. Questa evidenza attribuisce l'ingresso al trattamento degli interrupt; il ripristino completo e il ritorno dall'eccezione non sono ancora verificati in questo rapporto.

Il corpo gestisce inoltre annidamento e cambio dello stack in rami condizionali. Non si assume che un handler possa usare liberamente lo stack di un task o che il frame qui osservato sia l'ABI di tutte le eccezioni.

## 4. Consultazione della stessa tabella dei registrar

A **`0xB3168`** viene costruito `kernel+0x234`. Gli accessi relativi successivi corrispondono a:

| Accesso | Campo effettivo |
|---|---|
| `[r3-4]` | kernel+`0x230`, limite superiore |
| `[r3-8]` | kernel+`0x22C`, limite inferiore |
| `[r3+4]` | kernel+`0x238`, puntatore tabella |

Dopo le guardie, il codice calcola **`record = tabella + 12*(indice − limite_inferiore)`**. Legge il puntatore funzione a record+0 e il dato a record+8, quindi chiama la funzione a **`0xB31A4`**, passando il dato in r0.

È la stessa struttura su cui **`0x231428`** registra i dispatcher. Le associazioni già verificate si collegano quindi agli stub:

- indice 4 → stub `0xB2FAC` → ingresso comune → record 4 → `0x2640E0` → gruppo logico `0x0402`;
- indice 9 → stub `0xB2FF2` → ingresso comune → record 9 → `0x264308` → gruppo logico `0x0904` e callback dedicate.

Gli indici dei record coincidono con 4/9 nella costruzione con limite inferiore zero. Una configurazione diversa richiederebbe di applicare la sottrazione del limite. Il collegamento resta condizionato al completamento delle registrazioni e allo stato hardware/software del sistema.

## 5. Base iniziale 0x800 e possibilità di sostituzione

La verifica ampliata risolve la richiesta immediatamente precedente al bootstrap della tabella: **`0x29F622` carica `0x800` e `0x29F628` chiama `0x29F1A8`**. Quest'ultimo legge la base precedente, allinea vecchio e nuovo valore a 1.024 byte, scrive il nuovo valore in **`int_vector_base`** e restituisce il precedente.

Se questa richiesta è eseguita e la base non viene sostituita prima del generatore, le 16 voci iniziali occupano **`0x800..0x87F`**. In tale configurazione vettore 4 si trova a `0x820`, vettore 9 a `0x848`. Sono indirizzi derivati dal percorso statico verificato, non una lettura della RAM.

Esiste anche un chiamante **`0x1F0C72`** che passa allo stesso setter il campo **contesto kernel+`94*4 = 0x178`**. La condizione e l'ordine globale rispetto agli altri stadi devono ancora essere ricostruiti: la base corrente non può essere dichiarata universalmente `0x800`.

## 6. Riscrittura condizionale dei vettori 4 e 5

Due percorsi modificano la parola del target di una voce già costruita:

| Tratto | Posizione della voce | Nuovo target letto dal pool |
|---|---|---|
| `0x265244..0x265298` | `int_vector_base + 0x20`, target a +4 | `0x2646A0`, pool `0x265210` |
| `0x265F90..0x265FE4` | `int_vector_base + 0x28`, target a +4 | `0x2655D4`, pool `0x265F5C` |

Il codice scambia le due halfword del valore prima dello store, coerentemente con la disposizione del literal del salto ARC. Poi scrive **`dc_ivdc`** e **`ivic`**, modifica `aux_irq_lev` e prepara un collegamento interrupt da celle di contesto.

La verifica copre il corpo delle modifiche, non tutte le condizioni che le rendono raggiungibili. I target iniziali della tabella della sezione 2 restano quelli generati dal bootstrap; **non sono una prova che le voci 4 e 5 restino invariate**. Il percorso attraverso lo stub 4 deve essere qualificato con questo limite, mentre la verifica di queste due routine non mostra una riscrittura del vettore 9.

I due target nuovi non sono ancora ricostruiti integralmente. Non si estende quindi la catena del gestore comune a ogni possibile configurazione della voce 4.

## 7. Un ramo concreto di ripristino e ritorno

Il tratto **`0xB320E..0xB32BC`** ricarica dal frame stato degli accumulatori e registri ausiliari, registri generali, frame pointer e stato dei loop. Ripristina **`lp_start`, `lp_end`, `lp_count`**, il collegamento interrupt e lo stato selezionato, con un passaggio esplicito su **`status32_l2`**.

Alla fine ricarica r0, incrementa lo stack di **164 byte** e termina con **`j.f [r30]` a `0xB32B8`**. Il tratto alternativo `0xB32BC..0xB32F0` ripristina ulteriori registri, incluso **gp dal frame+132**, e rientra nella continuazione comune.

Questo verifica un'uscita concreta, senza assegnare una sola ABI a tutti gli interrupt: il corpo precedente contiene diramazioni di scheduling e casi alternativi di ritorno ancora da coprire. Il salvataggio e il ripristino qui ricostruiti non autorizzano a inserire codice nuovo senza rispettare quei contratti.

## Evidenze e continuazione

[Script](../Python_Trace_Scripts/s33_trace_interrupt_vectors.py), [JSON](../Ghidra_Results/ghidra_reports/interrupt_vectors/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/interrupt_vectors/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_interrupt_vectors.py`.

Verificati **16 SHA-256**, roundtrip ELF del blocco 00, **15 finestre, 21 collegamenti diretti e 68 istruzioni chiave**. Decodificate inoltre le 16 voci sintetiche prodotte con i parametri del generatore. Il listing separa esplicitamente quelle voci dal firmware originale.

Prossimo: condizioni di riscrittura dei vettori 4/5 e nuovi target `0x2646A0/0x2655D4`, chiamante alternativo della base, rami di scheduling/ritorno e coerenza dei buffer nel percorso SD. Nessuna prova hardware di interrupt o persistenza del JPEG.

## Continuazione sugli ingressi alternativi

Il [rapporto percorsi alternativi](S33_Percorsi_Interrupt_Alternativi.md) verifica i due target, le loro tabelle e accessor a indirizzi fissi distinti dalle riscritture relative alla base corrente. La catena iniziale della sezione 4 resta condizionata allo stato dei vettori.
