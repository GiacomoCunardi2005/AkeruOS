# S33 — banca delle terne, indice e layout

Analisi statica V1.1, 19 ottobre 2026. Continuazione del [workspace degli stadi](S33_Dimensionamento_e_Retry_Workspace.md) e dei [puntatori runtime](S33_Puntatori_Tre_Stadi_e_Registri_Buffer.md). Nessun accesso hardware.

## Risultato

Identificati il reset a0 e **tre avanzamenti modulo4** dell'indice **`0x3674E1 = C+0x51`**, con C=`0x367490`. L'indice seleziona una terna nella banca `0x392288`, costruita da quattro record da12byte. Uno degli avanzamenti è all'ingresso `0x15D100`, che il disassemblaggio lineare iniziato prima della tabella di salto non decodifica correttamente.

Risolto anche il layout locale dei quattro record in funzione delle due quantità numeriche inferiori. Gli aggiornamenti osservati mantengono l'indice in0..3, ma **il lettore non lo verifica prima dell'accesso**. La prova globale di tutti gli scrittori, l'ordine di inizializzazione e l'ultimo uso fisico rimangono aperti. Circa10% funzionale AkeruOS, invariato.

## 1. Identità dell'indice e reset

Il task lega r14 a C leggendo il pool `0x15CFA8`; la lettura `ldb [r14,81]` usa offset81decimale, cioè0x51. Gli store successivi usano un alias:

```text
pool 0x15D32C / 0x15DA94 / 0x15F284 = 0x3674C8 = C+0x38
alias+0x19 = 0x3674E1 = C+0x51
```

Nel tratto di setup raggiunto dopo le verifiche precedenti, `0x15F0A4` imposta r0=0 e **`0x15F0AC`** lo scrive nell'indice. La stessa sequenza azzera i byte adiacenti; non è una nuova inizializzazione eseguita prima di ogni lettura.

## 2. Tre aggiornamenti locali

| Tratto aritmetico | Store indice | Contesto verificato |
|---|---|---|
| `0x15D106..0x15D110` | `0x15D112` | caso della tabella su C+84, sotto C+64=1 |
| `0x15DA3E..0x15DA48` | `0x15DA4A` | dopo C+FD=0, C+63=1 e C+104=0 |
| `0x15DAA8..0x15DAB2` | `0x15DAB4` | dopo C+FD=0, C+63 diverso da1 e C+64=0 |

Gli offset C sono esadecimali. Sono condizioni dei tratti locali, da aggiungere alle guardie precedenti del task; non descrivono una modalità fotografica completa. Il secondo percorso incrementa anche C+68 prima di leggere C+104; il terzo lo incrementa dopo lo store dell'indice.

Ogni aggiornamento legge il byte i e applica la sequenza:

```text
x = i+1
t = ASR32(x,1) >> 30
nuovo = ((x+t) & 3) - t
```

Per i in0..255, t è sempre0 e l'uscita è **`(i+1) mod 4`**. Il modello interpreta separatamente le istruzioni effettive dei tre tratti: **3×256=768 casi**. Anche un byte255 viene normalizzato a0 da questi aggiornamenti. Ciò non rende sicure le letture già eseguite prima dell'aggiornamento.

Il reset0 e questi tre aggiornamenti preservano per induzione l'insieme0..3, se sono gli unici scrittori applicabili e se il reset precede la prima selezione. Le due premesse globali non sono ancora dimostrate.

## 3. Tabella di salto e ingresso nascosto

Sotto C+64=1, il task legge C+84, ammette valori fino a5 e usa una tabella di byte con segno a `0x15D0FA`, con destinazione `base+2*entry`:

| Valore C+84 | Byte | Destinazione |
|---|---|---|
| 0 | 3 | `0x15D100` |
| 1 | 85 | `0x15D1A4` |
| 2 | 85 | `0x15D1A4` |
| 3 | 3 | `0x15D100` |
| 4 | 3 | `0x15D100` |
| 5 | 14 | `0x15D116` |

I sei byte originali sono verificati direttamente dal payload. Avviando GNU a `0x15D100` si ottengono la lettura dell'indice, il pool dell'alias e l'aggiornamento completo. La tabella viene letta come dati: il verifier non tenta di decodificarla come istruzioni.

Questi valori sono stati interni; non vengono associati a nomi di modalità utente.

## 4. Quattro terne: layout locale

Il builder inizializza contatore4 e destinazione `0x392288` a `0x15EAFC/AFE`. Il ramo `C+72 != 0` salta interamente questo ciclo. Quindi l'esistenza del codice di costruzione non prova che la banca venga riscritta a ogni setup.

Sia A0 il cursore letto da `[sp+0xB4]` all'ingresso del ciclo; siano U e V le quantità inferiori:

- U è il risultato r57 del `muludw` a `0x15EB0E`, con input dalle halfword input+34 e input+36.
- V è il ritorno di `0x3342A8` chiamato a `0x15EB24`, con le due halfword dimezzate da shift aritmetici. Essendo state lette senza segno, quei valori iniziali sono non negativi.

La nuova verifica tratta U/V come quantità fornite al confine dei calcoli. Non prova la semantica completa del helper né attribuisce larghezza, altezza o formato colore agli input.

Definendo A8(x)=arrotondamento per eccesso a8, per ogni slot j=0..3:

```text
Tj = 0x392288 + 12*j
parola[Tj+0] = Aj
parola[Tj+4] = A8(Aj+U)
parola[Tj+8] = A8(parola[Tj+4]+V)
Aj+1 = A8(parola[Tj+8]+V)
```

Si riservano dunque una quantità U e due quantità V con allineamenti intermedi. Le formule valgono come interi senza overflow; il codice effettivo opera a32bit.

Il decremento, il confronto e il `bhi.d` di `0x15EB40..448` eseguono quattro iterazioni. Nel delay slot `0x15EB48` la destinazione avanza di12 anche all'ultima iterazione. I dodici store coprono **`[0x392288,0x3922B8)`**, 48byte. Il cursore finale è scritto in stack+0xB4.

Verificati517 coppie U/V, incluse quantità0, bordi dell'allineamento e casi casuali riproducibili: **2.068 layout di slot**, confrontati con le formule. Questi input sintetici verificano l'aritmetica, non la validità di una configurazione hardware.

## 5. Selezione e capienza: due limiti distinti

Nel ramo che raggiunge `0x15D3C6`, il task legge i come byte, costruisce12*i mediante shift2 e `add1` e carica la terna da `0x392288+12*i`. **Non c'è un confronto locale i<4 in questo tratto.**

Rispetto ai soli quattro record costruiti dal ciclo, gli indici0..3 individuano record completi; gli altri252 valori byte escono dall'intervallo di48byte. Questo non è una prova che un indice errato si presenti a runtime. L'avanzamento modulo4 limita le proprie uscite, non tutti i possibili ingressi del lettore.

Il confronto di capienza `0x15EB84..B94` avviene dopo la costruzione. Usa il cursore stack+0xB4 meno la base stack+0x90 e lo confronta senza segno con input+8. Prima del confronto, il ramo C+54=1 può chiamare **`0x15BA8C`**, passando anche il puntatore al cursore. Non è quindi corretto chiamarlo un controllo esclusivo dei byte della banca: riguarda il consumo complessivo di quel percorso di setup.

L'uguaglianza alla capienza è ammessa. I record sono stati scritti prima del confronto, e questo tratto non dimostra un rollback dopo l'errore. Resta distinta la capienza dell'arena dalla validità dell'indice della tabella.

## Evidenze e continuazione

[Script](../Python_Trace_Scripts/s33_trace_stage_bank_cycle.py), [JSON](../Ghidra_Results/ghidra_reports/stage_bank_cycle/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/stage_bank_cycle/gnu_verified.txt).

Riproduzione: `python3 Python_Trace_Scripts/s33_trace_stage_bank_cycle.py`.

Verificati **16 hash, roundtrip ELF blocco00, 10 finestre, 35 istruzioni chiave, 7 pool, 6 casi della tabella, 768 aggiornamenti dell'indice, 2.068 layout di slot e l'aritmetica del selettore su256 byte**. Nessuna esecuzione del firmware o della fotocamera.

Prossimo: estendere l'inventario agli scrittori indiretti e agli azzeramenti delle strutture, verificare l'ordine setup→prima lettura e ricostruire il consumo di U/V e delle aree condivise. L'ultimo uso fisico, il ritorno pronto e l'integrazione AkeruOS restano aperti.
