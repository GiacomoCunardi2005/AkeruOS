# S33 — apertura file, associazioni logiche e volumi

Analisi statica V1.1 del 18 ottobre 2026. Continuazione degli [handle e backend](S33_Handle_Logici_e_Backend_File.md). Nessuna operazione sulla fotocamera.

## Risultato

È collegata l'apertura del puntatore file alla registrazione nella tabella logica: **`0x217EFC → 0x12CE8C/0x12DBFC → 0x1F21F8`**, poi **`0x218458`**. I servizi inferiori registrano il puntatore anche in una tabella distinta di file aperti per volume.

La tabella statica dei volumi associa **`B:` a `DEVSD:`** e **`A:` a `DEVNAND:`**. Il percorso di installazione passa il prefisso del record alla famiglia filesystem già risolta. Questo raccorda nomi, registrazione e callback originali, senza dimostrare quale istanza fosse montata durante uno scatto reale.

Il wrapper superiore non controlla il risultato della registrazione logica dopo l'apertura riuscita. Un ritorno zero dell'apertura non certifica quindi, da solo, la presenza della successiva associazione chiave/puntatore. Non è dimostrato un esaurimento reale né una perdita globale di risorse. R2 rimane parziale; circa 10% funzionale, invariato.

## 1. Dalla chiave al puntatore file

`0x137ABC` inoltra a **`0x217EFC`**, conservando tre argomenti. Nel wrapper sono distinguibili questi percorsi:

| Condizione locale | Azione |
|---|---|
| Secondo argomento uguale a 1 | Se la chiave è già associata, tenta prima `0x21828C`; poi prepara il percorso e chiama `0x12DBFC` con selettore 2 |
| Secondo argomento diverso da 1, chiave già presente | Ritorna zero nel ramo locale senza creare una seconda associazione |
| Secondo argomento diverso da 1, chiave assente | Se il terzo argomento vale 1 usa `0x12`, altrimenti `0x11`, poi chiama `0x12CE8C` |
| Apertura inferiore riuscita | `0x218034 → 0x218458(chiave, puntatore_file)` |

Il ritorno del precedente tentativo di chiusura non viene confrontato prima di proseguire nel ramo secondo argomento 1. Validità del percorso, preparazioni e controlli del volume possono ancora impedire l'apertura.

Il convertitore **`0x210C5C`** riceve la chiave e prepara un percorso in un buffer locale. La generazione completa del nome fotografico e l'allocazione della chiave non sono ancora risolte. Questa ricostruzione non costituisce una firma API completa.

### Modalità passate al servizio generico

I letterali verificati sono:

- `0x12D008 = 0x3668D5`, contenente le stringhe `r` e `r+`;
- `0x12DE34 = 0x3668DE`, contenente `w`, `w+`, `n`, `n+`.

`0x12CE8C` sceglie `r` per il selettore `0x11`, altrimenti `r+`. `0x12DBFC`, con selettore 2 nel percorso superiore esaminato, sceglie `w+`. Vengono qui riportate le stringhe effettive, senza estendere automaticamente la semantica a tutte le varianti della libreria.

Entrambi arrivano a **`0x1F21F8`**. Il servizio cerca nel registro kernel un dispositivo il cui prefisso corrisponde al percorso, alloca un oggetto file da **32 byte**, scrive il puntatore dispositivo nella prima parola e invoca la callback a **dispositivo+`0x0C`**, passando percorso e modalità. Per la famiglia precedentemente risolta quella callback è `0x1F43AC`.

## 2. Due registrazioni con esiti differenti

I servizi inferiori `0x12CE8C` e `0x12DBFC`, dopo i controlli, conservano il puntatore ottenuto sia nella cella di uscita sia in uno slot del volume. L'apertura esegue anche controlli di duplicazione e percorsi di chiusura su errore; non è una singola allocazione senza condizioni.

Il wrapper `0x217EFC` conserva il risultato dell'apertura in `r13`. Se è zero, registra la coppia logica a **`0x218034`**, ma il seguito immediato è:

```text
0x218034: chiama 0x218458
0x218038: r0 = r13       // stato dell'apertura conservato prima
```

Il risultato della registrazione non viene copiato nello stato restituito. Nel tratto dopo tale chiamata non compare una chiusura di recupero del puntatore appena aperto se la tabella logica è piena. Questo è un confine locale: vanno ancora ricostruiti invarianti di ammissione e altri proprietari prima di affermare che il caso accada o produca una perdita sul dispositivo.

Le capacità sono distinte: **30 associazioni logiche complessive** nella tabella già documentata, contro **60 slot di puntatori per record volume** nella tabella inferiore. Il solo confronto delle capacità non prova la raggiungibilità dell'esaurimento.

## 3. Tabella dei volumi e prefissi

La base **`0x376018`** è verificata nei letterali `0x12D004`, `0x12DE24` e `0x1F1DA4`. Il passo usato dalle istruzioni è **`0x150 = 336` byte**: le operazioni ARC calcolano `21 × indice`, poi moltiplicano per 16.

Nel payload iniziale si trovano:

| Indice | Record | Nome a +8 | Nome a +19 | Prefisso a +30 | Sincronizzazione a +4 |
|---:|---|---|---|---|---|
| 0 | `0x376018` | `DEVSD:` | `PMSD:` | `B:` | `0x01A0000D` |
| 1 | `0x376168` | `DEVNAND:` | `PMNAND:` | `A:` | `0x01A0000A` |

Il record successivo ha prima parola zero nel campione. Questa osservazione riguarda i dati iniziali e il criterio di scansione; non è un inventario letto dal registro vivo.

Ogni record contiene da **+`0x60`** una sequenza di **60 puntatori da 4 byte**. `0x12CE8C` e `0x12DBFC` cercano uno slot nullo con indici da 0 a 59. Il passo del record corrisponde a `0x60 + 60*4 = 0x150`. Le sincronizzazioni e i flag nel prefisso del record controllano l'uso effettivo.

`0x1F19E0`, usata per risolvere il volume da un nome con due punti, confronta il prefisso a +30. La denominazione SD/NAND è sostenuta dalle stringhe presenti nei due record; l'accesso fisico al rispettivo supporto non viene verificato da questa lettura.

## 4. Il prefisso viene passato alla famiglia filesystem nota

Nel percorso **`0x1F2038`**, l'indice seleziona lo stesso record di volume. Se la guardia sul campo +`0x58` consente il seguito:

```text
r0 = parola del record a +0x54
r1 = indirizzo del prefisso a +30
r2 = 1 nel delay slot
0x1F205A → 0x1F3554
```

`0x1F3554` è l'installatore della famiglia già verificata, che registra open `0x1F43AC`, close `0x1F48A4`, write `0x1F4958` e controllo `0x1F56B4` tramite `0x2A3C5C`.

Questo collega condizionalmente **record SD → prefisso `B:` → installazione della famiglia filesystem**. Restano da ricostruire la preparazione del campo +`0x54`, gli effetti della guardia +`0x58`, l'effettivo avvio dell'installatore e la generazione del percorso a partire dalla chiave fotografica. Il selettore del backend a contesto privato+`0x70` non viene determinato dalle sole stringhe del record.

## Evidenze e prossimo passo

[Script](../Python_Trace_Scripts/s33_trace_file_opening.py), [JSON](../Ghidra_Results/ghidra_reports/file_opening/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/file_opening/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_file_opening.py`.

Verificati **16 hash, roundtrip ELF del blocco 00, 10 finestre mirate, nove collegamenti diretti, modalità e due record volume**. Il JSON conserva offset, nomi, geometria e limiti. Nessuna lettura della RAM del dispositivo o esecuzione delle callback.

**Prossimo passo R2:** seguire la preparazione del volume, il convertitore di chiave/percorso `0x210C5C` e la creazione fotografica fino all'ingresso di apertura; completare il servizio `0x2A1054` e i trasferimenti inferiori per stabilire il confine di sincronizzazione. Propagazione degli errori, recupero dei buffer e persistenza SD restano aperti. Nessuna compatibilità V1.0 o foto prodotta da AkeruOS è ancora dimostrata.

## Continuazione: chiave e formati del percorso

Il [rapporto chiave e percorso](S33_Chiave_File_e_Costruzione_Percorso.md) risolve i cinque campi estratti da `0x210C08` e il loro uso nel convertitore `0x210C5C`, con decoder locale. La stringa di base viene da `0x44234C + 56*indice`, con indice a `0x366889`; registro directory e prefisso file richiedono inizializzazione. Il numero directory non è direttamente l’indice codificato e non è dimostrata equivalenza con gli handle PTP. Nuova verifica: 16 hash, nove finestre, nove collegamenti.
