# S33 — callback filesystem e controlli prima della chiusura

Analisi statica V1.1 del 18 ottobre 2026. Continuazione degli [esiti ImgMgr](S33_Esiti_ImgMgr_e_Chiusura.md) e del [salvataggio](S33_Salvataggio_e_Chiusura.md). Nessun comando sulla fotocamera.

## Risultato

È stata risolta una famiglia concreta di callback registrate nel dispositivo filesystem: **chiusura `0x1F48A4`, scrittura `0x1F4958`, controllo `0x1F56B4`**. La registrazione, i campi della struttura driver e le chiamate indirette sono collegati attraverso le istruzioni originali.

Due comandi eseguiti da `0x12D604` prima del close sono stati risolti nella tabella del controllo. In questa famiglia, **`0x3015` non propaga direttamente il risultato di un worker interno**, mentre **`0x3038` sovrascrive il proprio risultato locale con `0x1A09`**. Il wrapper superiore ignora il ritorno del primo comando e controlla il secondo prima di chiamare close.

Queste sono conclusioni condizionate alla famiglia registrata: non è ancora provato che tutti i file fotografici sulla SD usino questa istanza del driver. Il confine «chiuso» non costituisce ancora una prova di persistenza sul supporto. R2 resta parziale, circa 10% complessivo invariato.

## 1. Dalla registrazione ai campi del dispositivo

`0x1F3554` richiede un contesto di 852 byte e, nel ramo in cui l'allocazione riesce, prepara gli argomenti di **`0x2A3C5C`**. I letterali sono:

| Argomento | Letterale | Callback | Campo installato dal registrar |
|---|---|---|---|
| `r1` | `0x1F3900` | `0x1F43AC` | +`0x0C` |
| `r2` | `0x1F3904` | `0x1F48A4` | +`0x10` |
| `r3` | `0x1F3908` | `0x1F48E8` | +`0x14` |
| `r4` | `0x1F390C` | `0x1F4958` | +`0x18` |
| `r5` | `0x1F3910` | `0x1F56B4` | +`0x1C` |
| `r6` | `0x1F3914` | `0x1F618C` | +`0x20` |

Per `r4/r5/r6` il caricamento ARC è scalato: per esempio `(0x1F3582 & ~3) + 228*4 = 0x1F3910`. I commenti non scalati del disassemblatore non sono usati come indirizzi dei letterali.

Il registrar conserva `r2/r4/r5` in `r21/r23/r24` e scrive quei valori a struttura +16/+24/+28, a `0x2A3DAE`, `0x2A3DB6` e `0x2A3DBA`. Il contesto privato ricevuto in `r7` viene scritto a +36. La struttura viene poi inserita nel registro del kernel; non è stata osservata la registrazione a runtime.

I consumatori generici coincidono con questi campi:

- **`0x1F22C0`** legge la prima parola dell'handle per ottenere il dispositivo e invoca dispositivo+`0x10`, a `0x1F2324`, passando l'handle nel delay slot. Conserva il risultato della callback attraverso le operazioni successive.
- **`0x1FA090`** invoca dispositivo+`0x18`, a `0x1FA0B6`, nel percorso di scrittura.
- **`0x1F2348`** gestisce localmente i comandi 1/2 e, per gli altri, invoca dispositivo+`0x1C`, a `0x1F2372`.

Per un handle associato a questa famiglia, quindi, i destinatari dei tre passaggi indiretti sono ora concreti. Nome del volume, istanza attiva e associazione del singolo handle fotografico richiedono ancora un raccordo.

## 2. Comandi prima del close

Nel corpo `0x12D604`, dopo i controlli e la sincronizzazione:

```text
0x12D682: controllo 0x3038 sull'handle file, terzo argomento zero
             ritorno non conservato come risultato del close
0x12D69A: controllo 0x3015 su un altro handle ricavato dal record volume
0x12D6A0..A4: conserva e controlla questo secondo risultato
             se nonzero esce prima del close e dell'azzeramento finale
0x12D6BC: chiama il close generico 0x1F22C0
0x12D6C4: conserva il risultato del close
0x12D6D4/D6: rimuove la voce e azzera l'handle del chiamante
```

La successiva operazione di rilascio della sincronizzazione può sostituire il risultato conservato se restituisce errore. L'azzeramento dell'handle segue la chiamata close anche quando quella callback restituisce errore; questo conferma e precisa il limite già documentato.

I due controlli non usano necessariamente lo stesso handle. Non si trasferisce automaticamente la famiglia del primo al secondo: il percorso del secondo volume deve essere attribuito separatamente.

## 3. Risoluzione della tabella del controllo registrato

Il dispatcher **`0x1F56B4`**, superati i controlli precedenti, sottrae `0x3002` al comando e richiede un indice non maggiore di `0x3E`. A `0x1F57C0` legge una mezza parola signed dalla tabella **`0x1F57C8`**, quindi salta a base + due volte lo spostamento.

| Comando | Cella tabella | Spostamento signed | Destinazione |
|---|---|---:|---|
| `0x3015` | `0x1F57EE` | 942 | `0x1F5F24` |
| `0x3038` | `0x1F5834` | 1225 | `0x1F615A` |

Sono controlli interni alla struttura driver, non operazioni PTP.

### `0x3015`: worker e canale di ritorno distinti

Il ramo `0x1F5F24` ricava il contesto, esegue un predicato e, se questo dà zero, chiama **`0x1F2484`**. Poi salta a `0x1F6116 → 0x1F60EC → 0x1F6180`.

Nel tratto locale non copia il ritorno di `0x1F2484` nello slot risultato `sp+0x0C`, inizializzato a zero all'ingresso del dispatcher. La coda restituisce proprio quello slot. Si tratta di un risultato interno non propagato direttamente; non basta chiamare il controllo e ottenere zero per certificare l'azione del worker.

`0x1F2484` usa un campo stato a contesto+`194*4 = 0x308`. Nel ramo stato 1 può iterare e chiamare **`0x2A0C60` con selettore 10**, aggiornando poi lo stato a 2 se il risultato finale è zero. Tipo di dati trasferiti, backend fisico, cache e persistenza di quella richiesta restano da attribuire. Non viene denominata «flush SD riuscito» dalla sola struttura del codice.

### `0x3038`: risultato sovrascritto

Nel ramo `0x1F615A`, se un campo privato è nonzero, viene chiamata `0x1F28A4`; altrimenti il risultato locale è zero. Il risultato viene scritto nello slot a `0x1F6174`, ma dopo il rilascio della sincronizzazione il codice prosegue a:

```text
0x1F617C: carica letterale 0x1F6290 = 0x1A09
0x1F617E: sovrascrive sp+0x0C
0x1F6180: legge lo slot di risultato
```

Il numero `0x1A09` non è qui trasformato in un nome semantico di errore. Nel chiamante `0x12D604`, il ritorno di questo primo controllo non viene usato come guardia per il close. La sequenza non dimostra da sola un difetto: restano da stabilire ruolo del comando, effetti collaterali previsti e istanza effettiva del driver.

## 4. La famiglia contiene backend alternativi

La callback di chiusura `0x1F48A4` può raggiungere `0x1F46C4`, oppure scegliere tra il servizio `0x1F9258` e **`0x21AD30`** in base a contesto e predicato. La scrittura `0x1F4958` ha analogamente un ramo verso `0x1F94D4` e uno verso **`0x21A4B8`**.

La registrazione non basta dunque a identificare l'ultima operazione eseguita sulla memoria. Occorre attribuire il predicato `0x1F35FC`, il contesto privato e il backend selezionato sul file fotografico, mantenendo distinti conteggio scritto, stato del file, risultato del controllo e close.

## Evidenze e prossimo passo

[Script](../Python_Trace_Scripts/s33_trace_storage_callbacks.py), [JSON](../Ghidra_Results/ghidra_reports/storage_callbacks/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/storage_callbacks/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_storage_callbacks.py`.

Verificati **16 hash, roundtrip ELF del blocco 00, 16 finestre, 10 collegamenti diretti, due celle della tabella e 11 istruzioni selezionate**. I conteggi descrivono la copertura statica, non una prova di chiusura sulla macchina.

**Prossimo passo R2:** collegare l'apertura del file fotografico a un'istanza registrata e al suo contesto privato; risolvere il predicato `0x1F35FC` e i backend `0x21AD30/0x21A4B8`, insieme al controllo sul secondo handle di volume. Restano aperti sincronizzazione effettiva della memoria, propagazione finale degli esiti e condizioni per consentire spegnimento o un nuovo scatto. Gli indirizzi V1.1 non sono automaticamente utilizzabili sulla fotocamera V1.0.

## Continuazione: handle logici e selettore del backend

Il [rapporto handle e backend](S33_Handle_Logici_e_Backend_File.md) distingue chiave logica e puntatore file tramite 30 record a `0x4BD110`. La rimozione dell’associazione precede il close senza rollback locale. Il predicato `0x1F35FC` è ora risolto: contesto privato+`0x70 == 7`; restano da attribuire valore sul volume fotografico e servizi inferiori, incluso `0x2A1054`. Nuove evidenze: 16 hash, 17 finestre, 16 collegamenti.

## Continuazione sui controlli e sul close senza contesto file

Il [rapporto successivo](S33_Controlli_Completamento_e_Close_Volume.md) risolve PM `0x2015/16`, comando filesystem 3 e un chiamante close che ne ignora l’esito. Distinto dal close ordinario con contesto file nonnullo; persistenza fisica e shutdown restano aperti.
