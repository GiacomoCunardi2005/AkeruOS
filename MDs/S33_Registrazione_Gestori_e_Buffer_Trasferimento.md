# S33 — registrazione dei gestori e indirizzo del buffer

Analisi statica V1.1, 18 ottobre 2026. Continuazione di [avvio e callback SD](S33_Avvio_Trasferimento_e_Callback_SD.md). Nessuna esecuzione hardware.

## Risultato

Collegata la registrazione **`0x0402 → 0x267F20`** alla voce 14 della tabella **`0x424A00`**, con cella callback **`0x424A80`**. Un dispatcher verifica due halfword MMIO e i bit indicati dal record prima della chiamata indiretta. Risolta anche la registrazione distinta **`0x2001 → 0x2689FC`**, conservata a **`0x36B324`**.

Il servizio di trasferimento **`0x266FC8`** scrive le due metà dell'indirizzo buffer a **`0x0FEE050C/0x0FEE0510`**. La catena ora comprende registrazione, selezione del gestore, callback software ed evento SD; il vettore CPU effettivo e la consegna runtime restano da provare. Circa 10% funzionale invariato.

## 1. Registrazione dell'ID 0x0402

A **`0x16DE54`** viene caricata la funzione **`0x267F20`** dal pool `0x16DEA0`. La chiamata **`0x16D898`** riceve ID **1026 (`0x0402`)**. L'ID è trattato come identificatore logico; non viene chiamato numero di vettore CPU.

Il registrar seleziona il gruppo `0x0400` e il puntatore **`0x424A00`**. Il ciclo confronta l'ID con una halfword del record e conserva il gestore nel campo callback. Nei byte verificati:

| Proprietà | Valore |
|---|---|
| Tabella | `0x424A00` |
| Primi due puntatori | `0x0FEF0050`, `0x0FEF0080` |
| Conteggio halfword a +8 | 16 |
| Inizio record | +`0x0C` |
| Passo record | 8 byte |
| ID presenti | `0x0410` fino a `0x0401`, ordine decrescente |
| Record per `0x0402` | Indice 14, indirizzo `0x424A7C` |
| Indici bit nel record | 1 e 1 |
| Cella callback | `0x424A80`, zero nel payload iniziale |

Lo store del registrar **`0x16D9A6`** scrive la callback nel campo a +4 del record scelto. La successiva richiesta `0x16D7E8(0x0402, 0xFF)` viene emessa soltanto se la registrazione restituisce zero; la sua semantica completa non è verificata qui.

## 2. Dispatcher con due condizioni MMIO

Il tratto **`0x2640E6..0x26418E`** legge i due puntatori dell'intestazione e le halfword ai rispettivi indirizzi. Se una lettura o il conteggio non consentono di proseguire esce. Per ciascun record controlla i bit indicati dai byte +2/+3 del record, poi legge il campo callback.

Soltanto con entrambe le condizioni soddisfatte e callback non nulla esegue **`jl [r0]` a `0x26414E`**. In caso contrario passa al record seguente, passo 8. Per la voce `0x0402`, entrambi gli indici sono 1.

Combinato con lo store precedente, questo attribuisce staticamente il gestore **`0x267F20`** al percorso della voce `0x0402`. Non prova che la registrazione sia stata eseguita sulla fotocamera, che le maschere siano abilitate o che questo dispatcher sia già collegato al vettore CPU corretto. Non sono assegnati nomi fisici ufficiali ai due registri dal solo contenuto della tabella.

## 3. Registrazione distinta dell'ID 0x2001

A **`0x16DD36`** il firmware carica **`0x2689FC`** dal pool `0x16DD78` e chiama **`0x266030`** con ID **`1 | (1<<13) = 0x2001`**. Il registrar usa uno slot dedicato:

| ID | Cella callback |
|---|---|
| `0x2001` | `0x36B324` |
| `0x2002` | `0x36B328` |
| `0x2004` | `0x36B32C` |

Il ramo `0x2001` conserva la parola ricevuta e restituisce zero. Il chiamante può poi invocare **`0x265FE8(0x2001)`**. La verifica risolve il salvataggio della funzione, senza attribuire ancora il dispatcher dedicato che la invoca.

I due ID appartengono a percorsi di registrazione diversi: non vengono fusi in una stessa numerazione di interrupt CPU.

## 4. Indirizzo del buffer nei registri del trasferimento

Nel servizio **`0x266FC8`**, il primo argomento è conservato in r13. Il tratto selezionato scrive:

```text
halfword [0x0FEE050C] = buffer & 0xFFFF
halfword [0x0FEE0510] = buffer >> 16
```

Le scritture usano **`sth.di`** e i pool sono verificati. Il servizio prepara anche dimensioni e modalità tramite `0x2822C4` e modifica altri campi MMIO; il loro contratto completo resta da attribuire. Gli indirizzi del buffer sono quelli ricevuti dal firmware, senza una prova aggiuntiva dell'equivalenza fra indirizzo CPU e indirizzo fisico del motore.

La coppia di scritture, insieme alla registrazione della callback e alle notifiche già collegate, sostiene l'attribuzione a un servizio di trasferimento assistito dal controller. Non dimostra ancora il motore DMA preciso, la coerenza delle cache o il completamento di ogni byte prima del riuso.

## Evidenze e prossimo passo

[Script](../Python_Trace_Scripts/s33_trace_transfer_registration.py), [JSON](../Ghidra_Results/ghidra_reports/transfer_registration/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/transfer_registration/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_transfer_registration.py`.

Verificati **16 SHA-256**, roundtrip ELF del blocco 00, **10 finestre, 7 collegamenti e 21 istruzioni chiave**, più intestazione e 16 record della tabella nel payload dati. Gli hash verificano anche il blocco dati; il roundtrip ELF riguarda il blocco di codice disassemblato.

Prossimo: origine CPU del dispatcher `0x2640E6`, consumatore dello slot `0x36B324`, contratto di avvio/abilitazione dei due registratori e gestione della coerenza del buffer nel servizio di trasferimento.

## Continuazione del 19 ottobre: slot runtime e aggregatore

Il [rapporto dispatch runtime](S33_Dispatch_Interrupt_Runtime_e_Gruppi_SD.md) collega i dispatcher agli slot 4/9 e risolve il consumatore di `0x36B324` tramite gruppo logico `0x0904`. Ingresso CPU effettivo e consegna runtime restano aperti.
