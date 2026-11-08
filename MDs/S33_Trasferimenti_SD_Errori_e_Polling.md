# S33 — trasferimenti SD, errori e polling MMIO

Analisi statica V1.1, 18 ottobre 2026. Continuazione del [backend SD](S33_Dispositivo_SD_e_Completamento.md). Nessun accesso alla fotocamera o modifica del firmware.

## Risultato

Ricostruiti i due servizi di scrittura **`0x25B9C0`** e **`0x25BB5C`**, collegati al backend DEVSD:. Il wrapper superiore **`0x168410`** consente al massimo **tre tentativi esterni**, con uscite anticipate su successo o recupero fallito.

Il completamento **`0x2E5634 → 0x25A658`** interroga un registro tramite **`0x25A0BC`**, che esegue una lettura halfword `.di` a **`0x0FF01804 − selettore`**. Il ciclo di polling esaminato non contiene un timeout locale. Quindi tre tentativi esterni non costituiscono un limite temporale all'intera operazione.

Sono inoltre individuati casi che traducono **`0x00E00200` in successo** in una specifica condizione di confine. Un ritorno zero va interpretato secondo questo contratto software; non dimostra la persistenza fisica dopo perdita di alimentazione. Avanzamento funzionale orientativo invariato: circa 10%.

## 1. Wrapper e limite dei tentativi

**`0x168410`** calcola un contesto dall'indice ricevuto e dalla base **`0x4463E0`**. Il callback SD `0x1684B4` passa indice 0; l'altro selettore del wrapper è 0 oppure `0x800` secondo l'indice. Non si identifica il contesto con la precedente tabella volumi `0x376018`.

La scelta dipende dal conteggio conservato in r16:

| Confronto signed | Destinazione |
|---|---|
| Maggiore di 1 | `0x25B9C0`, riceve il conteggio |
| Minore o uguale a 1 | `0x25BB5C`, che passa conteggio 1 al trasferimento inferiore |

Questo confronto locale non dimostra l'ammissione di conteggi nulli o negativi nell'intera API: resta da verificare il contratto dei chiamanti.

Dopo un risultato zero esce restituendolo. Dopo un errore chiama **`0x25BF3C`**, quindi tenta **`0x25B63C`** con selettore 0 nella prima iterazione e, quando richiesto, con selettore 1. Se il recupero richiesto fallisce, esce conservando il risultato del trasferimento in r14, distinto dal risultato del recupero.

Il contatore richiede attenzione ai target esatti:

```text
0x168444: r0 = 3           // inizializzazione, eseguita una volta
0x168446: r18 = r0         // destinazione del ritorno del ciclo
... trasferimento ed eventuale recupero ...
0x16849E: r0 = r18 - 1
0x1684A4: se r0 > 0, torna a 0x168446
```

Le iterazioni ammesse hanno r18 **3, 2, 1**. Il salto non torna alla costante 3. Il limite riguarda le chiamate esterne ai due servizi, senza limitare automaticamente i cicli interni o i tempi hardware.

## 2. Servizio con selettore 0x18

**`0x25BB5C`** controlla che la posizione sia inferiore alla parola **contesto+`0xE4`**; altrimenti sceglie **`0x00E00303`**. Prepara poi il servizio `0x2E514C`, costruisce un descrittore mediante **`0x2E509C`** con selettore **`0x18`**, ed esegue **`0x2E52F4`**.

Se quel risultato è zero chiama **`0x2E5648`** con buffer, dimensione/configurazione letta dal contesto e **conteggio 1**. Se anche il trasferimento restituisce zero, chiama **`0x2E5634`**, conservandone il risultato in r13.

In presenza di errore, costruisce ed esegue un altro descrittore con selettore **`0x0D`**. Il risultato di quest'ultima operazione non sostituisce l'errore già conservato. Il ritorno a `0x25BC36` usa r13, anche dopo il servizio di uscita `0x25AA8C`.

I numeri dei selettori sono verificati sui registri e sul costruttore del descrittore, senza attribuire qui nomi tratti da uno standard SD esterno.

## 3. Servizio con selettore 0x19 e casi di confine

**`0x25B9C0`** controlla posizione e somma posizione+conteggio rispetto a **contesto+`0xE4`**. Il ramo di rifiuto restituisce **`0x00E00302`**. L'addizione è quella della macchina a 32 bit; non è stata dimostrata qui una protezione generale contro ogni overflow.

Il percorso ammesso costruisce un descrittore con selettore **`0x19`**, esegue `0x2E52F4` e chiama **`0x2E5648`** con il conteggio richiesto. Può poi chiamare `0x2E5634` in base al campo contesto+`0xD4`.

Successivamente esegue un descrittore **`0x0C`**. Il codice conserva separatamente:

- r14: esito del trasferimento e dell'eventuale completamento precedente;
- r17: esito del descrittore `0x0C`.

Se r14 è nonzero, prevale quell'errore. Se r14 è zero, un esito nonzero di `0x0C` diventa errore, **tranne `0x00E00200` quando posizione+conteggio coincide con contesto+`0xE4`**. In tale caso il codice prosegue.

Dopo un nuovo completamento riuscito, se è al medesimo confine, esegue un descrittore **`0x0D`**. In quel ramo il risultato **`0x00E00200` è esplicitamente sostituito con zero** a `0x25BB1A`. Altri esiti sono conservati.

Se rimane un errore, un'ulteriore operazione `0x0D` non sovrascrive r14. Il ritorno a `0x25BB52` usa il risultato conservato. Il significato del codice `0x00E00200` non è dedotto soltanto dal suo valore.

## 4. Costruttore, trasferimento e primo MMIO del completamento

Il costruttore **`0x2E509C`** salva il selettore del comando come halfword a **descrittore+8**, l'argomento a **+`0x18`**, altri parametri a +0/+`0x0A`/+`0x0C` e inizializza campi di stato. Sono offset del descrittore, distinti da quelli del contesto del dispositivo.

Il dispatcher **`0x2E52F4`** configura i selettori `0x18/0x19` nel ramo `0x2E53A6`, quindi arriva al tratto **`0x25A278`** (emissione con selettore e argomento diviso) e **`0x25A5F8`**. Il seguito completo delle risposte non è ancora ricostruito in questo rapporto.

Il trasferimento dati **`0x2E5648 → 0x3042A8`** distingue il quarto parametro: se uguale a 1 esegue preparazioni e passa a **`0x3040DC`**; negli altri casi passa a **`0x304004`**. Non viene ancora assegnata universalmente l'etichetta DMA o PIO a questi rami.

Il servizio di completamento **`0x2E5634`** è un salto diretto a **`0x25A658`**. Il lettore **`0x25A0BC`** usa:

```text
indirizzo = 0x0FF01804 - selettore
stato = halfword letta con ldh.di
```

Nel percorso SD selezionato il valore passato è 0; l'indirizzo è dunque **`0x0FF01804`**. Questo è un collegamento statico al registro, non una misura del suo valore.

## 5. Priorità dei bit e polling senza timeout locale

La routine **`0x25A658`** rilegge lo stato e applica nell'ordine:

| Condizione, dopo le precedenti non soddisfatte | Azione |
|---|---|
| Bit 2 impostato | Restituisce `0x00E00103` |
| Bit 8 impostato | Restituisce zero |
| `(stato & 0x70) == 0x50` | Restituisce `0x00E00208` |
| Nibble basso uguale a zero | Torna alla lettura |
| Altro | Restituisce `0x00E00208` |

L'ordine è rilevante: il bit 2 ha priorità sul bit 8; il bit 8 viene trattato prima del confronto mascherato. Non si attribuiscono nomi hardware ai bit senza ulteriore prova.

Nel corpo completo **`0x25A658..0x25A690`** non compaiono contatore di timeout, lettura del tempo o attesa/sospensione del task. Se l'hardware continua a restituire uno stato che ricade nel quarto caso, il ciclo non ha un'uscita temporale locale. Ciò non prova che quel blocco si verifichi realmente, né esclude un intervento esterno come watchdog o interrupt.

Il ritorno zero prova soltanto che la routine ha scelto il ramo del bit 8, o che un chiamante ha tradotto un altro esito nei casi sopra descritti. Non stabilisce ancora il rapporto fra segnalazione hardware, completamento del buffer e conservazione fisica del JPEG.

## Evidenze e prossimo passo

[Script](../Python_Trace_Scripts/s33_trace_sd_transfer_status.py), [JSON](../Ghidra_Results/ghidra_reports/sd_transfer_status/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/sd_transfer_status/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_sd_transfer_status.py`.

Verificati **16 SHA-256**, roundtrip ELF del blocco 00, **11 finestre, 25 collegamenti e 29 istruzioni chiave**, pool degli errori e base del contesto. Il limite dei tentativi è ricavato dalle istruzioni e dal target del salto, senza pretendere una simulazione completa dell'hardware.

Prossimo: ricostruire `0x25A278/0x25A5F8`, i rami dati `0x304004/0x3040DC` e i produttori dello stato hardware/software; verificare l'eventuale protezione temporale esterna e collegare il risultato al ciclo di vita dei buffer fotografici.

## Continuazione sui registri e sui dati

Il [rapporto registri/dati SD](S33_SD_Registri_Comando_e_Percorsi_Dati.md) risolve l’emissione del comando, il distinto polling iniziale da 8.000 iterazioni e i percorsi CPU/servizio con callback. Il polling di completamento qui descritto resta privo di timeout locale.

## Continuazione — motori read e PIO eseguiti

[S33_Dumper_RAM_SD_Lettura_PIO_Motori_e_Completamento_Originali.md](S33_Dumper_RAM_SD_Lettura_PIO_Motori_e_Completamento_Originali.md):20PIO,28motori,13r/FAT/PMSD/SD/PIO/close. Il confine prima degli interi B15B4/B16D0 è superato: preparazione,descrittori,copia CPU/MMIO e completamento ora eseguiti. Dispatcher comandi2E52F4 e25AA8C restano fixture;profili sintetici,non prova elettrica. Percorso write/asincrono non generalizzato dal read. Nessun hardware o BIN modificato.
