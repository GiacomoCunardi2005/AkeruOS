# S33 — dispositivo SD e completamento dei metadati

Analisi statica V1.1, 18 ottobre 2026. Continuazione di [metadati differiti](S33_Metadati_Differiti_e_Scrittura_Inferiore.md) e [apertura/volumi](S33_Apertura_File_e_Volumi.md). Nessuna nuova prova sulla fotocamera.

## Risultato

Risolto il destinatario della scrittura inferiore per la costruzione SD esaminata: **filesystem → PMSD: → DEVSD: → `0x1684B4`**. Il wrapper di partizione inoltra conteggio e buffer al dispositivo grezzo e copia il suo campo errore. Il callback SD entra in `0x168410`, che seleziona servizi inferiori e contiene un percorso di recupero condizionale.

Individuato anche **`0x2A1270`**, che può attivare il differimento oppure tentare tre aggiornamenti in sequenza, fermandosi al primo errore. Questo restringe il percorso da verificare, ma non dimostra ancora una barriera universale di close/spegnimento o la persistenza fisica. Avanzamento funzionale orientativo invariato: circa 10%.

## 1. Tre strati e due handle per volume

La tabella iniziale a `0x376018`, passo `0x150`, conserva i nomi già attribuiti:

| Record | Nome dispositivo +8 | Nome wrapper +19 | Prefisso filesystem +30 | Callback grezzo +`0x38` |
|---|---|---|---|---|
| 0 | DEVSD: | PMSD: | B: | `0x1684B4` |
| 1 | DEVNAND: | PMNAND: | A: | `0x1695D0` |

`0x1F1E1C` costruisce direttamente un dispositivo da 44 byte e un file da 32 byte, con contesto privato da 40 byte. Imposta i callback open/close/read/write/control rispettivamente a **`0x2A04D0 / 0x2A04F0 / 0x2A0594 / 0x2A0534 / 0x2A05F4`**. Dopo open riuscito conserva il file in **record+`0x50`**. In questo corpo la costruzione è diretta, senza registrazione tramite `0x2A3C5C`.

`0x1F1F10` passa quell'handle e il nome a +19 a **`0x2A0698`**. Quest'ultimo alloca 72 byte di contesto, conserva l'handle grezzo alla prima parola e registra il wrapper tramite `0x2A3C5C`. La famiglia è:

| Slot dispositivo | Callback del wrapper |
|---|---|
| +`0x0C` open | `0x2A073C` |
| +`0x10` close | `0x2A0844` |
| +`0x14` read | `0x2A0870` |
| +`0x18` write | `0x2A0890` |
| +`0x1C` control | `0x2A0A14` |
| +`0x20` | `0x2A0BF0` |

Le tre istruzioni `ld.as` a `0x2A06C6/CE/D2` usano offset scalati per quattro: i pool corretti sono `0x2A0A98/9C/AA0`, verificati sui byte. I commenti automatici del disassemblatore non sono usati come indirizzi di quei pool.

`0x1F1F4C` apre il nome wrapper con `0x1F21F8` e salva il risultato in **record+`0x54`**. Il successivo installatore filesystem `0x1F2038 → 0x1F3554` riceve questo handle, conservandolo a **contesto filesystem+`0x1A4`**. Sono due handle distinti: +`0x50` grezzo e +`0x54` wrapper. L'associazione dipende dall'esecuzione riuscita dei percorsi di costruzione e dal contenuto runtime delle tabelle.

## 2. Inoltro e risultato della scrittura

Il write del wrapper **`0x2A0890`** risolve `file[0] → dispositivo+0x24 → contesto[0]`, ottenendo l'handle grezzo. Lo passa a **`0x1FA090`**, che invoca il write del dispositivo. Conserva il conteggio restituito e copia **errore grezzo+`0x0C` → errore wrapper+`0x0C`**.

Il write grezzo **`0x2A0534`** risolve l'indice del volume tramite `0x2A0504`: quest'ultimo confronta il dispositivo del file con quello degli handle in record+`0x50`. Il callback effettivo viene letto da **record+`0x38`** e invocato a **`0x2A0582`**, con posizione del file, conteggio richiesto, buffer e un quarto parametro calcolato da stato/configurazione.

Nel percorso ordinario:

- ritorno callback zero: scrive errore zero e restituisce l'intero conteggio richiesto;
- ritorno callback nonzero: conserva quel valore nel campo errore e restituisce conteggio zero.

C'è un ramo separato: **se byte record+`0x49` vale 1**, a `0x2A0556/58` imposta esito zero e salta direttamente alla registrazione del risultato, **senza invocare il callback**. Il conteggio richiesto rimane intatto e viene restituito. Il codice locale dimostra questa semantica, ma non attribuisce un significato al flag né prova che sia attivo durante una scrittura fotografica. Non viene identificato come protezione fisica della scheda.

Questo ramo è distinto dal precedente dubbio sul wrapper con residuo positivo ed errore zero: qui il conteggio riportato è completo, pur senza chiamata al backend. Va risolto il produttore del flag per capire quando tale comportamento è intenzionale e raggiungibile.

## 3. Primo ingresso al backend SD

La cella iniziale **`0x376050 = 0x1684B4`** appartiene a DEVSD:. La routine riordina gli argomenti e chiama **`0x168410` con indice 0**. Quest'ultima calcola una voce di contesto e sceglie, in base al conteggio, tra **`0x25B9C0`** e **`0x25BB5C`**.

Se il trasferimento restituisce nonzero, il codice può interrogare **`0x25BF3C`**, chiamare **`0x25B63C`** con selettori differenti e rientrare nel tratto di trasferimento. Non viene ancora dedotto un numero massimo di tentativi né il significato fisico di questi servizi. Non sono stati ricostruiti il contratto MMIO, il busy della scheda o la garanzia di conservazione dopo interruzione di alimentazione.

## 4. Controllore degli aggiornamenti pendenti

**`0x2A1270(contesto, modo)`** usa il medesimo campo +`0x3C` che seleziona il differimento in `0x2A1054`:

| Modo | Comportamento verificato |
|---|---|
| 1 | Imposta +`0x3C = 1`; non tenta gli aggiornamenti di questo ramo |
| 0, campo già zero | Esce senza tentare la sequenza |
| 0, campo nonzero | Azzera +`0x3C`, poi tenta la sequenza |
| 2 | Tenta la sequenza senza cambiare qui +`0x3C` |
| Altro | Restituisce `0x01A00001` |

La sequenza è **`0x1F2484 → 0x2A10F4 → 0x2AB5E0`**. Dopo le prime due chiamate il risultato è conservato e confrontato; un esito nonzero salta le successive. Il ritorno finale conserva lo stato selezionato attraverso il rilascio della sincronizzazione. Le chiamate di sincronizzazione non dimostrano, da sole, persistenza fisica.

Il secondo consumatore **`0x2AB5E0`** controlla il flag **contesto+`198*4 = 0x318`**, distinto dal pendente +`0x1AC`. Usa indice +`0x31C`, valore +`0x320`, puntatore record +`0x324` e buffer +`0x328`. Sostituisce temporaneamente record+`0x34`, chiama **`0x2A0D70`** con selettore 10, poi ripristina il campo. Azzera +`0x318` soltanto se il risultato è zero.

È quindi ricostruita una sequenza concreta di aggiornamento di più strutture. Restano da attribuire i chiamanti del controllore e i comandi superiori che lo selezionano, prima di collegarlo a ogni chiusura o spegnimento.

## Evidenze e prossimo passo

[Script](../Python_Trace_Scripts/s33_trace_sd_backend.py), [JSON](../Ghidra_Results/ghidra_reports/sd_backend/verified_evidence.json), [disassemblaggio GNU](../Ghidra_Results/ghidra_reports/sd_backend/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_sd_backend.py`.

Esito: **16 SHA-256 dei payload, roundtrip ELF del blocco 00, 13 finestre, 17 collegamenti diretti e 24 istruzioni chiave**, oltre alle celle callback e ai nomi SD/NAND verificati. I collegamenti indiretti sono attribuiti combinando inizializzazioni, pool e slot verificati; non sono una traccia di esecuzione osservata.

Prossimo: produttori di record+`0x49`; dispatcher del wrapper `0x2A0A14` per `0x2015/0x2016`; chiamanti e modi di `0x2A1270`; contratto dei servizi `0x25B9C0/0x25BB5C`. Questi controlli devono precedere una conclusione sulla persistenza del JPEG.

## Continuazione sui controlli e sul close senza contesto file

Il [rapporto successivo](S33_Controlli_Completamento_e_Close_Volume.md) risolve PM `0x2015/16`, comando filesystem 3 e un chiamante close che ne ignora l’esito. Distinto dal close ordinario con contesto file nonnullo; persistenza fisica e shutdown restano aperti.

## Continuazione sui servizi SD inferiori

Il [rapporto trasferimenti SD](S33_Trasferimenti_SD_Errori_e_Polling.md) risolve il limite di tre tentativi esterni, gli esiti dei due servizi e il polling MMIO del completamento. Il limite dei tentativi non impone un timeout al polling interno; persistenza fisica e contratto completo del ramo dati restano aperti.

## Continuazione — lettore e trasferimento eseguiti

[S33_Dumper_RAM_SD_Settori_Cache_e_Trasferimento_Originale.md](S33_Dumper_RAM_SD_Settori_Cache_e_Trasferimento_Originale.md): lettore/cache28casi, trasferimento25, lookup integrato20 fino a callback dispositivo sintetica. ProdottoDSP dichiarato e driver simulato; non prova persistenza fisica o r/open/close integrati. Il rapporto distingue regressioni e limiti; nessun hardware.

## Continuazione — r/FAT/PMSD/DEVSD/close integrati

[S33_Dumper_RAM_SD_Catena_PMSD_DEVSD_e_Contratto_Conteggi.md](S33_Dumper_RAM_SD_Catena_PMSD_DEVSD_e_Contratto_Conteggi.md):22casi contratto conteggi/flag e13matrici r/FAT/close ora attraversano PMSD, DEVSD e adattatore SD originale, con2015/16 e semafori. Count raw intero/0 ed errore copiato; flag49=1 può riportare successo senza aggiornare buffer. Separazione FAT/r superata; motori dati e runtime flag restano aperti. Nessun hardware, GNU o BIN modificato.
