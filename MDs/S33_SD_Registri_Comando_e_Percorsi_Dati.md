# S33 — registri comando SD e percorsi dati

Analisi statica V1.1, 18 ottobre 2026. Continuazione di [trasferimenti, errori e polling](S33_Trasferimenti_SD_Errori_e_Polling.md). Nessuna prova hardware.

## Risultato

Ricostruita l'emissione del comando fino a quattro scritture halfword MMIO. Distinti il controllo iniziale, limitato a **8.000 iterazioni**, dal completamento successivo senza timeout locale.

Il ramo dati **`0x304004`** include copie CPU dal buffer alla porta **`0x0FF01834 − selettore`**. Il ramo **`0x3040DC`** usa invece un servizio di trasferimento con callback, attese sull'evento **`0x00E00005`** e controllo di avanzamento. Un buffer non allineato a quattro byte devia da questo ramo al percorso CPU. L'implementazione completa del servizio resta da attribuire prima di descriverlo come un preciso motore DMA.

Queste evidenze riducono il confine fra filesystem e controller, ma non dimostrano la conservazione fisica del JPEG dopo perdita di alimentazione. Circa 10% funzionale invariato.

## 1. Emissione del comando

Il dispatcher già seguito chiama **`0x25A278(selettore, comando, argomento_alto, argomento_basso, configurazione)`**. Il corpo conserva gli argomenti ed esegue:

| Indirizzo, meno il selettore | Dato scritto | Istruzione |
|---|---|---|
| `0x0FF01824` | Halfword del comando | `0x25A28E` |
| `0x0FF01828` | Halfword alta dell'argomento | `0x25A29A` |
| `0x0FF0182C` | Halfword bassa dell'argomento | `0x25A2A6` |
| `0x0FF0180C` | Halfword della configurazione | `0x25A2B2` |

Tutti gli accessi usano **`sth.di`**; ogni indirizzo viene calcolato con `rsub` a partire dal selettore. Nel percorso DEVSD: ricostruito il selettore è zero. La sequenza descrive le scritture osservabili nel codice; il nome fisico ufficiale dei registri non è stato ottenuto da un datasheet.

## 2. Attesa iniziale: limite e priorità degli esiti

**`0x25A5F8`** imposta il limite a **`0x7D << 6 = 8000`**, poi legge:

- primo stato: **`0x25A084 → ldh.di` a `0x0FF01800 − selettore`**;
- secondo stato: **`0x25A0BC → ldh.di` a `0x0FF01804 − selettore`**.

La routine applica nell'ordine:

| Condizione | Azione e risultato |
|---|---|
| Primo stato bit 0 | Chiama `0x25A098` con maschera 1, restituisce `0x00E00100` |
| Altrimenti primo stato bit 1 | Chiama lo stesso helper con maschera 2, restituisce `0x00E00101` |
| Altrimenti primo stato bit 2 | Chiama lo stesso helper con maschera 4, restituisce zero |
| Altrimenti nibble basso del secondo stato nonzero | Restituisce `0x00E00208` |
| Altrimenti | Incrementa il contatore e ripete |
| Contatore esaurito | Restituisce `0x00E00100` |

L'helper **`0x25A098`** rilegge il primo registro e riscrive una halfword includendo i bit della maschera. Il codice mostra il writeback; una semantica fisica come write-one-to-clear non viene dedotta dal solo accesso.

Il limite è in **iterazioni**, non millisecondi. Inoltre `0x00E00100` è condiviso fra esaurimento e ramo bit 0: il solo codice restituito non distingue sempre la causa.

Questo controllo è distinto da **`0x2E5634 → 0x25A658`**, che interroga il secondo registro con una diversa priorità dei bit e senza timeout nel corpo locale già verificato. Non si estende il limite di 8.000 a quel ciclo.

## 3. Percorso CPU: buffer → porta dati

**`0x304004`** esamina l'allineamento del buffer. Il ramo halfword qui verificato legge con **`ldh.ab [buffer,2]`** e invoca **`0x25A430`**, che scrive con **`sth.di`** alla porta **`0x0FF01834 − selettore`**. Il bit 0 del buffer può deviare a `0x303F24`, non analizzato completamente in questo rapporto.

Il corpo halfword usa il primo registro di stato per decidere il trasferimento e può raggruppare scritture. Rami d'errore consultano il secondo registro e scelgono codici dai pool:

- `0x304380 = 0x00E01310`;
- `0x304384 = 0x00E01200`.

Questi pool sono caricati da `ld.as`: gli offset del disassemblatore sono scalati correttamente per quattro nella verifica.

Dopo il trasferimento richiesto, il polling finale attende il bit 7 del secondo stato, con limite **`0x1B2920` iterazioni** e codice di esaurimento **`0x00E01110`**. Il corpo del trasferimento contiene anche cicli di attesa/ritardo e aggiornamenti dei contatori: il limite del polling finale non fornisce un tempo massimo a tutta la copia.

## 4. Percorso tramite servizio, callback ed evento

**`0x3040DC`** controlla i due bit bassi del buffer: se non sono entrambi zero, chiama **`0x304004`**. Nel ramo allineato:

1. **`0x25A488`** restituisce l'indirizzo della medesima porta dati; viene passato con dimensione totale e altri parametri a **`0x2BFE88`**, che fornisce un oggetto di trasferimento sullo stack.
2. Prepara callback e servizi tramite **`0x266768/0x26671C`**, modifica una maschera tramite **`0x25A444`** e pulisce bit dell'evento **`0x00E00005`**.
3. Chiama **`0x2C00E4`**, passando buffer, callback di completamento e cella di uscita.
4. Attende con **`0x158D04`**, argomento finale **100**. L'unità temporale di questo argomento non è dimostrata qui.
5. In base al risultato, legge avanzamento tramite **`0x266E9C`** oppure lo stato evento tramite **`0x158E28`**, poi sceglie completamento/errore e pulizia.

I pool stabiliscono le associazioni:

| Selettore zero / nonzero | Zero | Nonzero |
|---|---|---|
| Callback di stato | `0x3042E4` | `0x304324` |
| Callback passata al servizio dati | `0x304368` | `0x304374` |

Le callback di completamento pubblicano rispettivamente bit **`0x200`** e **`0x200000`** sull'evento. Le callback di stato leggono il secondo registro e pubblicano altri bit per le condizioni esaminate. Questo collega in modo concreto il servizio inferiore al consumatore in attesa; non prova un interrupt reale osservato né identifica ancora l'intero controller di trasferimento.

## 5. Avanzamento e pulizia

Quando l'attesa restituisce nonzero, il codice può leggere un contatore di avanzamento. Se cambia, azzera il contatore locale dei controlli senza progresso. Se resta uguale, lo incrementa e dopo **nove controlli consecutivi invariati** abbandona il percorso, scegliendo **`0x00E01211`** dopo il tentativo di pulizia.

Questo non è un limite di nove attese totali: il conteggio riparte quando osserva progresso. Restano da ricostruire la semantica completa dell'attesa e gli altri rami di errore.

Il tratto finale modifica di nuovo la maschera tramite **`0x25A464`**, richiama `0x2667B0` e restituisce **r13**, conservato attraverso queste chiamate. Errori o esiti della pulizia non sostituiscono automaticamente il risultato conservato. Alcuni rami di uscita anticipata saltano il tratto comune: non si afferma una pulizia universale di ogni risorsa acquisita.

## Evidenze e prossimo passo

[Script](../Python_Trace_Scripts/s33_trace_sd_mmio_data.py), [JSON](../Ghidra_Results/ghidra_reports/sd_mmio_data/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/sd_mmio_data/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_sd_mmio_data.py`.

Verificati **16 SHA-256**, roundtrip ELF del blocco 00, **7 finestre, 24 collegamenti e 32 istruzioni chiave**, oltre ai pool degli errori, callback, evento e contatori. Solo evidenza statica V1.1.

Prossimo: contratto dell'oggetto `0x2BFE88`, esecuzione `0x2C00E4`, completamento `0x2C0E70`, gestione degli errori dopo acquisizioni parziali e rapporto fra callback, riuso dei buffer e successo del salvataggio.

## Continuazione sul rilascio dell’oggetto

Il [rapporto oggetto/rilascio](S33_Oggetto_Trasferimento_e_Rilascio.md) risolve `0x2C0E70` come alias della stessa routine usata per la pulizia dopo errori, e verifica disattivazione MMIO del primo oggetto e azzeramento della cella handle. Il rilascio non è una verifica separata di persistenza.

## Continuazione sulla notifica di completamento

Il [rapporto avvio/callback](S33_Avvio_Trasferimento_e_Callback_SD.md) collega parametro callback, due slot globali e consumatori condizionati da MMIO fino all’evento SD `0xE00005 / 0x200`. Restano condizionali invocazione runtime, arbitraggio e completamento fisico.

## Continuazione — motori read e PIO eseguiti

[S33_Dumper_RAM_SD_Lettura_PIO_Motori_e_Completamento_Originali.md](S33_Dumper_RAM_SD_Lettura_PIO_Motori_e_Completamento_Originali.md):20PIO,28motori,13r/FAT/PMSD/SD/PIO/close. Il confine prima degli interi B15B4/B16D0 è superato: preparazione,descrittori,copia CPU/MMIO e completamento ora eseguiti. Dispatcher comandi2E52F4 e25AA8C restano fixture;profili sintetici,non prova elettrica. Percorso write/asincrono non generalizzato dal read. Nessun hardware o BIN modificato.

## Continuazione — dispatcher e gate originali eseguiti

[S33_Dumper_RAM_SD_Comandi_Risposte_e_Controllo_Originali.md](S33_Dumper_RAM_SD_Comandi_Risposte_e_Controllo_Originali.md):40casi isolati e16scenari r/FAT/PMSD/SD/comandi/PIO/close;2E52F4 e25AA8C non sono più fixture nel nuovo profilo. Provati timeout8000 e limiti gate2000, risposta dalla porta originale, tipo0 che scarta errore e resetcountalto fisso0FF01854. Errori comando/risposta dati propagati dopo3tentativi, erroreFAT ancora trasformato in02. Quattro regressioni13casi PASS. Le prove precedenti mantengono il proprio confine; nientehardware. Prossimo25A83C/2801F0 asincrono e lifetime buffer, produttoreflag49. NON_INSTALLARE.

## Continuazione — copiePIO e servizio write eseguiti

[36nuovi casi](S33_Dumper_RAM_SD_Scrittura_Asincrona_e_PIO_Originali.md) eseguono3040DC,2BFE88/2C00E4 e callback/eventi/status/release originali. Il profilo1024B usa slot36B3D8/dispatcher2689FC,distinto da267F20.9stagnanti→E01211,un progressoal5°→14timeoutprimaerrore. Dodici casiPIO seguono304004/303F24 finoagli store25A430:8copie1024B e4parziali256B conE01200/E01310,bytecatturati dopo storeCPU. MMIO e clock sintetici,non SDfisica. Il vecchio rapporto rimane statico;questa continuazione aggiunge esecuzione nei profili dichiarati.
