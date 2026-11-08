# S33 — handshake di attivazione e polling del dispositivo

Analisi statica V1.1, 19 ottobre 2026. Prosegue il [collegamento della destinazione ai registri](S33_Destinazione_Worker_e_Registri_Indirizzo.md). Nessuna esecuzione hardware.

## Risultato

L'attivazione **`0x29601C → 0x2EDC60`** comprende una sequenza di aggiornamenti dei controlli e **tre cicli di polling locali**. Nel percorso banca1 vengono letti i bit **`0x8`, `0x80`, `0x400`** del registro halfword **`0x0FE9813C`**. I cicli ripetono la lettura finché il valore mascherato è zero, senza timeout o chiamate allo scheduler nel tratto locale verificato.

La sequenza è associata all'attivazione dopo la programmazione degli indirizzi. **Non viene identificata come completamento del frame o ultimo uso del buffer.** Il wrapper conclude con r0=0, ma questo valore non sostituisce la verifica dell'ordinamento dei consumatori. Stima funzionale invariata: circa 10%.

## 1. Funzioni e selezione dei registri

`0x2EDC60` conserva l'argomento banca in r16 e ne ricava una forma booleana tramite `0x2ED448`. Risolve due funzioni dai pool:

| Pool | Funzione | Uso osservato |
|---|---|---|
| `0x2EE014` | `0x2EE7B0` | aggiornamento di un bit di controllo selezionato da indice |
| `0x2EE018` | `0x2EE9C4` | operazione sullo stato, selezionata da indice e modalità |

La banca zero usa i registri con prefisso `0x0FE90...`; la banca nonzero usa `0x0FE98...`. Nel percorso `0x29601C(1)` seguito dal chiamante è usata la seconda banca.

Le tabelle di indirizzi dei controlli sono `0x40CB04/0x40CB94`; quelle delle maschere `0x40CB4C/0x40CBDC`. Le voci rilevanti nella banca1 sono:

| Indice controllo | Registro halfword | Maschera |
|---|---|---|
| 2 | `0x0FE9812C` | `0x1` |
| 3 | `0x0FE9812C` | `0x2` |
| 5 | `0x0FE9812C` | `0x8` |
| 6 | `0x0FE9812C` | `0x10` |
| 7 | `0x0FE98138` | `0x1` |

I writer fanno una lettura halfword e una scrittura halfword, impostando o azzerando il bit individuato dalla maschera. Non sono semplici scritture di parole complete e non viene presunta un'atomicità hardware del read-modify-write.

## 2. Operazione di stato: lettura e scrittura sono distinte

Il servizio `0x2EE9C4` sceglie una maschera da indice e banca, poi chiama un accessor. Nella banca1, l'accessor è `0x309C44`, che usa una tabella di salti halfword a `0x309C60`.

Le quattro voci sono **4,41,20,32**, relative alla base con scala due. La voce operazione1 va quindi a **`0x309CB2`**. Il tratto carica il pool `0x309CB8`, contenente **`0x0FE9813C`**, e legge la halfword con `ldh.di` a `0x309CBC`. Il servizio applica poi la maschera dell'indice al valore letto.

L'operazione0 prende invece un altro percorso: legge la stessa halfword, preserva i bit superiori, sostituisce i **bit bassi 0..10** con la maschera fornita e scrive con `sth.di`. Questo comportamento può essere compatibile con un'operazione di notifica/acknowledgement, ma **non viene dichiarata una semantica write-one-to-clear** senza ulteriori prove sul dispositivo.

Confondere le due operazioni farebbe apparire come letture innocue anche passaggi che scrivono il registro di stato.

## 3. Sequenza verificata per banca1

Nel corpo `0x2EDC60..2EDD14`, sotto normali ritorni delle chiamate:

1. azzera i controlli 3,5,2 e, per banca1, anche 6;
2. esegue operazione0 sullo stato indice3;
3. imposta controllo3; legge ripetutamente stato indice3, maschera **`0x8`**, finché nonzero; azzera controllo3;
4. esegue operazione0 sullo stato indice7;
5. imposta controllo5; legge ripetutamente stato indice7, maschera **`0x80`**, finché nonzero; azzera controllo5;
6. per banca1, esegue operazione0 sullo stato indice10, imposta controllo6 e attende maschera **`0x400`** nonzero; azzera controllo6;
7. imposta e poi azzera controllo2.

I salti all'indietro sono a **`0x2EDCAE`**, **`0x2EDCD2`**, **`0x2EDCFA`**. Nei tre cicli non compaiono contatori, scadenze o sleep; il servizio chiamato per la verifica segue lettura MMIO e mascheramento. Questo non esclude watchdog o effetti esterni all'area analizzata, ma **non offre un limite locale all'attesa**.

La banca0 segue i primi due handshake, leggendo `0x0FE9013C` con maschere 8/128; il terzo è condizionato alla banca normalizzata uguale a 1. Le semantiche di tutte le altre combinazioni di accessor non sono generalizzate da questo percorso.

## 4. Wrapper e collegamento alla pipeline

Nel ramo con argomento1, `0x29601C` chiama la sequenza banca1, poi imposta il controllo indice7 nella stessa banca tramite `0x2EE7B0`. Infine ritorna con **r0=0 nel delay slot** a `0x29604E`.

Il chiamante già seguito a **`0x248832`** prepara r0=1 nel delay slot. Quindi il percorso condizionale studiato è coerente con questa sequenza di banca1, dopo la configurazione degli indirizzi.

Questo verifica **quali bit vengono scritti o attesi**, non il loro nome funzionale. I numeri degli indici della tabella non vengono presentati come numeri di bit: per esempio indice3 controllo corrisponde alla maschera2, mentre indice3 stato alla maschera8.

Resta da collegare una condizione che dimostri l'ultimo uso del buffer alla successiva cancellazione del flag software dello slot. Un handshake che compare durante l'attivazione non viene trasformato per inferenza in una garanzia di fine elaborazione.

## Evidenze e continuazione

[Script](../Python_Trace_Scripts/s33_trace_device_activation_handshake.py), [JSON](../Ghidra_Results/ghidra_reports/device_activation_handshake/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/device_activation_handshake/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_device_activation_handshake.py`.

Verificati **16 SHA-256, roundtrip ELF del blocco 00, 11 finestre, 9 collegamenti diretti, 34 istruzioni chiave e 10 pool**, oltre a dieci voci controllo, cinque maschere di stato pertinenti ai percorsi seguiti e la tabella di salti dell'accessor banca1. Le finestre includono il corpo dell'handshake fino all'uscita.

Prossimo: risalire alle notifiche del dispositivo e ai lettori successivi della pipeline, distinguendo avvio, stato operativo e fine uso. Durata dei buffer, semantica fisica dei bit e prova runtime restano aperte.


## Continuazione: gestori e attesa evento

Il [rapporto sulle notifiche](S33_Notifiche_Dispositivo_e_Attesa_Evento.md) collega il test di un diverso bit dello stato ai gestori, all’evento e all’attesa corrispondente. L’esito non controllato dell’attesa impedisce di usare il ritorno zero del wrapper come prova sufficiente di ultimo uso.
