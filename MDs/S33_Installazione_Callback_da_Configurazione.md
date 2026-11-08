# S33 — installazione dei callback dalla configurazione

Analisi statica V1.1, 19 ottobre 2026. Continuazione della [selezione dei callback](S33_Descrittore_Worker_e_Selezione_Callback.md). Nessuna esecuzione hardware.

## Risultato

Individuato lo scrittore dei campi usati dal worker: **`0x15DF98`**, in un ramo condizionale, prende un puntatore da **configurazione d'ingresso+`0x110`** e ne copia cinque parole nei controlli a **`0x3674C0..0x3674D0`**.

I due callback già seguiti provengono quindi da **descrittore+8/+12**, rispettivamente per preferita e fallback. Risolti due chiamanti con oggetti a **`0x4424B8`** e **`0x445510`**. I loro contenuti effettivi e i relativi produttori restano da ricostruire: non vengono ancora assegnati nomi alle funzioni installate. Circa 10% funzionale invariato.

## 1. Ingresso e controllo del formato

La routine **`0x15DF98`** conserva il primo argomento in r16 e confronta la sua prima parola con **328 (`0x148`)**. Se il confronto non coincide, il ramo prepara un esito diverso e salta verso l'uscita comune; non entra nella continuazione normale verificata.

Questo è compatibile con un campo di formato/dimensione di una struttura, ma il nome simbolico originale non è noto. Non prova che ogni puntatore contenuto nella struttura sia valido o che tutte le uscite di errore ripristinino lo stato precedente.

Due siti di chiamata verificati:

| Sito | Primo argomento |
|---|---|
| `0x12F77C` | `0x4424B8`, caricato dal pool `0x12F91C` |
| `0x1649AE` | `0x445510`, caricato dal pool `0x164B94` |

Sono oggetti di configurazione passati dal firmware. Non vengono presentati come strutture iniziali interamente ricavate dal payload: i valori dei loro campi dopo la preparazione non sono ancora attribuiti.

## 2. Ramo che installa il descrittore

Il tratto **`0x15E560`** raggiunge la copia quando la parola temporanea stack+160 vale **1** e quella stack+168 vale **0**. Altrimenti devia a un altro ramo, fuori dalla copia qui descritta. Il significato di queste condizioni rispetto alle modalità utente resta aperto.

A **`0x15E570`**, l'istruzione **`ld.as r1,[r16,68]`** legge un puntatore a **input+`68*4 = 0x110`**. È un offset scalato, non +68 byte. Il puntatore identifica un descrittore di cinque parole usate dal tratto seguente.

| Campo del descrittore | Campo del controllo `0x367490` | Destinazione assoluta |
|---|---|---|
| +0 | +`0x30` | `0x3674C0` |
| +4 | +`0x34` | `0x3674C4` |
| +8 | +`0x38` | `0x3674C8` |
| +12 | +`0x3C` | `0x3674CC` |
| +16 | +`0x40` | `0x3674D0` |

La copia avviene con store separati. Non è dimostrata un'installazione atomica dei cinque campi né una sincronizzazione con ogni lettore.

## 3. Collegamento al worker e limiti delle guardie

Le destinazioni **`0x3674C8/CC`** coincidono con le sorgenti del builder già verificato: vengono trasferite nel descrittore di lavoro, copiate nel payload della richiesta e usate dalla chiamata indiretta del worker. La catena ora risale fino all'input dell'inizializzatore:

```text
input+0x110 → descrittore callback+8/+12
→ controlli 0x3674C8/CC → descrittore di lavoro
→ richiesta mailbox → chiamata worker
```

Il codice contiene poi controlli sui valori appena letti: per alcuni gruppi nulli salta a `0x15E4F8`, e il ramo a `0x15E614` richiede anche il quinto valore nonzero prima di proseguire. **Le scritture dei campi precedono queste decisioni**. Non si presume quindi che una deviazione successiva significhi che il controllo sia rimasto immutato.

Restano da verificare tutte le condizioni, i rami alternativi e l'eventuale ripristino. La presenza delle guardie non dimostra da sola che il worker non possa mai osservare un callback nullo o una configurazione transitoria.

## 4. Cosa manca per identificare l'elaborazione concreta

Il rapporto individua il produttore locale dei due puntatori, ma non ancora le funzioni effettive. Servono i writer dei campi **`0x4424B8+0x110`** e **`0x445510+0x110`**, e il contenuto dei descrittori selezionati nei rami reali.

Finché questa parte rimane aperta, non si attribuisce universalmente ai callback una funzione JPEG, un formato immagine o un contratto di proprietà del buffer. Il risultato di ritorno e la notifica dell'evento restano canali distinti, come nel rapporto precedente sulle risposte.

## Evidenze e continuazione

[Script](../Python_Trace_Scripts/s33_trace_worker_callback_install.py), [JSON](../Ghidra_Results/ghidra_reports/worker_callback_install/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/worker_callback_install/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_worker_callback_install.py`.

Verificati **16 SHA-256**, roundtrip ELF del blocco 00, **5 finestre, 2 collegamenti diretti e 21 istruzioni chiave**, oltre ai pool di destinazione e configurazioni. Nessuna misura hardware o prova di persistenza del JPEG.

Prossimo: costruzione delle due configurazioni e descrittori puntati da +`0x110`, identità dei callback e gestione delle installazioni parziali.


## Continuazione: produttori risolti parzialmente

Il [rapporto sui produttori](S33_Produttori_Descrittori_e_Callback_Concreti.md) risolve i due puntatori a `0x442630/0x445A6C` e identifica, nel secondo percorso selezionato, `0x1653C0/0x165338`. I contenuti e produttori indicati come aperti sopra restano tali solo per i campi e rami non ancora attribuiti; semantica, runtime e rollback restano aperti.
