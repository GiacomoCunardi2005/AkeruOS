# S33 — cicli di esecuzione alternativi e mailbox

Analisi statica V1.1, 19 ottobre 2026. Continuazione di [ingressi alternativi e handshake](S33_Percorsi_Interrupt_Alternativi.md). Nessuna esecuzione hardware.

## Risultato

Le entrate **`0x337218`** e **`0x23FB10`** raggiungono cicli persistenti che aspettano un campo di controllo, consumano una mailbox e chiamano una funzione conservata nel contesto. L'attesa usa un helper che esegue **`sleep 0`**.

Risolte **quattro mailbox, organizzate in due coppie direzionali**. I consumatori liberano la cella prima dell'esecuzione della callback: **cella zero non significa lavoro precedente terminato**. Questo separa l'ammissione di una nuova richiesta dal completamento del lavoro. Circa 10% funzionale invariato; significato globale dei due percorsi e notifiche finali ancora da attribuire.

## 1. Le due richieste di avvio hanno un chiamante comune

Nel tratto **`0x141C60..0x141C78`** il firmware chiama nell'ordine **`0x159A1C`** e **`0x159CE0`**. Confronta ogni ritorno e salta all'uscita sul primo esito nonzero. Il codice precedente effettua altre preparazioni, ma la funzione complessiva non è ancora attribuita a una specifica modalità utente.

Le due routine chiamate installano i percorsi e attendono il passaggio 1→2 già ricostruito. Le nuove prove seguono ciò che accade dopo l'ingresso: sono cicli di servizio, non semplici routine che impostano 2 e ritornano subito al chiamante originale.

## 2. Ciclo di esecuzione, campo di controllo e callback

| Percorso | Contesto principale | Campo controllato | Consumatore del lavoro |
|---|---|---|---|
| Primo | `0x424200` | +8 = `0x424208` | `0x33737C` |
| Secondo | `0x424400` | +8 = `0x424408` | `0x2D526C` |

Entrambi aspettano che campo +8 valga **4**, richiamando **`0x3371C0`**. Questo helper contiene **`sleep 0`**, alcuni nop e il ritorno. Il codice locale non consente una conversione in durata o una misura del consumo energetico.

Quando il campo vale 4, il ciclo scrive **3**, modifica `limit0/control0/count0` e tenta il consumo della mailbox. Se il consumatore restituisce zero, chiama la funzione a **contesto+4** con il valore ricevuto. Poi torna al controllo del campo +8. Se il consumatore restituisce nonzero, il ramo esaminato entra in un salto su sé stesso; non viene presentato come normale terminazione del servizio.

Nel primo percorso la callback timer **`0x3372E8`** scrive **4 a `0x424208`**, dopo una richiesta a `0x16DAA8`, e programma i registri timer. Un altro tratto decide se riarmare il timer in base al campo 3. I valori dei registri sono evidenza di configurazione, non tempi misurati. La verifica del secondo tratto di riarmo non dimostra da sola l'intera origine della sua notifica.

## 3. Quattro celle e due direzioni

| Cella | Produttore | Consumatore |
|---|---|---|
| `0x427B00` | `0x2D51EC` | `0x33737C` |
| `0x428200` | `0x33739C` | `0x2D520C` |
| `0x428300` | `0x2D522C` | `0x2D526C` |
| `0x428400` | `0x2D528C` | `0x2D524C` |

Ogni produttore attende che la propria parola sia zero, scrive l'argomento e invoca **`0x16DA68`** con un selettore di canale. Nei corpi esaminati il ciclo di attesa della cella occupata non contiene un contatore o un timeout locale. La semantica completa della richiesta di notifica deve ancora essere seguita.

Ogni consumatore restituisce **1** quando trova la cella vuota. Altrimenti copia la parola nella cella di uscita del chiamante, scrive zero nella mailbox e restituisce zero. Lo zero ha quindi ruolo di sentinella di cella libera: non viene dimostrato che un valore nullo possa rappresentare una richiesta valida.

Sono collegati anche due siti concreti di invio: **`0x293AAE → 0x2D51EC`** e **`0x247330 → 0x2D522C`**. I dati e il risultato finale delle operazioni a monte restano da attribuire; la presenza dell'invio non dimostra un salvataggio JPEG riuscito.

## 4. Ammissione e completamento sono eventi distinti

Nel ciclo del primo percorso l'ordine verificato è:

```text
0x33737C: copia richiesta e azzera la mailbox
ritorno al ciclo
0x3372DC: chiama la funzione del contesto
```

Il secondo segue lo stesso schema con `0x2D526C` e chiamata a `0x23FBD0`. La cella può quindi essere già libera mentre il lavoro ricevuto è ancora in esecuzione. Un produttore che osserva zero può pubblicare un'altra richiesta senza aver provato la fine della callback precedente.

Questo descrive la proprietà locale della mailbox, non una coda generale o una garanzia di sicurezza contro produttori concorrenti. Le letture e gli store `.di` non bastano da soli ad attribuire l'intero contratto di ordinamento o coerenza della memoria. Il ciclo di vita del buffer deve includere l'esito del lavoro, distinto dalla liberazione della cella.

## Evidenze e continuazione

[Script](../Python_Trace_Scripts/s33_trace_alternate_execution_loops.py), [JSON](../Ghidra_Results/ghidra_reports/alternate_execution_loops/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/alternate_execution_loops/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_alternate_execution_loops.py`.

Verificati **16 SHA-256**, roundtrip ELF del blocco 00, **12 finestre, 12 collegamenti diretti e 27 istruzioni chiave**. Nessuna prova del risveglio fisico o del comportamento dei due servizi sulla fotocamera.

Prossimo: callback conservate nei due contesti, contenuto delle richieste inviate e percorso di ritorno della risposta, per collegare mailbox e fine effettiva del lavoro immagini.

## Continuazione sulle risposte

Il [rapporto risposte/eventi](S33_Risposte_Worker_e_Eventi_Fine_Lavoro.md) collega record e mailbox inversa ai ricevitori, separa esito e notifica e identifica un wrapper che non confronta il risultato della propria attesa. Il significato finale dei payload rimane da attribuire.
