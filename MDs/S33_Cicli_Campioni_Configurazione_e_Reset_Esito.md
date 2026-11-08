# S33 — cicli sui campioni, configurazione e reset dell'esito

Analisi statica V1.1, 19 ottobre 2026. Continuazione del [contratto dei callback](S33_Contratto_Callback_Worker_e_Codici_Ritorno.md). Nessuna esecuzione hardware.

## Risultato

Le routine inferiori `0x1FD614/0x1FEAA0` contengono cicli CPU che scrivono campioni a **16 bit** in memoria. Nei tratti verificati, la sorgente deriva dall'argomento r0 e la destinazione dall'argomento r1. Nel ramo finale selezionato dal valore 1, i campioni letti vengono spostati a destra di un bit prima della scrittura.

Sono stati inoltre ricostruiti i due setter **`0x1FD38C/0x1FE960`**, già presenti nei descrittori come funzioni di preparazione: entrambi modificano lo stesso controllo a `0x3695DC` e il byte selettore `0x369620` **prima** dei controlli finali degli argomenti. Un ritorno di errore locale non implica quindi configurazione invariata.

Trovato anche un secondo scrittore del risultato: l'invio di una richiesta azzera **`0x36AD58`** nel delay slot del salto al produttore della mailbox. Il lettore finale rimane da identificare. Circa 10% funzionale invariato.

## 1. Origine degli indirizzi nei cicli CPU

| Routine inferiore | Sorgente nel tratto verificato | Destinazione nel tratto verificato |
|---|---|---|
| `0x1FD614` | r0 in ingresso, conservato in r13 a `0x1FD64C` | r1 in ingresso, conservato a stack+4 a `0x1FD646` |
| `0x1FEAA0` | r0 in ingresso, conservato in r18 a `0x1FEAE0` | r1 in ingresso, conservato a stack+4 a `0x1FEAE4` |

I backend e wrapper precedenti inoltrano gli argomenti r0/r1: per la chiamata worker documentata, corrispondono alle parole **payload+0/+4**. Questo attribuisce un uso come indirizzi sorgente/destinazione nei cicli, senza stabilire dimensione dell'allocazione o proprietà dell'intero buffer.

Nel ramo finale del fallback a `0x1FE2C6`, il selettore è letto da stack+`0x54`; nel percorso precedente verificato `0x1FE100..10A` viene aggiornato dal byte `0x369620` dopo la chiamata comune a `0x1FD4E4`. Il preferito legge direttamente lo stesso byte a `0x20047E`.

Quando il selettore vale 1, i tratti `0x1FE2FE..338` e `0x2004BE..4F4`:

1. costruiscono indirizzi di sorgente e destinazione con offset scalati;
2. leggono halfword con `ldh`;
3. applicano `asr` di un bit al valore letto;
4. scrivono halfword con `sth/stw_s` e avanzamenti dei puntatori.

Per il singolo campione letto senza estensione del segno, il valore scritto equivale a **floor(campione/2)**. È una relazione locale fra lettura e scrittura; non è una ricostruzione completa dell'algoritmo né una misura sui pixel della fotocamera.

Nei tratti successivi per selettori 2/3, i cicli usano confronti per scegliere fra più indirizzi sorgente, poi eseguono ancora letture, shift e scritture halfword. Sono candidati a una gestione dei bordi, ma questa interpretazione rimane un'inferenza: non vengono assegnati nomi di formato, colore o interpolazione.

## 2. Setter di preparazione e controllo condiviso

I descrittori del [rapporto sui produttori](S33_Produttori_Descrittori_e_Callback_Concreti.md) contengono `0x1FE960` nel campo +0 del ramo preferito e `0x1FD38C` nel campo +4 del ramo fallback. L'ordine globale delle loro invocazioni deve ancora essere chiuso.

| Proprietà | `0x1FD38C` | `0x1FE960` |
|---|---|---|
| Origine selettore | byte sullo stack in ingresso; letto a stack+4 dopo push r13 | r6 |
| Destinazione selettore | `0x369620` | `0x369620` |
| Record condiviso | `0x3695DC` | `0x3695DC` |
| Controllo finale | r4 ≥ r6 e r5 ≥ r7, confronti signed | r2 ≥ r4 e r3 ≥ r5, confronti signed |
| Ritorno se confronti soddisfatti | 0 | 0 nel delay slot del ritorno |
| Altro ritorno | `0x2711` | 1 nel delay slot del ritorno |

Per selettori 1, 2 e 3 vengono scritti parametri numerici nel record, compresi gli shift a **`0x36961C/1E`**:

| Selettore | Shift a `0x36961C` | Shift a `0x36961E` |
|---|---|---|
| 1 | 4 | 3 |
| 2 | 4 | 4 |
| 3 | 3 | 3 |

Entrambi i setter scrivono il byte selettore e campi del record prima di decidere il ritorno finale. Se il selettore non è 1/2/3, saltano l'inizializzazione di questi gruppi di parametri ma proseguono con altre scritture e confronti. Non è presente in questi corpi un rifiuto preliminare universale del selettore né un ripristino dei campi modificati.

Il nome funzionale dei parametri rimane aperto. Il fatto che i due setter condividano il record non dimostra che i due backend siano equivalenti o utilizzabili contemporaneamente senza sincronizzazione.

## 3. Reset del risultato prima dell'invio

La routine `0x247310` prepara richiesta tipo 0, azzera il byte `0x36AD54` e mantiene r2=0. A **`0x247330`** esegue un salto con delay slot al produttore **`0x2D522C`**. Nel delay slot **`0x247334`**, `st_s r2,[r3,4]` con r3=`0x36AD54` scrive:

```text
0x36AD58 = 0
```

Questa scrittura precede l'ingresso al produttore della mailbox. Il risultato ha quindi almeno due origini già verificate:

- **zero alla preparazione della richiesta**;
- **payload della risposta**, scritto dall'handler `0x247364` dopo una risposta tipo 1.

Il valore zero isolato non distingue questi due momenti. Il wrapper d'attesa `0x247338` attende l'evento, lo pulisce e imposta il byte `0x36AD54=1` nel delay slot del ritorno; non legge la parola risultato e non confronta il ritorno dell'attesa prima di impostare il byte.

La ricerca di riferimenti esatti a `0x36AD58/54` nei blocchi 00–10, in ordine pool e immediato ARC, ha trovato i siti locali e un candidato nella tabella dati del blocco 06. Questa ricerca **non esclude lettori tramite indirizzi intermedi, offset o altri percorsi**. Il lettore finale del risultato resta aperto; il candidato dati non è promosso a codice.

## Evidenze e continuazione

[Script](../Python_Trace_Scripts/s33_trace_worker_sample_loops.py), [JSON](../Ghidra_Results/ghidra_reports/worker_sample_loops/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/worker_sample_loops/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_worker_sample_loops.py`.

Verificati **16 SHA-256, roundtrip ELF del blocco 00, 12 finestre, 7 collegamenti e 56 istruzioni chiave**. I due setter sono inclusi fino al ritorno; dei corpi inferiori più lunghi sono verificate finestre mirate. Nessun test di allocazione, sovrapposizione o durata fisica dei buffer; nessuna prova di JPEG persistente.

Prossimo: collegare l'invocazione dei setter ai parametri reali, ricostruire il ruolo della routine comune `0x1FD4E4`, e cercare lettori del risultato attraverso indirizzi intermedi. Rimangono aperti i callback del descrittore `0x442630`, la sincronizzazione e l'ammissione delle modalità.


## Continuazione: ricampionamento comune

Il [rapporto sull’interpolazione](S33_Interpolazione_Griglia_due_Componenti.md) ricostruisce `0x1FD4E4`, incluse le due componenti, i troncamenti signed16 e la sovrascrittura della griglia. Questo aggiunge un cambio di rappresentazione da verificare nel ciclo dei buffer; formato e durata restano aperti.
