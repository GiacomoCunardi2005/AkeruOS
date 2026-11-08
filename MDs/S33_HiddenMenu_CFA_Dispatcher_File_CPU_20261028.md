# S33 V1.1 — dispatcher CFA e servizi file sintetici

28 ottobre 2026. Cinque casi offline eseguono il dispatcher originale `0x28D66C`, selettore 0, nel simulatore GNU ARC700 con modello DSP sperimentale. **NON_INSTALLARE**.

Il banco chiama in ordine le modalità 0, 1 e 2, come nel frammento CFA esaminato, ma le invoca direttamente: non esegue lo scatto o il gate HiddenMenu in questa prova. Controlli di disponibilità, conversione del nome e servizi open/write/close sono fixture. La scrittura sintetica riceve puntatore `0x2040000` e lunghezza 2.048, senza leggere o scrivere dati immagine.

| Caso | Esito open | Esito write | Esito close |
|---|---:|---:|---:|
| Conteggio completo 2.048/2.048 | 0 | 0 | 0 |
| Conteggio corto 0/2.048, stato inferiore 0 | 0 | `0x700103` | 0 |
| Errore write simulato | 0 | 77 | 0 |
| Errore open simulato | 78 | 0 | 0 |
| Errore close simulato | 0 | 0 | 79 |

La modalità di scrittura originale confronta il conteggio restituito dalla fixture con quello richiesto e segnala `0x700103` nel caso corto. Le tre chiamate successive sono imposte dal banco anche dopo errore; la [precedente prova del gate CFA](S33_HiddenMenu_CFA_Prova_Gate_CPU_20261028.md) aveva verificato separatamente la stessa prosecuzione con dispatcher sostituito. I due banchi **non sono una singola esecuzione integrata**. Nel caso open fallita, la fixture scrive comunque un handle sintetico: il successo delle chiamate successive non dice cosa accadrebbe con un handle reale non valido.

Con percorso fornito dalla fixture `B:\DCIM\DSCN1000.JPG`, il codice originale passa alla fixture open `B:\DCIM\CFAi1000.raw`. Questo è un esempio verificato con una stringa sintetica, non il nome, il contenuto o la cartella osservati sulla macchina. I valori, le condizioni di disponibilità e i conteggi sono input del laboratorio. Non sono provate creazione file, persistenza, purezza RAW, corrispondenza col JPEG o capacità del buffer.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_cfa_dispatcher_cpu.py`. [Casi](../Risultati/HiddenMenu_RAW/cfa_dispatcher_cpu_20261028T144732Z/cases.json), [fixture](../Risultati/HiddenMenu_RAW/cfa_dispatcher_cpu_20261028T144732Z/fixture_patches.json), [script](../Python_Trace_Scripts/s33_verify_cfa_dispatcher_cpu.py). Le finestre originali sono confrontate col dump; hash firmware, tracce e ritorni sono verificati. Il primo tentativo si è arrestato su una cella di stato non mappata; nel secondo è stata mappata una regione sintetica e ottenuto PASS; la terza esecuzione aggiunge controlli su nome e trace. Nessuna modifica al firmware originale o a GNU.
