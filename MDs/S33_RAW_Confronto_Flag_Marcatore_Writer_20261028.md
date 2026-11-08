# S33 V1.1 — confronto dei controlli del flag RAW

28 ottobre 2026. Analisi statica offline del firmware originale V1.1; nessuna acquisizione, modifica firmware o accesso alla fotocamera. **NON_INSTALLARE**.

## Risultato condizionale

Il getter `0x28D48C` restituisce il byte `0x36C26E` senza normalizzarlo. A `0x1B91F0` il controllo che precede il marcatore `0x28D5BC` richiede il valore **esattamente 1**: un valore diverso salta a `0x1B923A`. A `0x1B9296`, il controllo verso il writer richiede invece un valore **diverso da zero**; occorrono inoltre il puntatore non nullo e il selettore 3 per raggiungere il ramo che richiede 2N byte.

| Byte letto | Controllo flag del marcatore | Controllo flag del writer |
| --- | --- | --- |
| 0 | falso | falso |
| 1 | vero | vero |
| 2 | falso | vero |
| 255 | falso | vero |

La tabella confronta i due predicati, **supponendo che le due letture diano lo stesso valore**. Il controllo vero del marcatore non prova il suo raggiungimento dall'acquisizione, né il controllo vero del writer prova l'invocazione effettiva o la scrittura del file. Le istruzioni intermedie includono chiamate a `0x141ED8`, eventualmente `0x159BF0` e `0x141EBC`, e, per un ulteriore ramo condizionale, anche una chiamata indiretta. Non è dimostrato che queste chiamate o un altro task lascino il flag invariato. Le altre scritture del buffer e il suo contenuto non sono analizzati qui.

Il setter originale conserva il byte ricevuto e i precedenti test CPU sintetici hanno osservato i valori 2 e 255. La callback della voce 12 bit, invece, inverte lo stato normalizzandolo a 0 o 1: il valore 2 non deriva dalla sequenza GUI osservata. Questo confronto **non è una procedura per impostare 2**: gli effetti sugli altri consumatori, il ciclo di vita del flag e la sicurezza della macchina sono sconosciuti. Anche saltando questo marcatore non è provata la purezza del RAW, né la disponibilità, capacità o sincronizzazione del buffer, né il salvataggio RAW e JPEG dello stesso scatto.

## Riproduzione

`python3 Python_Trace_Scripts/s33_verify_raw_flag_gate_static.py` confronta sei finestre originali con il MainCode storico, verifica 20 istruzioni e riporta i quattro casi condizionali: [evidenza](../Risultati/HiddenMenu_RAW/flag_gate_static_20261028T143412Z/evidence.json), [disassemblaggio GNU](../Risultati/HiddenMenu_RAW/flag_gate_static_20261028T143412Z/gnu_windows.txt). Non esegue CPU o hardware. Setter/getter provati separatamente in CPU con contesti sintetici: [rapporto](S33_HiddenMenu_RAW_Massimo_20261027.md). Il codice tra i due getter e i consumer del flag richiedono ulteriore verifica.
