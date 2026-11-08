# S33 V1.1 — possibile ritorno da ChangeColorMenu a CaptureMenu con argomento 5

27 ottobre 2026. Analisi statica offline dei payload V1.1, confrontati nelle
finestre studiate con `DUMPS/MainCode.dmp`; indirizzi sulla mappa candidata.
Nessun intervento sulla fotocamera o sulla SD.

## Risultato

È stata individuata una **sorgente statica dell'argomento 5** per la richiesta
`0x1453E4(2, 5)`, finora ignota. Il primo record della risorsa di classe
`0x15`, ID `0x4800`, del descrittore `ChangeColorMenu` contiene proprio la
coppia `(argomento 5, destinazione 2)`. L'ID 2 corrisponde al descrittore
`CaptureMenu`. Il nome è interno al firmware e non identifica da solo il testo
visualizzato o il comando fisico.

| Collegamento | Evidenza nei byte originali |
| --- | --- |
| Slot oggetto `0xBB` | `0x3F5BEC` → descrittore `0x982064`, nome `ChangeColorMenu`; array risorse `0x89983C`. |
| Risorsa | Primo puntatore dell'array → `0x98202C`: ID `0x4800`, classe `0x15`, quattro record di passo 28 a `0x981FBC`. |
| Record zero | `0x981FBC`: halfword iniziali 606/606/606, word `+12`=26, word `+16`=5, halfword `+20`=2, word flag iniziale `+24`=8. |
| Destinazione | Slot oggetto 2 `0x3F5908` → `0x9802AC`, `CaptureMenu`. |

La struttura dei record e il loro utilizzo da parte dell'handler condiviso
sono documentati anche nell'[analisi delle destinazioni di CaptureMenu](S33_GUI_CaptureMenu_Destinazioni_20261027.md).
La risorsa `0x4801` di `CaptureMenu` include un record con destinazione
`ChangeColorMenu` e argomento zero: se selezionato e superate le guardie,
può richiedere l'apertura dell'oggetto `0xBB`. La scoperta corrente aggiunge
un possibile percorso inverso: l'elemento zero di `ChangeColorMenu` può
richiedere `CaptureMenu` con argomento 5.

## Condizioni e limiti

Il wrapper `ChangeColorMenu` a `0x7CAD08` inoltra all'engine `0x169F60` con
filtro e tabella originali `0x982084`/`0x982094`. Per l'evento `0x4405`, il
callback `0x7CAD40` chiama `0x145764` con l'ID `0x4800`. È una chiamata al
servizio, non la prova che la risorsa sia stata effettivamente visualizzata.

La tabella classi iniziale `0x77F728` collega classe `0x15` a `0x631610`, e la
relativa tabella eventi associa `0x0580` all'handler `0x631878`. **Se** la
risorsa viene registrata e selezionata, l'evento è recapitato all'handler e
l'indice calcolato è zero, l'handler controlla che l'indice sia nel limite e
che i bit 0 e 1 del flag siano chiari. I flag iniziali del record hanno valore
8, quindi quei due bit sono inizialmente chiari; il valore runtime può
cambiare. La routine esegue anche chiamate intermedie e richiede il bit 1 nel
risultato del servizio `0x1450D8` con selettore `0x14`. Se le guardie sono
superate e i campi `+16` e `+20` sono ancora 5 e 2 quando letti, passa
`(2, 5)` a `0x1453E4`. Non si assume che servizi o stato rimangano invariati.

Secondo l'[analisi dell'ingresso](S33_GUI_CaptureMenu_Argomento_Ingresso_20261027.md),
se il gestore consegna senza alterazioni il 5 a `CaptureMenu` e il successivo
callback lo legge invariato, `0x7CB118` esegue la sequenza relativa alla
risorsa `0x4801`. Redirezione, hook, filtri, ordine degli eventi e selezione
reale restano da verificare: la catena è una possibilità statica, non una
navigazione osservata.

## Riproduzione

`python3 Python_Trace_Scripts/s33_verify_gui_changecolor_capture_return.py`
ha prodotto **PASS statico circoscritto**: controlla descrittori, tabella,
record, istruzioni e corrispondenza dei rispettivi intervalli col dump.
[Evidenze e hash](../Risultati/GUI_S33/changecolor_capture_return_20261027T175730Z/evidence.json),
[disassemblaggio](../Risultati/GUI_S33/changecolor_capture_return_20261027T175730Z/disassembly.txt),
[verificatore](../Python_Trace_Scripts/s33_verify_gui_changecolor_capture_return.py).
Non sono stati eseguiti lifecycle, servizi o rendering; non è una prova CPU né
hardware. I candidati restano **NON_INSTALLARE**.
