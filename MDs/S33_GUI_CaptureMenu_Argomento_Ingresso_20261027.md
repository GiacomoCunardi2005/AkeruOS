# S33 V1.1 — argomento d'ingresso e liste di CaptureMenu

27 ottobre 2026. Analisi statica offline del firmware V1.1 originale, con
finestre confrontate con `DUMPS/MainCode.dmp` e indirizzi riferiti alla mappa
candidata dei payload. Il risultato distingue le condizioni del codice dallo
stato effettivo della fotocamera, che non è stato osservato.

## Come arriva il valore

Il wrapper `0x1453E4` conserva il secondo argomento nella chiamata al gestore
`0x145180`. Quest'ultimo lo salva in `r16` ma può sostituire sia la destinazione
sia tale valore dopo un pre-evento `0x4403`: la risposta viene interpretata da
`0x14510C`, e il percorso di redirezione carica il nuovo argomento dallo stack.
Nel ramo di ingresso `0x1452E0`, il gestore chiama `0x169D78` sull'oggetto
selezionato con evento `0x4401` e `r2=r16`. Questo ramo è condizionale: le
guardie del gestore e la redirezione possono impedirlo o cambiarne il bersaglio.

Per `0x4401`, la tabella di salti di `0x169D78` porta a `0x16A05C`, che
conserva l'argomento e lo inoltra a `0x16A028`; quest'ultimo può chiamare il
callback dell'oggetto con lo stesso `r2`. L'eventuale hook di `0x169D78` può
intercettare l'evento; un altro hook precede il callback in `0x16A028`.
Il dispatcher di `CaptureMenu` usa un filtro modificabile e la tabella eventi;
se `0x4401` arriva a `0x7CB020`, il callback scrive `r2` in `0x899860`.

Il pre-evento `0x4403` non compare nella tabella iniziale di CaptureMenu né
nei 66 record della tabella comune prima del terminatore. Con tabelle, filtro
e slot oggetto come nell'immagine iniziale, senza interventi degli hook,
la catena di fallback restituisce zero; se il gestore usa la tabella oggetti
iniziale `0x3F5900`, il relativo slot 0 è nullo e `0x14510C` non propone una
redirezione. L'effettiva registrazione di tale tabella, gli hook e il contenuto
runtime del filtro non sono verificati: non è una prova dell'ordine reale.

## Effetto sulla selezione

Nel callback `0x4405`, dopo una chiamata a `0xCAFF8`, `0x7CB118` legge
`0x899860`:

| Valore letto | Comportamento di `0x7CB118` |
| ---: | --- |
| 4 | Chiama `0x145764` per `0x4800`; passa 1 per `0x4800` e 0 per `0x4801` a `0x145B08`; salva in `0x89985C` il risultato di `0x145654` per `0x4800`. |
| 5 | Esegue le chiamate corrispondenti invertendo le due risorse e salva il risultato di `0x145654` per `0x4801`. |
| altro | Salta entrambe le sequenze e non scrive `0x89985C` in questa routine. |

I ritorni dei servizi non sono verificati nel presente studio: un valore
salvato può anche essere nullo e una chiamata non dimostra visualizzazione.
La word iniziale a `0x89985C` è zero, ma può cambiare durante l'esecuzione.
Non si può dedurre da quei byte iniziali quale lista sia attiva in seguito.

Il percorso `KeyMenu` precedentemente provato raggiunge la richiesta
`0x1453E4(2,0)` in certe condizioni. **Se** quella richiesta giunge a `0x4401`
senza redirezione, filtro o hook che alterino il percorso, scrive zero in
`0x899860`: la successiva `0x7CB118`, se legge ancora zero, non seleziona
nessuna delle due liste tramite i rami 4/5. Questo è un confronto condizionale,
non una prova che la GUI reale fallisca o usi una lista particolare. Un percorso candidato per il valore 4 è stato eseguito separatamente: nel [banco del menu rapido](S33_GUI_HotKeyMenu_Ritorno_20261027.md), evento sintetico `0x0580` non filtrato richiede `0x1453E4(2,4)` tramite una fixture registratrice. Se il gestore reale consegna 4 senza alterazioni e il callback successivo lo legge invariato, viene scelta la sequenza `0x4800`. Una [fonte statica candidata del valore 5](S33_GUI_ChangeColorMenu_Ritorno_CaptureMenu_20261027.md) è il primo record del controllo in `ChangeColorMenu`; la sua selezione e consegna restano condizionali. Restano ignoti lo stato runtime e gli altri scrittori dello stato.

## Riproduzione e limiti

`python3 Python_Trace_Scripts/s33_verify_capture_menu_entry_arg.py` ha prodotto
**PASS statico**: 30 istruzioni ancorate, byte delle finestre, descrittore,
tabelle, word iniziali e pool verificati contro MainCode. [Evidenza e hash](../Risultati/GUI_S33/capture_menu_entry_arg_20261027T175309Z/evidence.json),
[disassemblaggio](../Risultati/GUI_S33/capture_menu_entry_arg_20261027T175309Z/disassembly.txt),
[verificatore](../Python_Trace_Scripts/s33_verify_capture_menu_entry_arg.py).
La prova non esegue il lifecycle, i servizi, gli hook o il rendering e non
verifica la consegna di eventi o l'hardware. Nessuna operazione su fotocamera
o SD; candidati **NON_INSTALLARE**.
