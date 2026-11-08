# S33 V1.1 — destinazioni condizionali delle voci di CaptureMenu

27 ottobre 2026. Analisi statica offline di firmware originale e MainCode,
senza operazioni su fotocamera o SD. Gli indirizzi sono riferiti alla mappa
candidata dei payload V1.1; i byte esaminati sono confrontati con MainCode.

## Risultato

I sette record delle due liste `CaptureMenu` contengono un campo a offset
`+20` che, nel percorso studiato, può diventare l'ID passato al servizio di
apertura `0x1453E4`. Il valore a `+16` può diventare il secondo argomento.
Questa è una **richiesta condizionale**, non la prova che la finestra appaia
sullo schermo. I nomi derivano dai descrittori interni della tabella oggetti,
non dalle etichette visibili.

| Lista | Indice zero-based | Record | Halfword iniziali | ID a +20 | Nome descrittore | Argomento a +16 | Flag iniziale +24 |
| --- | ---: | --- | --- | --- | --- | ---: | --- |
| `0x4800` | 0 | `0x98016C` | 606, 606, 606 | `0x87` | AutoSceneLiveView | 0 | `0x08` |
| `0x4800` | 1 | `0x980188` | 284, 285, 284 | `0x9D` | LiveViewHotKeyMenu | 2 | 0 |
| `0x4800` | 2 | `0x9801A4` | 806, 807, 806 | `0x9D` | LiveViewHotKeyMenu | 3 | 0 |
| `0x4801` | 0 | `0x9801F8` | 606, 606, 606 | `0x87` | AutoSceneLiveView | 0 | `0x08` |
| `0x4801` | 1 | `0x980214` | 633, 634, 633 | `0x07` | ShootingMode | 0 | 0 |
| `0x4801` | 2 | `0x980230` | 413, 414, 413 | `0x0A` | FrameSelect | 0 | 0 |
| `0x4801` | 3 | `0x98024C` | 222, 223, 222 | `0xBB` | ChangeColorMenu | 0 | 0 |

Gli halfword sono riportati come valori grezzi: non sono state dimostrate la
loro interpretazione grafica né le etichette mostrate. I flag sono i byte
iniziali del payload, non necessariamente lo stato runtime dopo l'inizializzazione.

## Catena e guardie

- Il descrittore oggetto `0x9802AC` (ID 2, `CaptureMenu`) riferisce la lista
  risorse `0x9802A0`; le prime due hanno classe `0x15`, ID `0x4800` e
  `0x4801`, puntatori rispettivi `0x98016C` e `0x9801F8`, passo 28.
- `0x6337B0` passa la tabella `0x77F728` e conteggio `0x16` a `0x145010`,
  che li memorizza; il lookup `0x145020` accetta indici nel limite e legge
  l'elemento corrispondente. Lo slot di indice `0x15` contiene `0x631610`.
  La registrazione e l'uso effettivi durante una sessione non sono stati osservati.
- `0x631610` inoltra all'engine `0x169F60` con tabella `0x77F664`. In essa
  l'evento `0x0580` porta a `0x631878`; l'engine cerca la coppia evento/callback
  e passa il primo argomento ricevuto al callback. Il collegamento fra `0x0580`
  e `KeyOK` è documentato separatamente nella [prova dei comandi](S33_GUI_Tasti_Comandi_Eventi_20261027.md),
  non identifica un interruttore fisico.
- `0x631878` ricava un indice e un puntatore al record. Prima di aprire,
  verifica indice nel limite e bit 0 e 1 del flag a `+24` entrambi chiari;
  inoltre richiede bit 1 del valore restituito da `0x1450D8` con selettore
  `0x14`. Se il mezzo word **con segno** a `+20` è nonzero, lo passa a
  `0x1453E4`; la word a `+16`, se nonzero, diventa il secondo argomento,
  altrimenti l'argomento inizializzato rimane zero. L'indice è calcolato dal
  contesto e può dipendere dalla pagina: non è stato dimostrato quale record
  sia selezionato in una situazione reale.
- `0x7CB1B4` inizia azzerando il bit 1 del flag dei record tramite `0x631E98`,
  quindi può impostarlo su elementi specifici secondo lista e valori restituiti
  da servizi. Per `0x4801` controlla `+20` uguale a `0x0A` o `0xBB` e
  interroga `0xCAD30` e, in un ramo, `0xCA310`. Per `0x4800` controlla il byte
  a `+16` uguale a 2 o 3 e confronta i risultati di `0xCAD30` con vari valori.
  Il codice può rileggere il servizio più volte: non assumere che i risultati
  restino uguali senza una prova. Il bit impostato impedisce il percorso di
  apertura descritto sopra; non si attribuisce qui un significato visivo al bit.

La verifica non collega i numeri grafici ai JPEG studiati in precedenza e non
prova le scritte, l'aspetto, l'inizializzazione reale o la raggiungibilità di
ciascuna voce. I servizi sono analizzati staticamente e non eseguiti.

## Riproduzione e limiti

`python3 Python_Trace_Scripts/s33_verify_capture_menu_item_dispatch.py` ha dato
**PASS** per i byte delle finestre di codice, tabelle e sette descrittori di
arrivo, confrontati con MainCode. [Disassemblaggio e dati della verifica](../Risultati/GUI_S33/capture_menu_dispatch_20261027T174929Z/evidence.json),
[istruzioni](../Risultati/GUI_S33/capture_menu_dispatch_20261027T174929Z/disassembly.txt),
[verificatore](../Python_Trace_Scripts/s33_verify_capture_menu_item_dispatch.py).
È un controllo statico vincolato a questi elementi, non una prova CPU integrata,
una validazione del display o dell'hardware. Nessuna modifica del firmware;
i candidati rimangono **NON_INSTALLARE**.
