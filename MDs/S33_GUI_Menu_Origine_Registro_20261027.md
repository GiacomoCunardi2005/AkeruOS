# S33 — origine candidata del bit associato a Menu

Analisi statica del firmware V1.1, 27 ottobre 2026. Un percorso candidato verso il bit 7 associato al tasto logico 14 parte dalla metà parola letta all'indirizzo `0x0FE70228`. È un collegamento nel codice, subordinato allo stato del monitor e delle registrazioni; non identifica ancora il pulsante fisico.

## Due letture differenti

Il monitor `0x242104` controlla una condizione usando `0x2D62B0`. Questa routine legge due metà parola tramite `ldh.di` da `0x0FE7021C` e `0x0FE70220`, e le combina come `(prima << 10) | seconda`.

Quando il percorso condizionale richiede uno snapshot, `0x2B7190` chiama invece **`0x2D62D8`**, che combina nello stesso modo le metà parola lette da `0x0FE70224` e `0x0FE70228`. Il risultato viene scritto a `[0x5545F8+0x30]`. La distinzione corregge la descrizione precedente: il valore confrontato e lo snapshot inoltrato sono letti da coppie di registri diverse.

## Percorso verso la GUI

Secondo i rapporti statici precedenti, con le registrazioni installate e la condizione del monitor soddisfatta, `0x242104` passa lo snapshot a `0x1406D0`, che inoltra il suo complemento a `0x16EC38`. Il normalizzatore conserva il bit 7 ma può rifiutare la coppia in determinate condizioni; il consumatore `0x16F86C` rileva i cambiamenti e il record 7 della tabella `0x392F04` associa il bit 7 al tasto logico 14. Nel percorso che emette gli eventi, valore nonzero e zero danno rispettivamente `0x700` e `0x701`.

Poiché il primo operando dello snapshot è spostato a sinistra di 10, il bit 7 del valore combinato dipende solo dal bit 7 della lettura a `0x0FE70228`. Nel percorso indicato il complemento lo inverte prima della normalizzazione. Questa è una deduzione sul codice: non sappiamo se il registro rifletta direttamente un interruttore, quale sia il significato elettrico del bit o se il percorso venga effettivamente attivato durante l'uso della S33.

## Verifica e limiti

[Script di verifica](../Python_Trace_Scripts/s33_verify_gui_menu_input_registers.py): confronta le finestre originali con `MainCode.dmp`, controlla il disassemblaggio GNU e i cinque pool dei puntatori. [Evidenze](../Risultati/GUI_S33/input_registers_20261027T113615Z/evidence.json) e [finestre](../Risultati/GUI_S33/input_registers_20261027T113615Z/gnu_windows.txt). Il collegamento alle registrazioni, al normalizzatore e al consumatore deriva dagli studi statici [sugli scrittori](S33_Iride_Scrittori_Coppia_Stato_64bit.md) e [sul monitor](S33_Iride_Consumatori_Registrazioni_Evento_3200002.md), e dalla [tabella dei tasti](S33_GUI_Tasti_Maschere_Stato_20261027.md).

Nessuna lettura MMIO su hardware, nessuna prova CPU dell'intera catena e nessuna identificazione del tasto fisico. Nessun firmware modificato o installato.
