# S33 — ricerca delle dimensioni JPEG nella GUI

Il 27 ottobre 2026 ho eseguito nel simulatore GNU ARC700 la routine originale V1.1 `0x7C9C80` e la sua ricerca byte originale `0x32E5AC`. Il banco passa come buffer i 18 JPEG illustrati originali: tutti restituiscono successo e dimensioni **160×96**. I buffer sono fixture ricavati dal firmware; questa prova non carica le immagini dal backend e non disegna sul display.

La routine controlla la firma iniziale `FF D8`, cerca il byte `FF` e accetta la prima coppia `FF C0`; da questa legge due coppie di byte big-endian per altezza e larghezza. Non percorre i segmenti JPEG usando le loro lunghezze, quindi è uno scanner specifico, non un validatore generale. Sei casi sintetici precisano i limiti:

- Puntatore nullo e firma errata restituiscono 0 senza cambiare le dimensioni inizializzate nel banco; una sequenza contenente solo `FF C2` e nessun `FF C0` restituisce 0.
- Una sequenza sintetica con `FF C0` nei dati di un segmento APP e un secondo `FF C0` successivo restituisce le dimensioni associate al primo. Non dimostra che ciò accada nei JPEG della fotocamera.
- Due buffer con identici primi tre byte `FF D8 FF` e lunghezza dichiarata 3, ma diversi byte successivi mappati nella fixture, restituiscono rispettivamente 160×96 e 48×32. La routine legge dunque oltre la lunghezza dichiarata. Le fixture hanno memoria effettivamente disponibile oltre il limite dichiarato: non provano una lettura oltre l'allocazione reale o un difetto raggiungibile su hardware.

Il chiamante originale `0x7C9CFC` tenta la lettura una seconda volta se la prima fallisce, poi invoca comunque lo scanner senza confrontare l'esito del secondo tentativo. La lunghezza è quella scritta prima del lock dalla routine indice. Dopo due fallimenti contenuto e capacità del buffer reale non sono stabiliti; non si può inferire cosa apparirebbe sul display.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_jpeg_dimensions_cpu.py), [24 casi](../Risultati/GUI_S33/jpeg_dimensions_cpu_20261027T171528Z/cases.json), [disassemblato delle routine originali](../Risultati/GUI_S33/jpeg_dimensions_cpu_20261027T171528Z/gnu_windows.txt), [traccia CPU](../Risultati/GUI_S33/jpeg_dimensions_cpu_20261027T171528Z/cases.trace). Il percorso del chiamante è nel [disassemblato verificato](../Risultati/GUI_S33/jpeg_hint_path_20261027T114229Z/gnu_windows.txt). Nessun backend reale, filesystem, decodificatore, display o hardware è stato eseguito.
