# S33 — base delle immagini GUI e caso limite del lettore

Analisi statica del firmware originale V1.1, 27 ottobre 2026. I 18 record della tabella `0x981734` individuati in precedenza corrispondono esattamente ai JPEG nel file TBM originale e in `MainCode.dmp` quando si somma **`0x35C918`** all’offset del record. La verifica confronta tutti i byte e le lunghezze: ad esempio, indice 14 → offset `0xA7B9`, 2715 byte → posizione `0x3670D1` nel TBM e nel dump. Il contenuto del TBM alla posizione `0xA7B9` non coincide con quell’immagine; lo stesso vale per ciascuno dei 18 record alle rispettive posizioni relative non corrette.

Questa è una relazione fra file, non la prova che il backend usi tale base. Se il backend file apre esattamente quel TBM e il contesto del lettore ha base zero, l’indice 14 punta alla posizione `0xA7B9`, non al JPEG identificato. Serve dunque una base adeguata, un’altra sorgente o un diverso percorso; non è noto quale sia effettivamente usato dalla GUI. I wrapper studiati separatamente impostano base zero per i valori `0x10` e `0x20` del byte `0x928`, ma non è provato che questa configurazione resti in vigore quando HintMessage legge.

## Correzione del caso zero

Il record 1 ha offset zero e lunghezza 2688. Il lettore `0x159558` somma la base configurata all’offset; se il risultato o la lunghezza è zero, `0x159574` imposta `r0=1`, poi `0x15961A` salva tale valore nel campo di stato e salta a `0x159590`, che imposta `r0=0` prima dell’uscita. Non viene chiamato il backend. Il valore restituito è quindi **fallimento**, non successo come indicato nel precedente rapporto sui gruppi di caricamento, qui corretto. Nel percorso GUI il chiamante ritenta dopo un primo fallimento; due tentativi con la stessa base zero non leggono l’indice 1.

Il percorso dell’indice 14 resta condizionale. Non sono stati osservati base runtime, ordine dei task, backend, decodifica integrata o display fisico. Nessuna operazione sulla fotocamera o modifica firmware.

## Evidenze

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_jpeg_source_offsets.py), [18 confronti e hash delle fonti](../Risultati/GUI_S33/jpeg_source_offsets_20261027T171014Z/evidence.json), [disassemblato GNU del lettore](../Risultati/GUI_S33/jpeg_source_offsets_20261027T171014Z/gnu_reader.txt). Il codice del lettore è confrontato con il dump; le immagini sono confrontate integralmente fra firmware, TBM e dump. Il test è statico, non esegue la CPU.
