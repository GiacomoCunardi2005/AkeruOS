# Modello GUI: richiesta di ritorno

Il 29 ottobre 2026 ho esteso [`akeru_menu_event`](../AkeruOS/ui/menu.c) per l'evento logico `0x480`, già associato al ritorno nel [CaptureMenu originale](S33_GUI_CaptureMenu_Ritorno_LiveView_CPU_20261027.md):

- dalla schermata principale restituisce la nuova azione `AKERU_RETURN_LIVEVIEW`, lasciando invariato lo stato del modello;
- da esposizione o colore passa alla schermata principale e restituisce `AKERU_REDRAW`;
- la controparte `0x481` è consumata senza azione. La polarità e il pulsante fisico rimangono da verificare.

L'azione è una **richiesta al chiamante**, non esegue l'apertura o la chiusura della live view. È aggiunta dopo i valori esistenti dell'enum, così non cambia i numeri delle altre azioni. Gli eventi estranei continuano a non modificare la cella azione; come per le altre controparti, `0x481` scrive `AKERU_NONE`, quindi un chiamante deve acquisire un'azione prima di consegnare un altro evento. Proprietà della cella e concorrenza non sono risolte da questa modifica.

Test host UBSan e GNU ARC700 PASS per tutti e tre gli stati, le controparti e input invalidi: [manifest](../Risultati/GUI_S33/akeru_menu_model_20261029T224154Z/verified_evidence.json). Un [banco separato](../Python_Trace_Scripts/s33_verify_gui_original_queue_back_menu_cpu.py) genera `0x480` e `0x481` dal tasto logico 9 attraverso codice e coda originali, poi il banco consegna i record al modello C: [tre casi PASS](../Risultati/GUI_S33/original_queue_back_menu_cpu_20261029T224203Z/verified_evidence.json). Rieseguiti anche i 12 casi dei banchi esistenti coda, dispatcher e descrittore: PASS.

L'handler originale di CaptureMenu richiede condizionalmente `AutoSceneLiveView` ID `0x87`, mentre un [tentativo distinto](S33_GUI_Liveview_Ritorno_Clock_Tentativi_20261029.md) che chiedeva direttamente ID 1 non è completato. Questa azione astratta non sceglie tra quelle destinazioni e non sostituisce le guardie o i servizi originali. Nessun scheduler, collegamento alla fotocamera, tasto fisico, rendering o ritorno effettivo è verificato. **NON_INSTALLARE**.
