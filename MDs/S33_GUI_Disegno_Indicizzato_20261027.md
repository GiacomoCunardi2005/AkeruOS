# S33 V1.1 — percorso candidato del disegno indicizzato

27 ottobre 2026. Analisi offline delle finestre originali V1.1 confrontate con `DUMPS/MainCode.dmp`, letture REA e prove CPU circoscritte. Gli indirizzi usano la mappa candidata dei payload; non sono una mappa fisica osservata.

## Collegamento condizionale

Il contesto grafico iniziale a `0x36A5E0` contiene `0x2C8380` nel campo `+8`. Nel percorso statico studiato, `0x23B4B4` copia il descrittore su stack, può decomprimerlo e passa tramite il puntatore nel contesto `+8`. Questo è il **valore iniziale del payload**: il puntatore attivo e la chiamata sulla fotocamera non sono dimostrati.

Se la callback è `0x2C8380`, essa legge dal descrittore il mezzo word signed a `+6` e seleziona un ramo mediante una tabella di byte. I descrittori degli 11 ID studiati di CaptureMenu hanno tutti `+6 = 8` e `+12 = 0x3F6740`. Per il valore 8, il byte di tabella è `0x22` e indirizza il ramo `0x2C83F0`. Se `+12` è nonzero, quel ramo passa il puntatore e 256 a `0x21DC34`; quindi imposta un puntatore alla routine `0x2C9018` attraverso il valore originale caricato da `0x2C8440`. La routine `0x2C8170` contiene chiamate indirette al puntatore selezionato. Questa è una catena **statica e condizionata**: contesto, selezione effettiva e ritorni dei servizi non sono osservati.

Nel percorso di conversione esaminato, `0x21DC34` legge quattro byte per volta, li combina in una word in ordine `b0<<24 | b1<<16 | b2<<8 | b3`, chiama `0x17AF2C` e salva un byte del risultato. Sono presenti condizioni di cache e altri rami; non si attribuisce qui significato RGB, formato fisico o risultato di `0x17AF2C`. I 1.024 byte a `0x3F6740` sono stati confrontati con il dump; non si dimostra che quella tabella sia attiva a runtime.

Il successivo [studio di `0x17AF2C`](S33_GUI_Lookup_Colore_20261027.md) verifica la costruzione della chiave e la ricerca di una corrispondenza esatta su 256 word: con una tabella sintetica, la prima corrispondenza vince e zero può indicare sia indice zero sia assenza. La tabella runtime non è identificata; i risultati di laboratorio non assegnano colori fisici agli indici.

## Cosa fa il tratto di riga verificato

Nel dominio verificato, `0x2C9018` riceve un buffer destinazione, una sorgente di indici e una struttura sintetica con conteggio a `+0`, offset sorgente a `+2` e puntatore opzionale a una tabella di byte a `+8`.

- Con tabella, legge un indice, legge `tabella[indice]` e scrive il valore solo se quest'ultimo è diverso da zero.
- Senza tabella, scrive l'indice sorgente solo se diverso da zero.
- Nel tratto osservato avanza la destinazione anche quando non scrive; conteggio zero non modifica i byte destinazione.

Per esempio, con tabella sintetica `0→0x7E`, `1→0`, `2→0x33`, `3→0x44`, input `0,1,2,3` e destinazione iniziale `0xA5`, la CPU produce `0x7E,0xA5,0x33,0x44`. Quindi **non è lecito concludere che l'indice sorgente zero sia sempre trasparente**: con la tabella conta il valore dopo la conversione. L'effetto fisico di «non scrivere» dipende dal contenuto precedente del buffer e dal resto della pipeline.

## Evidenza e limiti

REA, tramite `rea-arc`, ha letto sette finestre delle routine e della tabella di salti; i byte coincidono con i payload originali: [evidenza REA](../Risultati/GUI_S33/rea_indexed_draw_20261027T183541Z/evidence.json). Questa è lettura statica, non una prova dell'esecuzione dei rami. Il primo avvio REA ha restituito `execution_failure` prima dell'avvio del bridge; un secondo tentativo identico è riuscito. Il log temporaneo del primo è stato ripulito, quindi la causa non è stata stabilita e non si dichiara corretto un difetto specifico.

Il [verificatore CPU](../Python_Trace_Scripts/s33_verify_gui_indexed_draw_cpu.py) esegue `0x2C9018` originale nel simulatore GNU ARC700 già presente: [cinque casi PASS](../Risultati/GUI_S33/indexed_draw_cpu_20261027T183649Z/verified_evidence.json), 181 istruzioni dichiarate, nessun fault, stack conservato e guardie delle destinazioni invariate. La tabella di conversione, le strutture, gli input e i buffer sono **fixture sintetiche**. La prova non esegue `0x2C8380`, `0x21DC34`, `0x2C8170`, il caricatore delle risorse o il display.

Restano aperti il contenuto della tabella convertita reale, il significato dei suoi byte, le guardie del chiamante, l'eventuale uso di più buffer e i pixel effettivamente mostrati. Firmware, GNU e fotocamera non modificati; candidati **NON_INSTALLARE**.
