# S33 V1.1 — lookup del valore grafico indicizzato

27 ottobre 2026. Analisi offline delle routine originali; nessun accesso a fotocamera o SD. Gli indirizzi appartengono alla mappa candidata dei payload V1.1.

## Funzionamento verificato nel dominio provato

Il percorso grafico condizionale già individuato passa a `0x21DC34` un puntatore a dati e il conteggio 256. Nel ramo di conversione esaminato la routine combina quattro byte in una word e chiama `0x17AF2C` per ciascun elemento. I quattro byte non vengono qui identificati con canali fisici di colore.

La routine `0x17AF2C` costruisce una chiave di quattro byte e cerca una word identica in una tabella di 256 word il cui indirizzo, nella mappa candidata, è `0x47A448`. Per gli 11 input provati, indicati con `b0,b1,b2,b3` nell'ordine originale:

- `b0` e `b2` vengono corretti di +1 se al massimo 83, di −1 se almeno 172, poi spostati a destra di due bit;
- `b1` rimane invariato;
- il quarto byte della chiave è `((255 − b3) × 126 + 255) // 510`;
- la chiave è confrontata con le word della tabella nell'ordine degli indici.

Con la tabella di laboratorio la routine restituisce l'indice della **prima** corrispondenza. Il caso con valore assente restituisce zero, ma zero è anche l'indice della prima voce: il solo risultato zero non distingue i due casi. Nel caso senza corrispondenza l'elemento sintetico successivo alle 256 voci contiene deliberatamente la chiave cercata, e non viene selezionato. La fixture mappa due word aggiuntive: questo esperimento non dimostra che una lettura oltre le 256 word sia impossibile.

## Prove

REA ha letto le finestre a `0x17AF2C` e `0x335B34` e il letterale `0x17B164`; i byte coincidono con i payload originali: [evidenza REA](../Risultati/GUI_S33/rea_color_lookup_20261027T183838Z/evidence.json). Si tratta di letture statiche; non provano da sole la semantica.

Il [verificatore CPU](../Python_Trace_Scripts/s33_verify_gui_color_lookup_cpu.py) esegue la routine originale e il suo helper di divisione sul simulatore GNU ARC700. [Undici casi PASS](../Risultati/GUI_S33/color_lookup_cpu_20261027T183924Z/verified_evidence.json), 6.894 istruzioni dichiarate e nessun fault: quattro input derivano dai primi quattro record originali a `0x3F6740`; sei coprono i valori 83, 84, 85, 171, 172 e 173 nei due campi ridotti; uno non trova la chiave. La prova include una chiave duplicata, una corrispondenza all'indice 255 e una all'indice zero. Stack e copie dei byte originali sono conservati.

La tabella a `0x47A448` è una **fixture sintetica**: l'intervallo non è coperto univocamente dalla mappa statica dei payload usata dal verificatore. Gli slot scelti e i valori restituiti non sono la palette della fotocamera. Il banco non esegue il caricatore della tabella, `0x21DC34`, il disegno di una schermata o il display; non stabilisce colori, trasparenza fisica o raggiungibilità a runtime. Firmware e GNU sono rimasti in sola lettura; candidati **NON_INSTALLARE**.
