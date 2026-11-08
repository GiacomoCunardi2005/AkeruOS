# S33 V1.1 — ingresso del valore tempo in un calcolo

27 ottobre 2026. Analisi **statica** del firmware V1.1: la word `0x37FBF4`, scritta dal controllo diagnostico del tempo, può essere copiata in un buffer usato da una routine di calcolo che riceve anche il valore ISO. Questo collegamento non dimostra una durata fisica, un ciclo AE o un effetto sul sensore.

## Copia e chiamata

Nel percorso `0xD8CA4`, `0xD8D06` chiama `0xF6F54` con destinazione locale `fp-76`. `0xF6F54` richiede a `0xAD920` la copia di 64 byte dal contesto `0x37FBD0`; secondo la convenzione di copia già studiata, la word a offset `+0x24` proviene quindi da `0x37FBF4` e finisce a `fp-40`. La halfword adiacente `+0x22` proviene da `0x37FBF2` (valore ISO software). L'helper scrive un flag prima e dopo la copia; non è dimostrato che esso garantisca un'istantanea atomica in presenza di concorrenza.

A `0xD8E1E` la routine chiama `0xFDA28(buffer_risultato, correttivo, fp-76)`. Quest'ultima salva il terzo argomento in `r13`: perciò le letture `[r13+0x24]` e `[r13+0x22]` riguardano i campi della **copia**, non necessariamente quelli correnti quando la routine successiva li usa. Tra copia e chiamata altri servizi sono invocati: i loro effetti sul buffer, l'ordine degli altri task e il momento della copia non sono stabiliti.

## Scelte condizionali

`0xFDA28` legge una halfword a `r13+0`. Se è inferiore a 4 usa altri campi `+0x2C`, `+0x38` e `+0x36`; se è `0x3E` imposta zero nel campo di lavoro che qui interessa. Negli altri casi legge la word `r13+0x24`, la halfword `+0x22`, un byte a `+0x21` e un ulteriore campo del contesto. Se almeno uno di questi quattro valori è zero, la word copiata viene inoltrata al campo `+0x18` di un input locale. Se sono tutti non zero, la word è riletta e passata come argomento a `0x336364`; dopo altre trasformazioni e un limite dipendente dallo stato, il risultato viene scritto nello stesso campo `+0x18`. Gli effetti numerici degli helper e il significato delle unità non sono stati qui caratterizzati.

A `0xFDBFA` il puntatore a quell'input locale viene passato a `0xFDE08`. Questa routine legge `+0x18` come condizione e, su un ramo ulteriore, lo passa a `0x18C99C`. Quindi la word del tempo può influenzare un calcolo successivo, ma possono intervenire selezioni, trasformazioni e altre scritture; zero **non** è dimostrato come sinonimo universale di automatico.

Il buffer risultato di `0xFDA28` è quello che il chiamante può ulteriormente aggiornare e poi copiare nell'area `0x380574+720`; le limitazioni sulle chiamate intermedie sono documentate nello [studio ISO](S33_GUI_ISO_Soglia_e_Buffer_20261027.md). Non è stabilito che questo buffer generi il differente snapshot `0x380574+960` letto da `0x17C480`, né che sia applicato durante lo scatto.

## Verifica e limiti

Il [verificatore](../Python_Trace_Scripts/s33_verify_gui_time_calculation_static.py) confronta i byte delle finestre analizzate e il letterale del contesto con `DUMPS/MainCode.dmp`, controlla le ancore del disassemblatore GNU e gli offset; i [listati e lo snapshot dello script](../Risultati/GUI_S33/time_calculation_static_20261027T215106Z/) sono conservati. Esecuzione: `python3 Python_Trace_Scripts/s33_verify_gui_time_calculation_static.py`.

Questa è una lettura condizionale del codice, senza prova di esecuzione della catena né identificazione del significato fisico, delle priorità AE, della persistenza o dell'effetto sul sensore. Nessuna operazione su fotocamera, NAND o SD; firmware e GNU originali non modificati; **NON_INSTALLARE**.
