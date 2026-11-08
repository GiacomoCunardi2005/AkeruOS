# S33 V1.1 — ordine originale del calcolo e dell'applicazione iride

**Data:** 2026-10-31. Analisi statica delle istruzioni del dump, senza esecuzione del percorso completo né accesso alla fotocamera.

Nel corpo di `0xD6A80` esiste un percorso con la seguente sequenza condizionata:

1. `0xD6EF2` chiama `0xF7238`; c'è anche un'altra chiamata a `0xD6EEC`. Almeno uno dei rami interni di `0xF7238` chiama `0xFDA28` (`0xF7302`), con destinazione `0x380754` e puntatore sorgente nel registro `r14`. Non si assume che tutti i rami producano lo stesso risultato.
2. `0xD6EFC` imposta `r1=1` e `0xD6EFE` chiama `0xF7844`. Il prologo di quest'ultima conserva il selettore in `r19`: il confronto a `0xF7870` e il salto a `0xF7874` fanno saltare il ramo che contiene `0xF78BE` se il selettore è diverso da zero. La chiamata con 1 non attraversa quel ramo.
3. `0xD6F68` chiama `0xF7568`: le istruzioni copiano `0xF0` byte da `0x380754` a `0x380664`, quindi anche `0x38077F` in `0x38068F`.
4. Dopo la chiamata a `0xD4DF4`, se il suo risultato è zero, `0xD6F80` richiama `0xF7844` con `r1=r13`. Nel prologo di `0xD6A80`, `r13` è inizializzato a zero; la conclusione per questa chiamata dipende dal mantenimento di tale registro lungo il percorso e dalle convenzioni dei servizi chiamati. Con selettore zero il salto iniziale non viene preso; l'ulteriore condizione `0x11D074()==0` porta a `0xF78BE`, che legge `0x38068F`, confronta lo stato e può richiedere un aggiornamento.

La sequenza è coerente con il precedente banco CPU che imponeva calcolo → copia → frammento di richiesta: ora esiste un percorso originale compatibile, con una chiamata intermedia a `0xF7844` che non entra nel ramo iride e un'altra successiva che può entrarvi. Questo non dimostra che il percorso sia sempre eseguito, che i servizi intermedi preservino tutti i dati, che la richiesta arrivi all'ottica o che un valore numerico corrisponda a un'apertura o ad Auto.

Verifica riproducibile: `python3 Python_Trace_Scripts/s33_verify_iris_original_order_static.py`; PASS, byte delle finestre e puntatori confrontati con `DUMPS/MainCode.dmp`, disassemblato ed hash in `Risultati/GUI_S33/iris_original_order_static_20261031T205944952623Z/`. Il controllo non esegue la funzione completa e non verifica indipendentemente ogni ramo o effetto collaterale dei servizi. Rimangono da identificare l'inizializzazione dei valori sorgente e il loro significato fisico. **NON_INSTALLARE.**
