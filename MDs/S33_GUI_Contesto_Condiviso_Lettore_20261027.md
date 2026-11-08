# S33 — contesto condiviso del lettore immagini GUI

Analisi statica del firmware V1.1, 27 ottobre 2026. La routine GUI `0x7C9E38` acquisisce la sincronizzazione identificata da `0x00300008`, legge offset e lunghezza dalla tabella JPEG e chiama `0x159558`. Nel suo corpo disassemblato non chiama il configuratore `0x159550`. Legge il byte di modalità `0x928` e calcola un valore in `r18`, ma non lo usa per configurare la sorgente prima di leggere.

Un altro percorso originale, a `0x2BEAFC`, per certi ingressi e condizioni acquisisce lo **stesso identificatore** `0x00300008`, chiama `0x159550` con base `0xD03000`, legge tramite `0x159558` e richiede il rilascio. Il primo argomento del configuratore è il percorso restituito da `0xC76C4` se il byte `0x928` vale `0x20`, altrimenti zero. In presenza di un valore già memorizzato per quell'indice il percorso può evitare la lettura: la riconfigurazione non è incondizionata.

Il configuratore salva percorso e base nel contesto `0x3672A4`; il lettore vi legge la base. È quindi concreta la necessità di stabilire quale configurazione sia in vigore quando la GUI ottiene la sincronizzazione. **Non è dimostrato** che questo percorso preceda la GUI, né che il contesto sopravviva al rilascio o ad altre chiamate: i servizi e lo scheduling non sono stati eseguiti in questa verifica. L'identificatore condiviso da solo non dimostra il comportamento del lock o l'ordine dei task.

Per illustrare la dipendenza, se il contesto mantenesse base `0xD03000` e il backend aprisse esattamente il TBM originale, l'indice 14 chiederebbe la posizione `0xD0D7B9`; i 2715 byte lì presenti differiscono dal JPEG identificato alla posizione `0x3670D1`. Questo è un confronto condizionale tra file, non una lettura osservata. Il backend a selettore 6 può avere una mappatura diversa.

## Riproduzione e limiti

Il [verificatore](../Python_Trace_Scripts/s33_verify_gui_reader_shared_context.py) confronta con `MainCode.dmp` le finestre e i pool utilizzati, controlla i due identificatori, il valore della base, il record 14 e i byte del file; [esito e hash](../Risultati/GUI_S33/jpeg_shared_context_20261027T171211Z/evidence.json) e [finestre GNU](../Risultati/GUI_S33/jpeg_shared_context_20261027T171211Z/gnu_windows.txt). È analisi statica: nessuna CPU, concorrenza, backend reale o display fisico. Il passo successivo è eseguire in fixture la sequenza configuratore → rilascio → routine GUI con servizi espliciti e risalire ai chiamanti reali; ciò comunque non proverebbe l'ordine sulla fotocamera.
