# GUI: origine di eventi identici nella coda sintetica

Il 29 ottobre 2026 ho confrontato due modi di produrre ciascuna delle coppie logiche 1+2 e 1+3 nel [banco lettore→coda→modello](S33_GUI_Coppie_Coda_Transizione_Modello_CPU_20261029.md):

1. entrambi i bit cambiano nello stesso snapshot;
2. cambia prima il bit dello slot 1, il lettore e il callback sono eseguiti, poi cambia anche l'altro bit mentre il primo resta attivo e viene eseguito un secondo snapshot.

Il banco attende di aver prodotto entrambi gli eventi prima di estrarli, li consegna al modello C in ordine, quindi ripristina entrambi i bit ed estrae le controparti. Per entrambe le coppie, i quattro record estratti di 12 byte e i relativi ritorni sono **identici byte per byte** nei due modi; anche le schermate e le azioni del modello coincidono. Per 1+2 si ottengono `580, 700, 581, 701` e le richieste esposizione, ISO; per 1+3 `580, 2180, 581, 2181` e le richieste esposizione, diaframma.

Con questi soli record, in questa configurazione, un consumatore non può distinguere i due modi di acquisizione. Per evitare una selezione involontaria dopo una transizione servirà valutare un'informazione aggiuntiva o una politica esplicita per le pressioni ancora attive; non è dimostrato che esista già un identificatore di snapshot recuperabile, né che una determinata politica preservi tutti i comandi voluti.

[Quattro casi PASS](../Risultati/GUI_S33/mmio_pair_origin_compare_cpu_20261029T054829Z/verified_evidence.json), 13.530 istruzioni GNU ARC700. Il banco controlla anche dieci ingressi a lettore e callback, due in più per gli scenari sequenziali: [casi](../Risultati/GUI_S33/mmio_pair_origin_compare_cpu_20261029T054829Z/cases.json), [traccia](../Risultati/GUI_S33/mmio_pair_origin_compare_cpu_20261029T054829Z/cases.trace), [verificatore](../Python_Trace_Scripts/s33_verify_gui_mmio_pair_origin_compare_cpu.py).

Il primo tasto resta attivo nel caso sequenziale: non è una prova di due pressioni complete con rilascio intermedio. Coda e stato condividono backing e fixture; eventi, acquisizione e consegna sono pilotati dal banco, senza intervalli fisici, scheduler o display. Non dimostra che altri canali di stato o temporizzazione reali non distinguano i casi, né associazione ai tasti fisici. **NON_INSTALLARE**.
