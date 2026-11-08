# ISO e tempo: dalla copia all'ingresso del calcolo

Il 30 ottobre 2026 ho collegato nel simulatore GNU ARC700 i setter originali ISO/tempo, la copia `0xF6F54` e il prefisso originale della routine `0xFDA28`, fino alla chiamata `0xFDBFA`. Una fixture al posto di `0xFDE08` registra i campi di ingresso e termina volutamente l'esecuzione: il calcolo successivo non viene eseguito.

Il banco usa contesti sintetici. Per ogni caso scrive indice ISO e tempo con i setter, copia il contesto, poi imposta nel contesto corrente indice 19 / valore software 1600 e tempo 121.000. Infine passa la copia precedente a `0xFDA28`. In tutti i casi il banco verifica i nuovi valori correnti e i campi effettivamente ricevuti dalla fixture:

| Campo modalità della copia | Indice ISO prima della copia | Tempo nella copia | Altra condizione sintetica | Tempo passato alla fixture |
|---:|---:|---:|---|---:|
| 4 | 6 | 42.000 | gate `+0x478` = 0 | 42.000 |
| 4 | 0 | 42.000 | gate = 1, byte `+0x21` = 1 | 42.000 |
| 4 | 6 | 42.000 | gate = 1, byte `+0x21` = 0 | 42.000 |
| 4 | 6 | 0 | gate = 1, byte `+0x21` = 1 | 0 |
| 3 | 6 | 42.000 | campo `+0x38` = 777 | 777 |
| 62 | 6 | 42.000 | gate = 1 | 0 |

Nei primi quattro casi la routine passa anche il byte e l'ISO della **copia**, non quelli cambiati successivamente. Nei casi con modalità 3 e 62 passa campi diversi o zero come mostrato. Le tracce verificano rispettivamente il ramo e la chiamata `0xFDBFA`. Questo conferma in CPU il comportamento condizionale precedentemente ricostruito [staticamente](S33_GUI_Tempo_Ingresso_Calcolo_20261027.md). I numeri di modalità sono valori interni sintetici, senza attribuzione a modalità fotografiche reali.

La routine di copia `0x128C20` è sostituita nella copia laboratorio da una fixture di copia byte per buffer sintetici non sovrapposti; la destinazione `0xFDE08` è un registratore che ferma la prova. Il contesto a `0x43C000` è memoria sintetica zero; altri byte del contesto e gate sono imposti dal banco. Il primo tentativo `101416Z` è andato in ricorsione perché la fixture di copia richiamava `0xAD920`, che a sua volta richiama `0x128C20`; il secondo `101433Z` si è fermato su memoria non mappata a `0x43C53F`. I sei casi finali usano la fixture indipendente e memoria aggiuntiva, senza modifiche ai file originali.

[Test ripetibile](../Python_Trace_Scripts/s33_probe_gui_exposure_calculation_input_cpu.py): invocare con numero da 0 a 5. [Caso 0](../Risultati/GUI_S33/exposure_calc_probe_0_20261030T101455Z/verified_evidence.json), [caso 1](../Risultati/GUI_S33/exposure_calc_probe_1_20261030T101455Z/verified_evidence.json), [caso 2](../Risultati/GUI_S33/exposure_calc_probe_2_20261030T101455Z/verified_evidence.json), [caso 3](../Risultati/GUI_S33/exposure_calc_probe_3_20261030T101455Z/verified_evidence.json), [caso 4](../Risultati/GUI_S33/exposure_calc_probe_4_20261030T101455Z/verified_evidence.json), [caso 5](../Risultati/GUI_S33/exposure_calc_probe_5_20261030T101455Z/verified_evidence.json).

Il ramo con tutti e quattro i fattori nonzero e la trasformazione numerica non è stato eseguito. Nessuna prova del chiamante `0xD8CA4`, di concorrenza, AE, GUI fisica, sensore o scatto; nessuna unità fisica del tempo stabilita. **NON_INSTALLARE**.
