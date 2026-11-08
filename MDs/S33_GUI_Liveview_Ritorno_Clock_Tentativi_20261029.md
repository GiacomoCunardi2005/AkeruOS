# Ritorno live view: ulteriori dipendenze simulate

Il 29 ottobre 2026 ho continuato il [banco fermo su FE800AC](S33_GUI_Liveview_FE8014C_CPU_20261029.md). In quattro tentativi successivi, ciascuno conserva le dipendenze sintetiche precedenti e aggiunge una regione nel simulatore:

| Tentativo | Regione aggiunta | Esito |
|---|---|---|
| [224031Z](../Risultati/GUI_S33/liveview_return_ac_probe_cpu_20261029T224031Z/verified_evidence.json) | `0x0FE800AC`, seed `0xA55A` | FAIL a lettura `0x0FE80120` in `0x17A6D6`, dopo 587.149 istruzioni. La cella AC passa `A55A→A55A→A14A`; controllati hash della traccia e backing finale. |
| [224042Z](../Risultati/GUI_S33/liveview_return_clock_probe_cpu_20261029T224042Z/verified_evidence.json) | `0x0FE80120`, seed zero | FAIL a `0x0FE800A0` in `0x17A8B4`, dopo 588.956 istruzioni. |
| [224049Z](../Risultati/GUI_S33/liveview_return_a0_probe_cpu_20261029T224049Z/verified_evidence.json) | `0x0FE800A0`, seed zero | FAIL a `0x0FE80140` in `0x17A8B4`, dopo 590.723 istruzioni. |
| [224058Z](../Risultati/GUI_S33/liveview_return_140_probe_cpu_20261029T224058Z/verified_evidence.json) | `0x0FE80140`, seed zero | FAIL a `0x0FE800D4` in `0x17A8B4`, dopo 591.610 istruzioni. |

La routine `0x17A6CC` legge due volte la halfword a `FE80120` e una a `FE80118`, già mappata dal banco; la traccia del secondo tentativo mostra zeri in queste letture. Il codice prosegue usando un'istruzione DSP nel modello GNU sperimentale. Un [precedente studio statico](S33_Parametri_Clock_e_Proseguimento_Boot.md) collega questa routine a un getter con cache: qui non si dimostra che zero sia un parametro corretto o una frequenza fisica.

Nessuna delle prove raggiunge gli assert di ritorno o il descrittore finale. I seed sono input di laboratorio e le celle sono memoria ordinaria, senza effetti periferici; guardie, RAM e altri servizi rimangono sintetici. Non si inferiscono tempi, stato hardware, display o successo sulla fotocamera. Prima di continuare occorre ricostruire i parametri e la semantica dei servizi coinvolti, non assumere che una sequenza di zeri costituisca inizializzazione reale. **NON_INSTALLARE**.
