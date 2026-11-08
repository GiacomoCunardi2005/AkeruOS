# S33 V1.1 — aggiornamento dei record e selezione degli slot

27 ottobre 2026. In CPU ARC700 emulata, la routine originale `0x7CB1B4` è stata eseguita direttamente su copie dei quattro record della lista originale CaptureMenu `0x4801`; subito dopo è stato chiamato uno degli handler originali degli slot 2 e 3. I **6 casi PASS** mostrano un collegamento tra la modifica dei flag e la successiva richiesta di apertura, nelle condizioni sintetiche indicate sotto.

Il primo ciclo della routine chiama `0x631E98` con argomento zero per ciascun record: nel banco il bit 1, inizialmente impostato artificialmente su tutti e quattro, viene cancellato. Per i record il cui campo signed `+20` è `0x0A` o `0xBB`, un secondo ciclo può reimpostarlo, a seconda dei risultati di due helper. I record originali di indice 2 e 3 hanno proprio questi due valori. Gli helper e l'ID del controllo corrente sono fixture, stabili durante ciascun caso.

| Risultati sintetici di `0xCAD30`, `0xCA310` | Flag finali dei quattro record (`+24`) | Slot 2 / slot 3 |
| --- | --- | --- |
| 0, 0 | 8, 0, 2, 2 | Nessuna richiesta di apertura |
| 44, 7 | 8, 0, 2, 2 | Nessuna richiesta di apertura |
| 44, 0 | 8, 0, 0, 0 | Rispettivamente richiesta `(0x0A, 0)` e `(0xBB, 0)` |

Le richieste sono registrate da una fixture di `0x1453E4`, non finestre effettivamente aperte. La prova usa attributi restituiti da fixture pari a 2 e pagina zero. Anche il servizio di selezione `0x631E00` è una fixture; quando il bit 1 blocca l'handler, quest'ultimo non chiama né il servizio di selezione né quello di apertura. Stack verificato per ogni caso.

Staticamente, nel callback CaptureMenu `0x4405` la routine `0x7CB1B4` segue `0x7CB118`, che può scegliere il controllo in base all'argomento d'ingresso; il banco **non** esegue quel callback completo, il caricamento o il passaggio dell'argomento. La stessa routine opera sui record attraverso il puntatore del controllo e modifica i flag: un nuovo record non basta da solo a garantire una voce disponibile. Servono un controllo valido per l'intero suo lifetime, risorse e destinazione coerenti, oltre a considerare gli aggiornamenti che possono cambiare i flag. La prova non identifica un'area RAM fisica libera o un meccanismo di installazione.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_capture_init_slot_cpu.py), [sei casi](../Risultati/GUI_S33/capture_init_slot_cpu_20261027T215042Z/cases.json), [fixture](../Risultati/GUI_S33/capture_init_slot_cpu_20261027T215042Z/fixture_patches.json), [evidenza e hash](../Risultati/GUI_S33/capture_init_slot_cpu_20261027T215042Z/verified_evidence.json), [istruzioni GNU](../Risultati/GUI_S33/capture_init_slot_cpu_20261027T215042Z/gnu_windows.txt). I byte di codice e della lista sono confrontati con il dump V1.1; il banco usa copie isolate e il modello GNU DSP v7 sperimentale. Non dimostra consegna eventi, stato reale degli helper, rendering, ordine dei tasti fisici, fotocamera o persistenza. Firmware originali invariati; **NON_INSTALLARE**.
