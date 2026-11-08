# S33 V1.1 — formato richiesto dal controllo diagnostico del tempo

Il 28 ottobre 2026 ho esteso il banco originale di modifica/conferma/annullamento del tempo: la fixture del servizio di formattazione registra ora il puntatore al formato e il valore passato dal codice originale `0x7D24BC`. Le stringhe originali sono confrontate con `DUMPS/MainCode.dmp`.

Nelle **sette sequenze CPU PASS**, per l'ultima modifica di ogni sequenza:

- se la word di lavoro finale è zero, il codice richiede il formato originale `Auto`;
- se è non zero, richiede il formato originale `%000d` e passa la word come argomento numerico.

Per esempio, da 3999 con evento su il controllo produce word zero e richiede `Auto`; da 120 con due eventi su produce 122 e richiede `%000d` con argomento 122. Conferma e annullamento si comportano nei casi provati come nella [prova precedente](S33_GUI_Debug_Esposizione_Uscita_20261027.md).

La formattazione, la scrittura del testo e il display sono fixture: non sono stati prodotti né osservati caratteri sullo schermo. La parola `Auto` è il testo richiesto dalla schermata diagnostica; non dimostra la semantica dell'esposizione automatica, il tempo fisico o la persistenza. Gli eventi sono iniettati direttamente e non identificano pulsanti fisici. Firmware e fotocamera non modificati; **NON_INSTALLARE**.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_debug_time_session_cpu.py), [sette casi](../Risultati/GUI_S33/debug_time_session_cpu_20261028T090322Z/cases.json), [fixture](../Risultati/GUI_S33/debug_time_session_cpu_20261028T090322Z/fixture_patches.json), [risultato e hash](../Risultati/GUI_S33/debug_time_session_cpu_20261028T090322Z/verified_evidence.json).
