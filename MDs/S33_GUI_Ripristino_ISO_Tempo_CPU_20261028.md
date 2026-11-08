# S33 V1.1 — ripristino condizionale ISO e tempo in CPU

Il 28 ottobre 2026 ho eseguito la routine originale `0xCA654` con quattro record sintetici e i getter diagnostici, il convertitore ISO e i setter del tempo originali. Quattordici servizi riguardanti altri campi sono fixture che restituiscono zero: il banco non esegue l'intero comportamento fotografico. Le finestre interessate sono confrontate con `DUMPS/MainCode.dmp`.

Ogni record parte con indice ISO 19, indice della tabella tempo 1 e word tempo 90.000. Gli ingressi diagnostici vengono impostati direttamente dal banco; non si simula la loro impostazione tramite GUI.

| Indice ISO diagnostico | Word tempo diagnostica | Indice ISO / word tempo nel record dopo la routine | Valore ISO / word tempo nei campi software |
| ---: | ---: | --- | --- |
| 0 | 0 | 19 / 90.000 | 1600 / 90.000 |
| 0 | 42.000 | 19 / 42.000 | 1600 / 42.000 |
| 6 | 0 | 6 / 90.000 | 125 / 90.000 |
| 6 | 42.000 | 6 / 42.000 | 125 / 42.000 |

Sono **4 casi PASS**. Nei casi con ingresso diagnostico zero, la routine conserva il campo corrispondente del record; nei casi non zero lo sostituisce. Per il tempo, la routine esegue prima la conversione dell'indice del record e poi scrive la word finale dal record: quest'ultima prevale nel tratto eseguito. Zero qui descrive solo la guardia di questo percorso, non dimostra una modalità automatica o un significato fisico.

La routine è chiamata direttamente, i campi e il record sono sintetici e i servizi sostituiti possono avere effetti rilevanti nel sistema reale. Non si conoscono ordine runtime, concorrenza, valori reali, persistenza, guadagno sensore o durata dello scatto. Il primo tentativo `090108Z` e il secondo `090130Z` sono conservati come FAIL per finestre di disassemblaggio tagliate; il banco corretto usa finestre allineate e non modifica codice firmware per aggirare l'emulatore. Nessuna operazione su fotocamera, NAND o SD; **NON_INSTALLARE**.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_debug_restore_cpu.py), [quattro casi](../Risultati/GUI_S33/debug_restore_cpu_20261028T090140Z/cases.json), [fixture](../Risultati/GUI_S33/debug_restore_cpu_20261028T090140Z/fixture_patches.json), [finestre GNU](../Risultati/GUI_S33/debug_restore_cpu_20261028T090140Z/gnu_windows.txt), [risultato e hash](../Risultati/GUI_S33/debug_restore_cpu_20261028T090140Z/verified_evidence.json).
