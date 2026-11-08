# S33 V1.1 — evento HiddenMenu CFA collegato al gate di salvataggio

28 ottobre 2026. Sei casi offline nel simulatore GNU ARC700 con DSP sperimentale. **NON_INSTALLARE**.

Il banco collega il wrapper originale IQDEBUG `0x7CF024`, il lookup e la tabella originali (`0x5004 → 0x7CF51C`), la callback e gli accessor originali del flag `0x366C20` al frammento originale del gate CFA `0x1E6A54`. L'evento viene **iniettato** nel wrapper; servizi grafici e dispatcher file sono fixture e il gate viene arrestato prima del resto della routine.

| Flag CFA iniziale | Eventi 0x5004 | Flag finale | Chiamate al dispatcher fixture |
|---:|---:|---:|---:|
| 0 | 0 | 0 | 0 |
| 0 | 1 | 1 | 3 |
| 1 | 1 | 0 | 0 |
| 0 | 2 | 0 | 0 |
| 0 | 1 | 1 | 3, formato sintetico alternativo |
| 0 | 1 | 1 | 3, anche con errore 77 simulato |

Il banco imposta separatamente l'altro flag RAW `0x36C26E=1` e il selettore `0x366F90=3`: dopo gli eventi CFA questi valori rimangono invariati nei sei scenari. Ciò dimostra la separazione in questa prova, non l'assenza di altri effetti o interferenze nel dispositivo. La richiesta di scrittura è 2.048 o 1.536 byte per dimensioni sintetiche 17×19, a seconda del formato del contesto; non misura un file reale.

La sequenza avvalora il nesso fra la voce diagnostica e la richiesta di esportazione: non prova accesso fisico all'HiddenMenu, scatto, dati sensore, successo delle operazioni file, JPEG o persistenza. La fixture dispatcher non dereferenzia il puntatore; errore 77 è iniettato, non osservato sulla fotocamera. Il gate viene invocato dal banco dopo l'evento: non è dimostrato che lo scatto reale raggiunga quella sequenza.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_hidden_cfa_menu_gate_cpu.py`. [Casi](../Risultati/HiddenMenu_RAW/hidden_cfa_menu_gate_cpu_20261028T144545Z/cases.json), [fixture](../Risultati/HiddenMenu_RAW/hidden_cfa_menu_gate_cpu_20261028T144545Z/fixture_patches.json), [script](../Python_Trace_Scripts/s33_verify_hidden_cfa_menu_gate_cpu.py). Il verificatore confronta le finestre originali col dump, verifica l'hash del firmware, la voce della tabella e la traccia degli ingressi. Firmware e GNU non modificati; copia laboratorio usa trampolini espliciti. La precedente esecuzione PASS `144535Z` precede l'aggiunta dei controlli sugli altri due campi e sulla traccia.
