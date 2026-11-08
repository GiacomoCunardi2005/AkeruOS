# S33 V1.1 — HiddenMenu CFA fino al dispatcher originale

28 ottobre 2026. Sei casi offline nel simulatore GNU ARC700 con modello DSP sperimentale. **NON_INSTALLARE**.

Nella stessa esecuzione il banco inizializza il flag CFA, inietta se previsto l'evento `0x5004` nel wrapper IQDEBUG originale e invoca il frammento originale `0x1E6A54`. Quest'ultimo chiama il dispatcher originale `0x28D66C`, selettore 0; solo servizi GUI, nome, disponibilità e open/write/close sono fixture. L'esecuzione del gate viene arrestata prima di `0x1E6ACC`.

| Caso | Flag dopo evento | Open/write/close fixture | Osservazione |
|---|---:|---|---|
| Nessun evento, iniziale 0 | 0 | 0/0/0 | Salvataggio non richiesto. |
| On, conteggio completo | 1 | 1/1/1 | Richiesti e simulati 2.048 byte. |
| On, conteggio 0 con write stato 0 | 1 | 1/1/1 | Dispatcher esegue ramo `0x700103`; segue close, stato osservato all'arresto 0. |
| On, write errore 77 | 1 | 1/1/1 | Segue close, stato osservato all'arresto 0. |
| On, open errore 78 | 1 | 1/1/1 | La fixture open scrive comunque un handle sintetico; seguono write e close. |
| On, close errore 79 | 1 | 1/1/1 | Stato 79 osservato all'arresto del frammento. |

Il test consolida nella stessa CPU ciò che prima era provato in banchi separati: il chiamante non interrompe localmente i tre tentativi anche se il dispatcher rileva un conteggio corto. Il valore osservato all'arresto è quello dopo la close, **non il risultato finale della funzione**: l'istruzione originale successiva chiama un altro servizio e il resto non viene eseguito. Non sono esclusi altri canali di errore. Le fixture non leggono il buffer né scrivono file; dimensioni 17×19, puntatore, nome e conteggi sono sintetici. In particolare, il caso di open fallita non rappresenta il valore di un vero handle dopo errore.

Il nome ottenuto dal percorso sintetico `B:\DCIM\DSCN1000.JPG` è `B:\DCIM\CFAi1000.raw`, non una misura del dispositivo. Gli eventi sono iniettati e il gate è chiamato direttamente dal banco: non è stata provata la sua attivazione da uno scatto reale, né contenuto CFA, purezza, JPEG o persistenza.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_cfa_menu_dispatcher_cpu.py`. [Casi](../Risultati/HiddenMenu_RAW/cfa_menu_dispatcher_cpu_20261028T144855Z/cases.json), [fixture](../Risultati/HiddenMenu_RAW/cfa_menu_dispatcher_cpu_20261028T144855Z/fixture_patches.json), [verificatore](../Python_Trace_Scripts/s33_verify_cfa_menu_dispatcher_cpu.py). Hash firmware, finestre e ingressi in traccia verificati; codice originale e installazione GNU non modificati. Il campo `reported` del caso off è solo il valore configurato nella fixture, che non viene chiamata.
