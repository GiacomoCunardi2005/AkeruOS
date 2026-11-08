# Modello esposizione: apertura e conferma del tempo

Il 29 ottobre 2026 ho collegato nel [banco CPU](../Python_Trace_Scripts/s33_verify_gui_model_time_confirm_cpu.py) la richiesta tempo del modello al manager originale. Il tasto logico 78 genera `0x2700` tramite codice e coda originali; il banco passa il record al modello C già predisposto nella schermata esposizione. Quando riceve `AKERU_OPEN_SHUTTER`, chiama il servizio originale `0x1453E4(0x3E,0)`, che lascia corrente il descrittore diagnostico tempo `0x989CD8`.

Il banco inizializza a 120 la word di lavoro e consegna direttamente al dispatcher l'evento di incremento `0x380`: il valore diventa 121, mentre due campi software restano alle sentinelle iniziali. Poi consegna conferma o annulla:

| Termine | Campi software dopo il termine | Destinazione originale |
|---|---|---|
| Conferma `0x580` | 121.000 / 121.000 | menu diagnostico `0x987AF8` |
| Annulla `0x480` | sentinelle invariate | menu diagnostico `0x987AF8` |

[Due casi PASS](../Risultati/GUI_S33/model_time_confirm_cpu_20261029T054021Z/verified_evidence.json), 32.332 istruzioni: verificati azione, eventi iniziali stato 1 e 0, descrittore tempo, incremento, campi, destinazione finale e stack. [Casi](../Risultati/GUI_S33/model_time_confirm_cpu_20261029T054021Z/cases.json), [traccia e fixture](../Risultati/GUI_S33/model_time_confirm_cpu_20261029T054021Z/). Il ritorno resta alla diagnostica: non è ancora il sottomenu esposizione desiderato.

Il modello è chiamato direttamente e il banco traduce l'azione in apertura; selezione iniziale e successivi eventi sono iniettati, controllo attivo nullo, servizi e RAM sintetici, DSP sperimentale. Non sono provati unità fisiche del tempo, AE, persistenza fino allo scatto, rendering o tasti fisici. Nessuna modifica a firmware originale, fotocamera o SD; **NON_INSTALLARE**.
