# ISO software: correttivo e copia finale — CPU emulata

Il 5 novembre 2026 è stato esteso il [banco delle scelte ISO e del calcolo](S33_GUI_ISO_Scelte_Conferma_Calcolo_CPU_20261030.md). Inietta le conferme diagnostiche ISO e tempo, poi chiama esplicitamente il chiamante originale `0xD8CA4`; il getter originale `0xE309C` riceve un puntatore a una tabella sintetica con flag, soglia ISO **125** e correttivo signed **−7**. Questi valori sono scelti per la prova, non misurati in camera. Il banco osserva il campo `+76` del primo buffer dopo `0xFDA28` e quello della copia finale da 124 byte a `0x380844`, dopo il ritorno del chiamante.

| ISO software scelto | Flag tabella | Guardia contesto | Primo `+76` | Copia finale `+76` |
|---:|---:|---:|---:|---:|
| 125 | 1 | 0 | 0 | 0 |
| 1600 | 1 | 0 | 7 | 7 |
| 125 | 0 | 0 | 0 | 0 |
| 1600 | 0 | 0 | 0 | 0 |
| 1600 | 1 | 1 | 0 | 0 |

**5/5 PASS**. In ciascuno di questi casi la traccia verifica una sola chiamata a `0xFDA28`, il suo store originale a `0xFDBFE`, il percorso di conferma e la copia finale. ISO 1600, guardia 0 e contesti uguali: confrontando tutti i 124 byte delle due copie con flag rispettivamente 1 e 0, differiscono soltanto gli offset `+0` e `+76`, entrambi `7` contro `0`. Il confronto descrive queste due esecuzioni e non attribuisce un significato fisico ai campi. [Indice, hash dei cinque risultati e confronto](../Risultati/GUI_S33/iso_threshold_final_buffer_20261105T103000Z/comparison.json). La regressione senza la nuova tabella con selezione Auto passa e continua a mostrare due chiamate `0xFDA28`: [evidenze](../Risultati/GUI_S33/gui_iso_choices_calc_probe_1_20261105T103000873600Z/verified_evidence.json).

La halfword `fp−4` modificata dalla precedente [prova del consumatore `0x18C90C`](S33_GUI_ISO_Consumatore_Scrittura_CPU_20261105.md) è distinta dal buffer locale `fp−200` passato a `0xFDA28` e dalla sua copia a `0x380844`. Questa prova segue il risultato aritmetico sino a quest'ultimo; non dimostra che la halfword della prova precedente venga copiata lì.

Riproduzione: `python3 Python_Trace_Scripts/s33_probe_gui_iso_choices_to_calc_cpu.py 3 --threshold`; `2` sceglie ISO 125, `3` ISO 1600; `--disabled` azzera il flag e `--guard` imposta la guardia. Le singole cartelle contengono snapshot dello script, tracce, immagini fixture e manifest.

Input, ordine delle conferme e chiamata a `0xD8CA4` sono imposti. Il banco usa RAM e tabella sintetiche, callback e copia byte fixture e DSP GNU sperimentale; a `0xD8E22` un registratore sostituisce il confronto e riproduce il ramo scelto. Anche la copia finale usa una routine fixture: la sua corrispondenza con il funzionamento completo della fotocamera non è dimostrata. Non sono verificati tempi fisici, AE, guadagno, persistenza, concorrenza o uso del buffer da parte del sensore; altre condizioni possono portare a chiamate e sovrascritture differenti. Nessun dispositivo o supporto modificato; **NON_INSTALLARE**.
