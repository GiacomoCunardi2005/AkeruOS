# Tempo: tasto logico, modifica e ritorno — 28 ottobre 2026

Due sequenze GNU ARC700 eseguono tasto logico 11, coda, dispatcher e WindowManager originali per aprire `DebugModeExpTime` `0x3E`; il descrittore corrente diventa `0x989CD8`. Il banco imposta la word di lavoro a 120 e inietta l'evento `0x380` nel dispatcher: il callback originale porta la word a 121. I due campi `0x365788` e `0x37FBF4`, impostati a `0x12345678`, rimangono invariati dopo la modifica.

| Fine iniettata | Evento | Campi dopo la fine | Descrittore corrente |
|---|---:|---|---|
| Conferma | `0x580` | 121.000 / 121.000 | `0x987AF8`, DEBUG MODE MENU `0x36` |
| Annulla | `0x480` | `0x12345678` / `0x12345678` | `0x987AF8`, DEBUG MODE MENU `0x36` |

La conferma usa il setter originale, che in questi casi scrive la word moltiplicata per 1000. L'apertura e il ritorno attraversano `0x1453E4` e `0x145180` originali. La selezione iniziale del tempo, modifica e conferma non sono state effettuate con tasti fisici: i tre eventi successivi sono consegnati dal banco al dispatcher, che riceve un controllo corrente nullo sintetico. Il ritorno resta al menu diagnostico, non al futuro sottomenu esposizione.

La lista principale, manager e contesti sono sintetici; lock, notifiche, filtro, attributi, recupero della risorsa, testo, formato, timer e disegno sono fixture. Il modello DSP è sperimentale. [Verificatore](../Python_Trace_Scripts/s33_verify_gui_key_time_confirm_transition_cpu.py) e [risultati](../Risultati/GUI_S33/key_time_confirm_transition_cpu_20261028T093248Z/) includono trace, patch e hash. I byte dei percorsi e la tabella degli eventi sono controllati sul dump V1.1. Non sono dimostrati unità fisiche, tempi di scatto, display, AE o persistenza dei campi; nessuna operazione su fotocamera o SD. **NON_INSTALLARE**.
