# GUI — chiamante e copia finale del buffer di esposizione

Il 30 ottobre 2026 ho proseguito i [sei casi del chiamante `0xD8CA4`](S33_GUI_Tempo_Chiamante_Calcolo_CPU_20261030.md) fino alla copia dei 124 byte a `0x380574 + 720` e al ritorno del chiamante, con stack conservato. La traccia mostra una sola chiamata a `0xFDA28` in ciascuno di questi sei percorsi sintetici: le altre possibili chiamate non sono state prese.

| Tempo impostato | Campo signed `+0x0E` | Limite | Seconda word confronto | Tempo finale `+52` | ISO finale `+64` | Byte finale `+80` |
|---:|---:|---:|---:|---:|---:|---:|
| 42.000 | 0 | 1.000.000 | 1 | 42.000 | 125 | 1 |
| 84.000 | 0 | 1.000.000 | 1 | 84.000 | 125 | 1 |
| 42.000 | 0 | 20.000 | 1 | 20.000 | 125 | 1 |
| 42.000 | 100 | 1.000.000 | 1 | 44.941 | 125 | 1 |
| 42.000 | 0 | 1.000.000 | 42.000 | 42.000 | 125 | 0 |
| 42.000 | 0 | 1.000.000 | 50.000 | 42.000 | 125 | 0 |

In tutti i casi i tre campi letti dopo il ritorno coincidono con quelli registrati subito dopo la prima chiamata. Offset del buffer finali in byte decimali; non sono una mappa di registri del sensore.

Per osservare il primo risultato senza interrompere, una fixture nella copia laboratorio sostituisce le istruzioni `cmp` e salto a `0xD8E22`, salva i dati e riproduce la diramazione per l'argomento sintetico `r16=0`. Essa preserva i registri temporanei usati e prosegue a `0xD8E9A`; non equivale a una verifica del ramo opposto. Altre fixture: copia byte al posto del wrapper `0x128C20`, `0x18C634` e callback indiretta con ritorno zero. Parametri, RAM, limite e tabelle sono sintetici.

Il tentativo `102058Z` saltava erroneamente nell'istruzione sovrascritta dal trampolino e si fermava; `102105Z` raggiungeva il ritorno ma l'area osservazioni del banco era troppo corta. Il banco finale corregge entrambe le proprie configurazioni. [Verificatore](../Python_Trace_Scripts/s33_probe_gui_exposure_caller_complete_cpu.py), [casi 0–5](../Risultati/GUI_S33/exposure_caller_complete_probe_0_20261030T102137Z/verified_evidence.json) (sostituire lo 0 nel nome cartella con 1–5 per gli altri casi).

La copia e il ritorno sono dimostrati solo per questi ingressi e fixture, non per tutti i rami né per la macchina fisica. Non sono provati uso successivo del buffer, AE, unità fisiche, tasti o scatto. Firmware originale e dispositivo non modificati; **NON_INSTALLARE**.
