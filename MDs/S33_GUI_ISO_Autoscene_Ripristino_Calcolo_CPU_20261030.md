# GUI — ramo AutoScene, ISO e calcolo

Il 30 ottobre 2026 ho esteso il [banco sul record ISO](S33_GUI_ISO_Origine_Record_Wrapper_CPU_20261030.md). Dopo conferma diagnostica ISO e tempo, il banco entra direttamente nel frammento originale `0x659C08` con `r14` impostato al getter originale `0xCAD30`. Quest'ultimo legge un byte di modalità predisposto in RAM sintetica. Se è `0x2C`, il frammento chiama `0x65BA94 → 0x65BC60 → 0xCA5DC → 0xCA654`; se è `0x2B`, non chiama il wrapper. Il banco poi invoca esplicitamente il calcolo `0xD8CA4`.

| Scelta diagnostica | Aggiornamento operativo 19 imposto dopo conferma | Modalità sintetica | Wrapper chiamato | ISO software nel buffer finale |
|---|---|---:|---|---:|
| Auto | no | `0x2C` | sì | 0 |
| Auto | sì | `0x2C` | sì | 0 |
| 125 | no | `0x2C` | sì | 125 |
| 125 | sì | `0x2C` | sì | 125 |
| Auto | no | `0x2B` | no | 0 |
| Auto | sì | `0x2B` | no | 1600 |
| 125 | no | `0x2B` | no | 125 |
| 125 | sì | `0x2B` | no | 1600 |

L'aggiornamento artificiale chiama `0x17C320(19)` e cambia l'indice operativo, senza cambiare quello diagnostico. Nel ramo `0x2C`, il wrapper prepara il record e il ripristino riporta il valore a quello della scelta diagnostica; nel ramo `0x2B` tale ripristino non è eseguito e l'aggiornamento operativo rimane visibile al calcolo. Il tempo finale è 42.000 in tutti i casi, valore software senza unità fisica stabilita. Gli otto casi verificano numero di ingressi al wrapper, campi del record quando esiste, campo ISO finale, copia finale e stack.

L'osservazione riguarda un frammento chiamato direttamente, non l'intero handler AutoScene: non dimostra che l'evento `0x4405` lo raggiunga, che `r14` abbia quel valore nella macchina o che la fotocamera assuma quelle modalità. La continuazione `0x659C12` è fixture; sono fixture anche servizi del wrapper, getter ausiliari, callback, copia e apertura GUI. Modalità, aggiornamento dell'indice, stato, tabelle e ordine sono sintetici; GNU DSP è sperimentale. Non attribuire automaticamente il comportamento alla fotocamera fisica.

[Verificatore](../Python_Trace_Scripts/s33_probe_gui_iso_autoscene_to_calc_cpu.py); [caso 0](../Risultati/GUI_S33/gui_iso_autoscene_calc_probe_0_20261030T102803Z/verified_evidence.json), con numeri 1–7 nelle rispettive cartelle per gli altri casi. Non sono verificati AE, tasti, sensore, scatto o unità fisiche. Firmware e dispositivo invariati; **NON_INSTALLARE**.
