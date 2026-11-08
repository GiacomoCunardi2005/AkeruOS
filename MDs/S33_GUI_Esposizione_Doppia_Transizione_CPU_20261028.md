# GUI V1.1 — lista esposizione sintetica, ISO e tempo in CPU

Quattro sequenze GNU ARC700 usano la stessa configurazione di lista sintetica classe `0x15`: slot 0 richiede `DebugModeISO` (`0x3F`) e slot 1 `DebugModeExpTime` (`0x3E`); gli altri due non hanno destinazione nel banco. Il banco inietta i tasti logici 11 o 14, estrae dalla coda e passa esplicitamente l'evento al dispatcher originale `0x169E1C`. Manager, apertura e inizializzazione diagnostica vengono eseguiti fino al controllo scelto; selezioni e successivi eventi sono iniettati dal banco.

| Caso | Risultato software osservato | Destinazione finale originale |
|---|---|---|
| ISO, posizione 7 | indice diagnostico 6, indice convertitore 6, valore 125 | `DEBUG MODE MENU` `0x36` |
| ISO, uscita posizione 0 | sentinelle 88 / 77 / 555 invariate | `DEBUG MODE MENU` `0x36` |
| Tempo, 120→121 e conferma | due word impostate a 121.000 | `DEBUG MODE MENU` `0x36` |
| Tempo, 120→121 e annulla | due sentinelle `0x12345678` invariate | `DEBUG MODE MENU` `0x36` |

Le configurazioni sono copie separate dello stesso contenuto, con contesti sintetici e pagina zero; non è una sessione che passa da ISO a tempo e torna allo stesso menu. Assert verificano i due record di coda per ciascun tasto, selezione, descrittori iniziale/finale, campi e stack. La prova estende il [banco di instradamento](S33_GUI_Sottomenu_Esposizione_Instradamento_CPU_20261028.md), che registrava soltanto la richiesta di apertura, e riunisce le precedenti prove delle schermate separate.

PASS: quattro casi; [verificatore](../Python_Trace_Scripts/s33_verify_gui_exposure_dual_transition_cpu.py), [casi](../Risultati/GUI_S33/exposure_dual_transition_cpu_20261028T143407Z/cases.json), [manifest e trace](../Risultati/GUI_S33/exposure_dual_transition_cpu_20261028T143407Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/exposure_dual_transition_cpu_20261028T143407Z/fixture_patches.json). Le finestre e le tabelle considerate sono confrontate con il dump V1.1; DSP GNU v7 sperimentale.

Il ritorno delle schermate è ancora il menu diagnostico, non la lista sintetica: il ciclo del sottomenu richiesto resta incompleto. Manca anche la scelta f/. Lista, contesti e input sono sintetici; sincronizzazione, filtri, selezione, risorse e disegno sono fixture. Non si verificano tasti fisici, display, unità fisiche, sensore, AE o persistenza. **NON_INSTALLARE**.
