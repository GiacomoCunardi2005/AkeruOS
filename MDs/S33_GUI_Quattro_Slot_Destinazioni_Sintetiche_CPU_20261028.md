# S33 V1.1 — destinazioni sintetiche di quattro slot, prova CPU

Il 28 ottobre 2026 un banco GNU ARC700 ha eseguito direttamente i quattro handler originali della classe `0x15` su una lista **sintetica in RAM emulata**. In otto casi PASS, due varianti con pagina zero e guardie permissive producono le seguenti richieste al servizio di apertura sostituito da fixture:

| Slot logico | Evento iniettato | Record sintetico: destinazione, argomento | Risultato osservato |
| --- | --- | --- | --- |
| 0 | `0x580` | `DebugModeISO` (`0x3F, 0`) oppure `DebugModeExpTime` (`0x3E, 0`) | una richiesta di apertura, a seconda della variante |
| 1 | `0x700` | `ChangeColorMenu` (`0xBB, 0`) | una richiesta di apertura |
| 2 | `0x2180` | destinazione zero | selezione registrata, nessuna richiesta di apertura, ritorno 0 |
| 3 | `0x2700` | `GeneralSetupMenu` (`0xB7, 1`) | una richiesta di apertura |

Le varianti ISO e tempo sono **alternative nello stesso slot**, non un menu che le riunisce. Lo slot 2 è un segnaposto tecnico: il ritorno zero potrebbe essere gestito da altro codice non incluso nella prova, quindi non dimostra un pulsante disabilitato. `ChangeColorMenu` è il menu colore originale, non implementa la modalità Mono RAW Luminance richiesta. Le schermate diagnostiche ISO e tempo tornano a `DEBUG MODE MENU`, come documentato nella [verifica dell'uscita](S33_GUI_Debug_Esposizione_Uscita_20261027.md); manca quindi anche la gestione del ritorno al nuovo menu.

Il banco copia descrittore e record della lista `CaptureMenu 0x4801` e modifica **solo nella copia sintetica** puntatore dei record, destinazioni, argomenti e flag; gli handler restano originali. Confronta finestre degli handler, tabella eventi, descrittori e record originali con il dump V1.1. Selezione, attributi e apertura sono servizi fixture; gli attributi sono forzati a 2. La simulazione usa il modello GNU DSP v7 sperimentale per `MULUDW`. Ogni caso verifica indice selezionato, richiesta registrata, ritorno e conservazione dello stack. Indirizzi di test e contesti sono esclusivamente sintetici e non indicano RAM fisica libera.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_four_slots_synthetic_routes_cpu.py), [casi](../Risultati/GUI_S33/four_slots_synthetic_routes_cpu_20261028T090046Z/cases.json), [fixture](../Risultati/GUI_S33/four_slots_synthetic_routes_cpu_20261028T090046Z/fixture_patches.json), [evidenza e hash](../Risultati/GUI_S33/four_slots_synthetic_routes_cpu_20261028T090046Z/verified_evidence.json), [disassemblato](../Risultati/GUI_S33/four_slots_synthetic_routes_cpu_20261028T090046Z/gnu_windows.txt).

La prova riguarda il solo instradamento mediante handler direttamente invocati: non dimostra creazione o caricamento della lista nella GUI, dispatcher, mapping dei pulsanti fisici, apertura effettiva, rendering, ritorno, variazione delle impostazioni, RAW, persistenza o funzionamento sulla fotocamera. Firmware, GNU originale, hardware e SD non sono modificati. **NON_INSTALLARE**.
