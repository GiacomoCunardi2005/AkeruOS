# S33 V1.1 — banco sintetico per il sottomenu esposizione

Il 28 ottobre 2026 ho eseguito direttamente i quattro handler originali della classe `0x15` su una **stessa configurazione di quattro record sintetici**: ISO e tempo sono presenti insieme. È un banco offline che verifica la scelta della destinazione, non un sottomenu funzionante sulla fotocamera.

| Slot logico | Evento iniettato | Destinazione sintetica | Osservazione nel banco |
| --- | --- | --- | --- |
| 0 | `0x580` | `DebugModeISO` (`0x3F, 0`) | una richiesta al servizio di apertura simulato, ritorno 1 |
| 1 | `0x700` | `DebugModeExpTime` (`0x3E, 0`) | una richiesta al servizio di apertura simulato, ritorno 1 |
| 2 | `0x2180` | zero | selezione registrata, nessuna richiesta di apertura, ritorno 0 |
| 3 | `0x2700` | zero | selezione registrata, nessuna richiesta di apertura, ritorno 0 |

Le ultime due righe non costituiscono un comando apertura né un comando indietro: il ritorno zero potrebbe essere gestito da codice non incluso nella prova. Non si associa alcuno slot a un pulsante fisico. Non c'è ancora una destinazione verificata per scegliere f/ e il ritorno al menu esposizione non è stato implementato.

Le prove separate dei callback diagnostici confermano invece che ISO e tempo richiedono entrambi `0x1453E4(0x36, 0)`, identificato come `DEBUG MODE MENU`, quando escono nei casi esaminati: [verifica dell'uscita](S33_GUI_Debug_Esposizione_Uscita_20261027.md). Perciò la coesistenza delle destinazioni nella tabella sintetica non dimostra il ciclo completo selezione → modifica → ritorno. La [prova del setter iris](S33_GUI_Iride_Esiti_Setter_Prova_CPU_20261027.md) inoltre mostra che il ritorno del wrapper da solo non conferma un cambio di stato; la relazione fra stati software e valori f/ fisici è ancora ignota.

Il verificatore copia descrittore e record originali di `CaptureMenu 0x4801`, modifica solo la copia in RAM sintetica e confronta i byte degli handler e dei dati originali con `DUMPS/MainCode.dmp`. Tutti i casi usano pagina zero, guardie permissive e servizi fixture per selezione, attributi e apertura; gli attributi sono forzati a 2. Il simulatore usa il modello DSP v7 sperimentale. Controlla indice selezionato, conteggio e argomenti delle richieste, ritorno e conservazione dello stack. Gli indirizzi di banco non provano disponibilità di RAM fisica.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_exposure_submenu_routes_cpu.py), [quattro casi](../Risultati/GUI_S33/exposure_submenu_routes_cpu_20261028T090322Z/cases.json), [fixture](../Risultati/GUI_S33/exposure_submenu_routes_cpu_20261028T090322Z/fixture_patches.json), [evidenza e hash](../Risultati/GUI_S33/exposure_submenu_routes_cpu_20261028T090322Z/verified_evidence.json), [finestre GNU](../Risultati/GUI_S33/exposure_submenu_routes_cpu_20261028T090322Z/gnu_windows.txt). Nessuna prova di caricamento, rendering, dispatcher reale, tasti fisici, effetto sul sensore o persistenza; firmware, GNU, fotocamera e SD non sono stati modificati. **NON_INSTALLARE**.
