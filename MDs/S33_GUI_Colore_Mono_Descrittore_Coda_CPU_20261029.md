# Scelta colore/mono dal gestore originale al nucleo C

Il 29 ottobre 2026 ho esteso il [banco di apertura del descrittore modello](S33_GUI_Apertura_Menu_Modello_CPU_20261029.md) al [componente colore/mono](S33_GUI_Colore_Mono_Nucleo_Collegamento_CPU_20261029.md). Il banco predispone il modello nella schermata colore, genera un evento con lo scrittore e la coda originali, apre il descrittore sintetico con il manager e consegna il record estratto al dispatcher originale. Il callback sperimentale invoca il modello C; il banco acquisisce l'azione prima della controparte e chiama selezione e elaborazione del componente C.

| Tasto logico e evento sintetico | Scelta e risultato su frame 2×2, tutti i campioni 1024 |
|---|---|
| 14 / `0x700` | Standard: modalità 0, elaborazione restituisce 0, output sentinella `777` invariato. |
| 67 / `0x2180` | Mono: modalità 1, elaborazione restituisce 1, quattro campioni di luminanza `1219`. |

Le modalità iniziali sono opposte a quelle scelte; entrambi i casi verificano cambio di modalità, record e controparti, descrittore corrente, stack e conservazione dei quattro campioni RAW. **Due casi PASS**, 13.166 istruzioni GNU ARC700: [casi](../Risultati/GUI_S33/descriptor_color_raw_cpu_20261029T224439Z/cases.json), [manifest e traccia](../Risultati/GUI_S33/descriptor_color_raw_cpu_20261029T224439Z/verified_evidence.json), [banco](../Python_Trace_Scripts/s33_verify_gui_descriptor_color_raw_cpu.py).

Il collegamento tra azione, selezione e frame è effettuato dal banco, non da un hook nello scatto Nikon. Il descrittore non ha risorse grafiche; stato iniziale, eventi, RAM e MMIO sono sintetici, vari servizi sono fixture e il DSP è sperimentale. Standard non esegue la pipeline JPEG Nikon nel test; mono usa i parametri provvisori non calibrati. Non sono verificati tasti fisici, sincronizzazione, scatto o salvataggio. **NON_INSTALLARE**.
