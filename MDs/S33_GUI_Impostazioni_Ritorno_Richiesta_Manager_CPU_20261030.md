# Impostazioni — richiesta di ritorno dal manager

Il 30 ottobre 2026 ho esteso il percorso del quarto slot in un [banco GNU ARC700](../Python_Trace_Scripts/s33_probe_gui_settings_back_request_cpu.py). Il generatore e la coda originali producono l'evento logico `0x2700`; il banco lo consegna al dispatcher originale e al callback del descrittore sintetico AkeruOS. Il modello richiede le impostazioni, quindi il banco chiama il manager originale per aprire `GeneralSetupMenu` (`0xB7`, argomento 1). In entrambi i casi il descrittore corrente diventa `0x99242C`.

Il banco predispone poi il contesto di ritorno e consegna direttamente al dispatcher l'evento `0x580`. L'handler originale `0x7EAAD8` legge il byte del contesto e, nei due casi PASS, richiede:

| Byte sintetico | Destinazione richiesta | Argomento |
|---:|---|---:|
| 1 | `0x87`, AutoSceneLiveView | 0 |
| 2 | `0x5E`, ReviewState | 0 |

La chiamata finale di apertura nell'handler è deviata **nella sola copia di laboratorio** a un registratore, per evitare di attribuire a uno scheduler inventato un ritorno completo. Il manager resta quindi nel descrittore impostazioni: non è un ritorno effettivo. La traccia verifica due ingressi nel manager originale di apertura iniziale, due nell'handler di ritorno e due nel registratore; sono verificati destinazione, argomento, conteggio e stack. [Casi](../Risultati/GUI_S33/descriptor_settings_back_request_cpu_20261030T154938Z/cases.json), [manifest](../Risultati/GUI_S33/descriptor_settings_back_request_cpu_20261030T154938Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/descriptor_settings_back_request_cpu_20261030T154938Z/fixture_patches.json) e traccia nella stessa cartella.

Il risultato collega la richiesta dell'handler al percorso sperimentale di apertura delle impostazioni: la scelta originale dipende dal contesto e **non richiede il nuovo menu AkeruOS**. Per rientrare nel menu desiderato serve ancora una gestione del contesto di provenienza e una transizione effettiva verificata, senza alterare i ritorni Nikon da altre schermate. Eventi, contesti e vari servizi sono sintetici; apertura di ritorno, scheduler, rendering, persistenza e tasti fisici non sono verificati. Il DSP GNU usato è sperimentale. Nessuna modifica a firmware originale, fotocamera o SD; **NON_INSTALLARE**.

Il tentativo `154901Z` è fallito perché il primo assemblaggio del salto verso il registratore trattava il numero come spostamento anziché destinazione; la versione finale usa una rilocazione a simbolo e controlla la destinazione in traccia. Anche i precedenti tentativi di transizione completa falliti sono conservati nel [rapporto precedente](S33_GUI_Impostazioni_Ritorno_Manager_Tentativo_CPU_20261029.md).
