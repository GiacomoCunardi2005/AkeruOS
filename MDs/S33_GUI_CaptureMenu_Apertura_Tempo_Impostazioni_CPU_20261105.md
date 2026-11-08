# CaptureMenu: apertura di destinazioni originali — 2026-11-05

## Risultato

Nel firmware S33 V1.1, in CPU ARC emulata con stato e servizi sintetici, la sequenza snapshot → AutoScene → CaptureMenu originale → evento successivo raggiunge il gestore originale e apre due destinazioni Nikon esistenti. I record di CaptureMenu sono alterati solo nella RAM emulata: `0x980244` = `0x3e`, `0x980260` = `0xb7`, `0x98025c` = 1. Le finestre di codice, descrittori e voci di tabella verificate corrispondono al dump originale. Le due chiamate al gestore non sono intercettate.

| Evento successivo | Richiesta | Descrittore finale | Callback originale raggiunto |
| --- | --- | --- | --- |
| `0x2180` | `0x3e, 0` | `0x989cd8` | `0x7d22f0` |
| `0x2700` | `0xb7, 1` | `0x99242c` | `0x7ea958` |

Il primo target è usato come destinazione diagnostica legata al tempo, il secondo alle impostazioni: questo esperimento non dimostra un controllo funzionale dell'otturatore o delle impostazioni. Con guardia manager `0x366ebb` impostata dopo l'apertura iniziale, entrambi gli eventi restituiscono 1 dal dispatcher ma lasciano attivo `0x9802ac`, senza raggiungere i rispettivi callback. Non è dimostrato un eventuale successivo tentativo automatico.

## Verifica riproducibile

Verificatore: `Python_Trace_Scripts/s33_verify_snapshot_capture_focus_original_cpu.py`. Otto processi indipendenti, due target × guardia libera/occupata × fixture UI 0/0x23, tutti PASS il 2026-11-05 UTC:

- UI 0, target tempo: `Risultati/GUI_S33/snapshot_capture_focus_original_cpu_20261105T105255998832Z` e guardia occupata `...105256716484Z`.
- UI 0, impostazioni: `...105257427953Z` e guardia occupata `...105258163421Z`.
- UI 0x23, target tempo: `...105258952410Z` e guardia occupata `...105259733012Z`.
- UI 0x23, impostazioni: `...105300673891Z` e guardia occupata `...105301800937Z`.

Ogni cartella contiene trace, scenario, snapshot del verificatore, patch fixture e risultati. Comando base: `python3 Python_Trace_Scripts/s33_verify_snapshot_capture_focus_original_cpu.py --boot-2c --custom-targets --open-targets`; aggiungere `--settings`, `--target-busy`, `--ui-mode-23` per le altre combinazioni. Regressioni precedenti nella stessa sessione: 2c con richieste intercettate e percorso 46, 4/4 ciascuna (`...105231261644Z`, `...105232284757Z`).

## Confini

MMIO e consegna eventi, RAM delle destinazioni, modalità `CAD30=0x2c`, guardie e vari servizi/lifecycle sono fixture; il modello DSP è sperimentale. Lo scanner originale genera pressione e rilascio iniziali; il secondo evento è consegnato logicamente, senza verificarne rilascio e uscita dalla schermata. Non sono stati verificati rendering, navigazione completa, pagina personalizzata, persistenza, esposizione, memoria fisica o hardware. REA ha rifiutato l'ELF ARC come architettura non supportata; la prova usa il simulatore GNU disponibile senza cambiarne sorgenti/build. Nessun candidato è installabile: **NON_INSTALLARE**.
