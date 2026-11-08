# GUI V1.1 — audit dei tentativi di ritorno FEB, 28 ottobre 2026

Sei prove successive al [tentativo MMIO](S33_GUI_Esposizione_Ritorno_MMIO_Tentativo_20261028.md) erano già presenti, ma non documentate nel checkpoint. Tutte riportano **FAIL**. La tabella segue i manifest, non implica sei prove indipendenti con una sola variabile cambiata: lo script è stato modificato tra le esecuzioni e non vi è uno snapshot dello script nei risultati falliti.

| Run UTC 2026-10-28 | Istruzioni | Primo accesso non mappato (lettura 16 bit) |
|---|---:|---|
| 143754 | 13.367 | `0x0FEB4010` a `0x17B49C` |
| 143801 | 13.411 | `0x0FEE0180` a `0x208BF8` |
| 143805 | 13.416 | `0x0FEE01A0` a `0x208C14` |
| 143809 | 13.457 | `0x0FEE02C0` a `0x20A140` |
| 143814 | 13.488 | `0x0FEE0480` a `0x20A844` |
| 143821 | 13.532 | `0x0FEB0000` a `0x20C718` |

Nell'[ultima traccia](../Risultati/GUI_S33/exposure_return_feb_cpu_20261028T143821Z/cases.trace), la CPU supera `0x1789CC`: legge `1` da `0x0FEB211C` e `0` da `0x0FEB2120`, quindi prosegue attraverso gli altri accessi modellati della tabella fino al nuovo fault. I valori sono input sintetici, non misure; il file fixture contiene halfword iniziali `1, 0, 1` e la memoria mappata è ordinaria. La traccia, il file fixture, `cases.elf` e `cases.bin` dell'ultima prova coincidono con gli hash del suo [manifest FAIL](../Risultati/GUI_S33/exposure_return_feb_cpu_20261028T143821Z/verified_evidence.json). Il confronto degli hash verifica l'integrità degli artefatti elencati, non il modello o il risultato della GUI.

L'ultimo script disponibile è [s33_verify_gui_exposure_return_feb_cpu.py](../Python_Trace_Scripts/s33_verify_gui_exposure_return_feb_cpu.py); il comando e i file della singola esecuzione sono nel relativo risultato. La CPU non ha completato il primo caso, quindi gli assert sui quattro casi e sul ritorno al menu non sono stati raggiunti. Nessuna conclusione su tasti fisici, display, persistenza o esposizione reale segue da queste tracce. Servizi, tabelle, contesti e MMIO sono fixture; DSP v7 e AUX 69 sono modelli sperimentali. La sequenza suggerisce di analizzare `0x20C70C` e il contratto del suo accesso prima di scegliere un modello motivato, invece di aggiungere indiscriminatamente celle zero. **NON_INSTALLARE**.
