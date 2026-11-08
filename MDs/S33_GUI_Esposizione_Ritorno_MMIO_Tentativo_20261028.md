# Lista esposizione — continuazione con MMIO modellato, 28 ottobre 2026

La [prova precedente](S33_GUI_Esposizione_Ritorno_Tabella_Tentativo_20261028.md) si arrestava all'accesso `0x1F08F4→0x0FEF0020`. Il percorso è già stato studiato separatamente nel [loop FE6](S33_Registri_FE6_Loop_Originale_e_Modalita_20261025.md): il banco qui riusa come **input sintetici**, non come valori hardware, `FEF0020=0x00A4`, `FE800BC=0`, `FED3000=0`, `FED3800=8`. La traccia mostra le quattro letture originali e il proseguimento della CPU.

Altri registri raggiunti successivamente sono modellati come memoria ordinaria inizialmente zero: `FE80158`, `FE8014C`, `FEF000C`, `FE800AC`, `FE8002C`, `FE80108`, `FE80100`; la CPU esegue anche scritture sui backing modellati. Il modello DSP v7 e una scrittura AUX 69 storage-only risultano nella diagnostica. Il percorso non è un modello fisico di timing, periferiche o AUX.

**Esito ancora FAIL:** il primo caso, dopo 13.256 istruzioni nel modello, arriva a `0x1789CC` e si ferma sulla lettura halfword non mappata `0x0FEB211C`. La routine di apertura e il ritorno al sottomenu non sono completati; gli altri tre casi non sono stati eseguiti fino alla fine. Il nuovo fault non dimostra un problema sulla fotocamera.

[Script sperimentale](../Python_Trace_Scripts/s33_verify_gui_exposure_return_mmio_cpu.py), [manifest FAIL](../Risultati/GUI_S33/exposure_return_mmio_cpu_20261028T143709Z/verified_evidence.json), [traccia CPU](../Risultati/GUI_S33/exposure_return_mmio_cpu_20261028T143709Z/cases.trace). I tentativi intermedi sono conservati con i loro fault. Lista e tabella oggetti sono copie sintetiche; la rimappatura globale dell'ID `0x36`, rendering, ciclo completo, hardware e persistenza restano non verificati. **NON_INSTALLARE**.
