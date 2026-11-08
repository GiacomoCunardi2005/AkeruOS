# Mono RAW: ottimizzazione delle medie

Il 29 ottobre 2026 ho aggiornato il [nucleo monocromatico C](../AkeruOS/camera/mono_raw.c). Per ogni canale il numero dei fotositi usati nella media è 1, 2, 3 o 4: il codice tratta ora questi divisori in modo esplicito, mantenendo la stessa divisione intera e arrotondamento. Restano invariati controlli iniziali, coefficienti Q16 e interpretazione RGGB sperimentale. La [versione precedente](../AkeruOS/tests/fixtures/mono_raw_baseline.c) è conservata come riferimento per il confronto.

Il test confronta esattamente le uscite delle due implementazioni su **243 raster sintetici**: tutte le dimensioni da 2×2 a 10×10, con valori zero, 4095 e pseudocasuali non uniformi. **Host UBSan e GNU ARC700 PASS**, 4.522.171 istruzioni per l'intero test ARC; [manifest](../Risultati/GUI_S33/akeru_mono_equivalence_20261029T055149Z/verified_evidence.json), [test](../AkeruOS/tests/mono_raw_equivalence_test.c). Passano anche i test di input e i sei ritagli reali su host del precedente verificatore. `make -C AkeruOS mono-raw-verify` esegue le tre verifiche.

Con lo stesso [banco prestazioni](../Python_Trace_Scripts/s33_measure_akeru_mono_raw_cpu.py), raster uniforme e controlli inclusi:

| Geometria | Istruzioni prima | Istruzioni dopo | Riduzione |
|---|---:|---:|---:|
| 8×8 | 25.219 | 11.529 | 54,3% |
| 16×16 | 102.731 | 48.193 | 53,1% |
| 32×32 | 415.003 | 197.265 | 52,5% |
| 64×64 | 1.668.539 | 798.385 | 52,2% |

[Misure precedenti](../Risultati/Mono_RAW/mono_cost_cpu_20261029T055050Z/cases.json), [misure aggiornate](../Risultati/Mono_RAW/mono_cost_cpu_20261029T055130Z/cases.json). Sono istruzioni del programma completo nel simulatore, non tempo fisico; il pattern di benchmark è uniforme. L'equivalenza è verificata sui casi indicati, non su tutte le possibili immagini. Nessuna prova di prestazioni a frame completo, calibrazione, buffer di scatto, JPEG o collegamento alla GUI; **NON_INSTALLARE**.
