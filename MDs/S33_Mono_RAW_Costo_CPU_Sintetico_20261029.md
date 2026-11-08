# Mono RAW C: costo nel simulatore ARC700

Il 29 ottobre 2026 ho misurato il nucleo [`mono_raw.c`](../AkeruOS/camera/mono_raw.c) compilato `-O2` per ARC700 su raster sintetici RGGB quadrati con tutti i campioni uguali a 1024. Ogni esecuzione inizializza l'ingresso, converte e verifica tutti i pixel di uscita (1219). Il conteggio è quello riportato dal profiler GNU per **l'intero programma**, incluse inizializzazione, validazione, conversione e controllo; non sono cicli o tempo della fotocamera.

| Geometria | Pixel | Istruzioni totali | Istruzioni per pixel, programma intero |
|---|---:|---:|---:|
| 8×8 | 64 | 25.219 | 394,0 |
| 16×16 | 256 | 102.731 | 401,3 |
| 32×32 | 1.024 | 415.003 | 405,3 |
| 64×64 | 4.096 | 1.668.539 | 407,4 |

Il costo osservato suggerisce che il nucleo di riferimento necessita di una valutazione e probabilmente di ottimizzazione prima di un uso nello scatto: un frame DSCo ha 13.263.616 pixel. Non si può convertire questo rapporto direttamente in secondi o attribuire l'intero conteggio alla sola conversione. Dimensione, contenuto, compilatore, costi di memoria, DMA e contesa reale possono cambiare il risultato.

[Banco ripetibile](../Python_Trace_Scripts/s33_measure_akeru_mono_raw_cpu.py), [misure](../Risultati/Mono_RAW/mono_cost_cpu_20261029T055050Z/cases.json), [manifest e comandi](../Risultati/Mono_RAW/mono_cost_cpu_20261029T055050Z/verified_evidence.json). Le quattro verifiche di uscita sono PASS; è un solo pattern uniforme, non una nuova verifica di qualità. La [prova precedente](S33_Mono_RAW_Nucleo_C_CPU_20261029.md) copre anche dati non uniformi e ritagli reali su host.

Nessun frame completo è stato eseguito in ARC, né sono stati verificati tempi hardware, memoria disponibile, pipeline JPEG, calibrazione o collegamento alla GUI. **NON_INSTALLARE**.
