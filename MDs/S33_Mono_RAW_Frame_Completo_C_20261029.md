# S33 — confronto monocromatico C su fotogrammi completi

Il 29 ottobre 2026, su host, `akeru_color_process` in modalità mono è stato applicato ai due DSCo 1003 e 1012 completi. Il risultato intero è confrontato pixel per pixel con i TIFF float32 precedentemente prodotti dal riferimento Python indipendente. Il confronto è in unità RAW, moltiplicando il riferimento per 4092; comprende i bordi.

| RAW | Pixel confrontati | Errore massimo (unità RAW) | Errore medio | Differenza media JPEG decodificato (livelli 8 bit) | Massima |
|---|---:|---:|---:|---:|---:|
| 1003 | 13.263.616 | 0,531755 | 0,250075 | 0,341697 | 6 |
| 1012 | 13.263.616 | 0,515528 | 0,250130 | 0,423847 | 6 |

Entrambi i massimi sono inferiori alla soglia di 0,7 unità RAW. Il TIFF è float32, mentre il risultato C è intero: le differenze comprendono arrotondamenti e quantizzazione. Le differenze JPEG sono misurate dopo decodifica, includono anche la compressione e non implicano identità byte per byte.

Le anteprime [1003](../outputs/mono_raw_c_full_20261029T224554Z/DSCo1003_mono_C.jpg) e [1012](../outputs/mono_raw_c_full_20261029T224554Z/DSCo1012_mono_C.jpg) usano gli stessi limiti tonali del riferimento Python, ombre `x + 0.16*x*(1-x)^2`, curva sRGB e Pillow qualità 98, in scala di grigi. Sono JPEG sperimentali prodotti offline, non impostazioni lette dalla macchina. Bayer RGGB, nero 0, bianco 4092 e guadagni RGB 1,75/1/1,43 rimangono ipotesi non calibrate.

Il [verificatore](../Python_Trace_Scripts/s33_verify_mono_raw_full_frames.py) compila i sorgenti C per host, legge RAW e riferimenti, confronta tutti i pixel e controlla gli SHA-256 prima e dopo. [Dati e hash](../outputs/mono_raw_c_full_20261029T224554Z/report.json). RAW, TIFF e JPEG di riferimento non modificati.

La prova non dimostra esecuzione sulla fotocamera, prestazioni reali, collegamento alla cattura/JPEG firmware, calibrazione o orientamento fisico CFA. Il monocromatico è luminanza derivata da un sensore a colori; il candidato resta **NON_INSTALLARE**. Struttura RAW e parametri JPEG precedenti: [struttura](S33_RawsAnalysis_Struttura_e_Risultati_20261029.md), [metadata e ricette](S33_RAW_Metadata_e_Parametri_JPEG_20261029.md).
