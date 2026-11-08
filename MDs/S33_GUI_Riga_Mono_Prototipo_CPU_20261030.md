# GUI — prototipo per la riga a un bit ritagliata

Il 30 ottobre 2026 è stato preparato un prototipo isolato di `akeru_mono_scanline` in [mono_scanline.c](../AkeruOS/ui/mono_scanline.c), con la struttura di argomenti in [mono_scanline.h](../AkeruOS/ui/mono_scanline.h). Per ogni bit richiesto, in ordine dal più significativo, un uno scrive il colore e uno zero lascia invariata la destinazione. Il ciclo si ferma alla larghezza richiesta anche quando l'offset iniziale non è allineato. Il prototipo è separato dalla GUI e non modifica firmware o callback reali.

Nel [banco della routine originale](S33_GUI_Clipping_Riga_Catena_CPU_20261030.md), clipping 4×1 a x=-3 produce larghezza 1 e offset 3; la routine originale scrive 8 byte e tenta il nono oltre la regione sintetica. La nuova prova richiama la stessa catena originale `23AD90 → 23B3F8 → 2C8380 → 2C8170` con gli stessi tipi di fixture e reindirizza il puntatore della routine di riga **solo nella copia laboratorio** a C compilato ARC700:

| Posizione | Risultato prototipo nel buffer sintetico di 8 byte |
|---|---|
| x=-3 | `7e a5 a5 a5 a5 a5 a5 a5`; ritorno senza fault |
| x=0 | `7e 7e 7e 7e a5 a5 a5 a5`; ritorno senza fault |

Le tracce verificano l'ingresso nella catena e nel prototipo; le fixture forniscono colore, dimensioni, buffer e contesto. GNU DSP v7 è sperimentale. [Bordo](../Risultati/GUI_S33/mono_graphics_scanline_prototype_cpu_20261030T101209Z/verified_evidence.json), [controllo interno](../Risultati/GUI_S33/mono_graphics_scanline_prototype_cpu_20261030T101210Z/verified_evidence.json), [banco](../Python_Trace_Scripts/s33_verify_gui_mono_graphics_prototype_cpu.py).

I [test isolati](../AkeruOS/tests/mono_scanline_test.c) passano su host con UBSan e GNU ARC700 per 800 combinazioni: offset 0–15, larghezza 0–24 e colori 0/0x7e su sequenza sintetica mista, con sentinelle prima e dopo l'area e confronto con una stringa di bit attesi. Controllati anche puntatori nulli e offset del campo colore. [Manifest test](../Risultati/GUI_S33/akeru_mono_scanline_20261030T101208Z/verified_evidence.json). Esecuzione: `make -C AkeruOS mono-scanline-verify`.

L'interfaccia non trasporta capacità o durata dei buffer: il chiamante deve garantirle. I casi verificati non dimostrano equivalenza completa con la routine Nikon, presenza del difetto sulla fotocamera, font reale, display, mapping dei tasti o funzionamento del menu. Non è una patch firmware né un candidato installabile: **NON_INSTALLARE**.
