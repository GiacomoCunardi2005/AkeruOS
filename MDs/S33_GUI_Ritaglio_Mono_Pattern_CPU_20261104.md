# Riga grafica sperimentale con ritaglio e bit misti

Il 4 novembre 2026 il banco GNU ARC700 ripete il percorso grafico sintetico con clipping Nikon originale `0x23AD90 → 0x23B3F8 → 0x2C8380 → 0x2C8170` e routine di riga AkeruOS `akeru_mono_scanline`. Il puntatore alla riga è reindirizzato soltanto nella copia laboratorio; il sorgente ha primo byte `0xA0` (bit `1010`), il descrittore è largo quattro pixel, colore `0x7E` e destinazione inizializzata a `0xA5` per otto byte.

| Posizione x | Primi quattro byte destinazione | Esito |
|---:|---|---|
| −4 | `a5 a5 a5 a5` | Ritaglio completo, routine di riga non chiamata |
| −3 | `a5 a5 a5 a5` | Ultimo bit zero, nessuna scrittura visibile |
| −2 | `7e a5 a5 a5` | Un bit uno seguito da uno zero |
| −1 | `a5 7e a5 a5` | Zero, uno, zero |
| 0 | `7e a5 7e a5` | Intera sequenza `1010` |

**5/5 PASS**: per ciascun caso sono verificati tutti gli otto byte di destinazione, sorgente invariata, ritorno senza fault e punti di esecuzione; per x=−4 è verificato che il prototipo non sia chiamato. [Evidenze x=−4](../Risultati/GUI_S33/mono_graphics_scanline_prototype_cpu_20261104T162103Z/verified_evidence.json), [−3](../Risultati/GUI_S33/mono_graphics_scanline_prototype_cpu_20261104T162104Z/verified_evidence.json), [−2](../Risultati/GUI_S33/mono_graphics_scanline_prototype_cpu_20261104T162106Z/verified_evidence.json), [−1](../Risultati/GUI_S33/mono_graphics_scanline_prototype_cpu_20261104T162107Z/verified_evidence.json), [0](../Risultati/GUI_S33/mono_graphics_scanline_prototype_cpu_20261104T162108Z/verified_evidence.json). Riproduzione: `python3 Python_Trace_Scripts/s33_verify_gui_mono_graphics_prototype_cpu.py -2 0xa0`; il primo argomento varia fra −4 e 0.

Regressione `make -C AkeruOS mono-scanline-verify` PASS: test isolato host/GNU e due casi della catena con sorgente `0xFF`. I test non verificano font o testo reali, altri bordi, né equivalenza completa con Nikon. La routine C non riceve la capacità dei buffer: i chiamanti devono garantirla. Buffer, palette, dimensioni e contesto sono fixture; modello DSP sperimentale. Nessun hardware o display verificato, **NON_INSTALLARE**.
