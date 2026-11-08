# Mono RAW — sensibilità ai bit del marcatore candidato

Il 29 ottobre 2026 ho misurato su host l'effetto dei 32 bit candidati del marcatore sull'algoritmo C sperimentale `akeru_mono_raw`. Per ciascuno dei dieci DSCo completi ho calcolato la luminanza due volte: sul file letto e su una copia in memoria con il bit basso **invertito in tutte e 32 le posizioni** `13.263.616 + i × 8.416`. Questa è una perturbazione controllata, non la ricostruzione dei bit originali prima del marcatore.

| DSCo | Pixel mono differenti su 13.263.616 | Massima differenza in unità RAW |
|---|---:|---:|
| 1003 | 16 | 1 |
| 1004 | 19 | 1 |
| 1005 | 13 | 1 |
| 1006 | 15 | 1 |
| 1007 | 16 | 1 |
| 1008 | 24 | 1 |
| 1009 | 19 | 1 |
| 1010 | 12 | 1 |
| 1011 | 19 | 1 |
| 1012 | 18 | 1 |

Tutte le differenze sono a distanza al massimo di un pixel da un campione perturbato, coerentemente con la finestra 3×3 del nucleo. La quantizzazione intera può annullare le differenze; le finestre adiacenti possono sovrapporsi. Questi conteggi non sono un limite dimostrato per ogni possibile combinazione dei 32 bit, per altre immagini o per un JPEG Nikon. La prova non dimostra che il marcatore sia stato effettivamente scritto né quanti bit abbia cambiato.

Il [verificatore](../Python_Trace_Scripts/s33_verify_mono_marker_sensitivity.py) controlla la sequenza osservata, elabora l'intero frame due volte e verifica hash invariati dei RAW e del sorgente C. [Risultati, coordinate e hash](../outputs/mono_marker_sensitivity_20261029T224741Z/report.json). Il riferimento RGGB, i guadagni e i livelli restano ipotesi non calibrate. Nessuna conclusione sulla pipeline JPEG reale, sulla purezza complessiva o sulla sicurezza di intervenire nel buffer condiviso: **NON_INSTALLARE**.
