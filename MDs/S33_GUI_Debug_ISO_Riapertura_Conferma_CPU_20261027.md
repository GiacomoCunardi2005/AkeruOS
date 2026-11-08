# S33 V1.1 — riapertura e conferma ISO in una sequenza CPU

Il 27 ottobre 2026 ho collegato in GNU ARC700 il setter ISO originale `0xD03B8`, l'handler di inizializzazione `0x7D2564` e l'handler di conferma `0x7D25B0` con le loro routine originali di ricerca, selezione, getter e conversione. La lista contiene i 24 record originali verificati rispetto al dump V1.1. Il controllo GUI, conteggio 24 e i chiamanti sono sintetici; sette servizi GUI sono fixture. Non viene simulata navigazione fra inizializzazione e conferma.

| Indice inizialmente imposto | Valore software iniziale | Posizione scelta dal controllo | Indice / valore dopo conferma |
| ---: | ---: | --- | --- |
| 0 | 0 | 1 — Auto | 0 / 0 |
| 6 | 125 | 7 — ISO 125 | 6 / 125 |
| 19 | 1600 | 20 — ISO 1600 | 19 / 1600 |
| 22 | 3200 | 23 — ISO 3200 | 22 / 3200 |
| 23 | 6400 | 0 — Exit | 23 / 6400 |
| 255 | 0 | 0 — Exit | 255 / 0 |

Nei sei casi PASS, se l'indice iniziale non figura nella lista (`23` o `255`), l'inizializzazione richiede e applica la posizione `Exit` nel controllo sintetico. Confermare quella posizione **non richiama il setter**: gli indici e il valore software precedenti rimangono invariati. Pertanto la posizione di fallback non prova che l'ISO sia stato resettato. Il caso `255` e l'indice 23 sono iniettati: non è dimostrato che siano raggiungibili o visualizzati nella fotocamera. In tutti i casi la conferma richiede l'apertura `(0x36,0)` al servizio registratore.

La prova non include la consegna dei tasti, il caricamento del controllo reale, la rappresentazione a schermo, AE, sensore o persistenza allo scatto. Il valore `6400` è una conversione software, non un ISO fisico verificato. Nessuna modifica firmware o operazione su fotocamera/SD; candidati **NON_INSTALLARE**.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_debug_iso_roundtrip_cpu.py), [casi](../Risultati/GUI_S33/debug_iso_roundtrip_cpu_20261027T214810Z/cases.json), [fixture](../Risultati/GUI_S33/debug_iso_roundtrip_cpu_20261027T214810Z/fixture_patches.json), [finestre GNU](../Risultati/GUI_S33/debug_iso_roundtrip_cpu_20261027T214810Z/gnu_windows.txt), [risultato e hash](../Risultati/GUI_S33/debug_iso_roundtrip_cpu_20261027T214810Z/verified_evidence.json).
