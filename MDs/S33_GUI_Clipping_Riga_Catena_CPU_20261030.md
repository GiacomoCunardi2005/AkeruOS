# GUI — clipping e riga a un bit nella stessa catena

Il 30 ottobre 2026 ho eseguito nel simulatore GNU ARC700 il percorso originale `0x23AD90 → 0x23B3F8 → 0x2C8380 → 0x2C8170 → 0x2C8E4C`. Il banco chiama direttamente `0x23AD90` con un descrittore sintetico a un bit 4×1, sorgente `0xFF`, limiti sintetici 320×240 e destinazione di 8 byte. Lookup colore, limiti e servizi di buffer sono fixture; il modello DSP GNU è sperimentale.

| Posizione sintetica | Riga letta dal disegnatore | Risultato nella destinazione |
|---|---|---|
| `x=0` | offset 0, larghezza 4 | Quattro byte `0x7E`, poi quattro sentinelle `0xA5`; ritorno senza fault. |
| `x=-3` | offset 3, larghezza 1 | Otto byte `0x7E`, poi tentativo di scrittura fuori dalla regione e fault atteso. |

Il secondo caso collega **nella stessa esecuzione** il clipping originale e il chiamante di riga, senza impostare a mano la struttura intermedia. La traccia controlla i valori letti da `0x2C8E4C` e i primi cinque store del ramo non allineato. Il PASS del probe indica riproduzione del fault atteso, non sicurezza del percorso. Il controllo positivo verifica un caso interno distinto, non tutti gli altri offset o dimensioni.

[Probe al bordo](../Risultati/GUI_S33/mono_graphics_clipping_fault_cpu_20261030T100840Z/verified_evidence.json), [controllo interno](../Risultati/GUI_S33/mono_graphics_clipping_control_cpu_20261030T100856Z/verified_evidence.json), [banco probe](../Python_Trace_Scripts/s33_probe_gui_mono_graphics_clipping_cpu.py), [banco controllo](../Python_Trace_Scripts/s33_verify_gui_mono_graphics_control_cpu.py). Un test intermedio `mono_clipper_caller_probe_cpu_20261030T100824Z` passa il risultato del clipping al callback direttamente dal banco. Il primo controllo `100852Z` è fallito per un assert del banco che cercava lo store del ramo non allineato, mentre il caso interno usa un'altra istruzione; la ripetizione corregge il controllo.

Il descrittore, i registri grafici software, il colore e la memoria sono sintetici. Non sono dimostrati l'uso di questo formato, le dimensioni effettive dei buffer, il ramo o un overflow sulla fotocamera. Non installare una modifica basata su questa prova; firmware originale e dispositivo invariati, **NON_INSTALLARE**.
