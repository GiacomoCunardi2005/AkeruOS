# GUI — dal campo testo del record agli argomenti grafici

Il 29 ottobre 2026 ho verificato due frammenti originali V1.1 in GNU ARC700, collegati esplicitamente dal banco tramite lo stesso frame sintetico:

1. `0x63200A..0x632012` legge il campo `+12` del record, chiama il lookup originale e salva il puntatore a `fp−40`.
2. Il banco entra successivamente a `0x632540`; il frammento originale legge quel campo in `r4` e chiama `0x186D08`, qui sostituito con una fixture che registra i sette argomenti.

I 14 casi coprono i tre ID originali 26, 64 e 88 e quattro puntatori a stringhe sintetiche `ISO`, `f/`, `Tempo`, `Mono RAW`, per i blocchi lingua italiano e inglese. In tutti il puntatore registrato in `r4` coincide con quello restituito dal lookup, i sei altri argomenti coincidono con i valori sintetici impostati e lo stack è conservato. Le tracce verificano l'esecuzione di entrambi i frammenti per ogni caso. [Casi](../Risultati/GUI_S33/menu_text_record_fragments_cpu_20261029T225240Z/cases.json), [manifest e tracce](../Risultati/GUI_S33/menu_text_record_fragments_cpu_20261029T225240Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/menu_text_record_fragments_cpu_20261029T225240Z/fixture_patches.json), [verificatore](../Python_Trace_Scripts/s33_verify_gui_text_record_fragments_cpu.py).

Il programma **salta il codice intermedio**, imposta direttamente contesto e registri e non esegue il disegnatore originale: verifica il passaggio del puntatore fra frammenti, non che le guardie reali conducano alla chiamata o che il testo sia visualizzato. Blocchi lingua, record, frame e indirizzi sono fixture; i puntatori diretti non sono controllati dal wrapper. Font, clipping, framebuffer, lifetime fisico e hardware restano da verificare. Nessuna modifica al firmware originale o alla fotocamera; **NON_INSTALLARE**.
