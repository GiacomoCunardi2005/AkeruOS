# S33 — confronto del descrittore recuperato dal lavoro immagini

Il 29 ottobre 2026 ho esteso il [banco RAW/coda](S33_RAW_Coda_Immagini_Descrittore_CPU_20261028.md). Dopo il writer diagnostico simulato, la pubblicazione e il recupero del descrittore, il banco entra direttamente nel confronto originale `0x1E293E..0x1E2950`, inserendo nel contesto il descrittore atteso e uno stato precedente. L'esecuzione viene fermata a `0x1E2952`: non viene eseguito tutto il chiamante né la callback di preparazione completa.

| Condizione sintetica | Stato precedente | Stato dopo confronto |
|---|---:|---:|
| Nodo corrispondente e descrittore atteso uguale, flag RAW 1 o 0 | 0 | 0 |
| Nodo con indirizzo dati diverso, recupero fallito | 0 | `0x700204` |
| Nodo corrispondente, ma descrittore atteso diverso da quello recuperato | 0 | `0x700204` |
| Stessa discrepanza, con stato precedente nonzero | 77 | 77 |

**Cinque casi PASS** nel simulatore GNU ARC700. Il quarto caso è particolarmente rilevante: un nodo compatibile con la tabella e promosso da stato 1 a 2 non basta a superare il confronto se il descrittore del lavoro è un altro. Nel quinto l'errore precedente viene conservato invece di essere sostituito dal codice di discrepanza. Questi esiti riguardano il confronto isolato nelle condizioni impostate, non la propagazione completa dell'errore fino al file o alla GUI.

Il [verificatore](../Python_Trace_Scripts/s33_verify_raw_queue_image_compare_cpu.py) confronta le finestre del firmware col dump; [casi](../Risultati/HiddenMenu_RAW/raw_queue_image_compare_cpu_20261029T224845Z/cases.json), [manifest e traccia](../Risultati/HiddenMenu_RAW/raw_queue_image_compare_cpu_20261029T224845Z/verified_evidence.json), [fixture](../Risultati/HiddenMenu_RAW/raw_queue_image_compare_cpu_20261029T224845Z/fixture_patches.json). Un'esecuzione precedente `224837Z` copriva quattro casi; la prova finale aggiunge lo stato precedente nonzero.

I due frammenti vengono collegati dal banco, che imposta descrittore e stato: coda, lock e writer sono fixture e il buffer immagine non è dereferenziato. Non sono dimostrati scheduler, continuità fisica del frame, input del JPEG, proprietà del buffer, scrittura o hardware. Nessun firmware o dispositivo modificato; **NON_INSTALLARE**.
