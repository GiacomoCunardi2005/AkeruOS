# S33 V1.1 — quattro slot su liste originali in CPU emulata

27 ottobre 2026. Un banco GNU ARC700 ha chiamato direttamente i quattro handler originali della classe `0x15` con le liste originali complete di `CaptureMenu` e `ChangeColorMenu`. Sono stati eseguiti **24 casi PASS**, con pagina sintetica 0 o 1, risorsa copiata in un contesto di laboratorio e attributi restituiti dalla fixture uguali a 2. Gli indirizzi e le liste valgono per la mappa candidata V1.1.

| Lista | Geometria originale: dimensione pagina / prefisso / numero voci | Richieste registrate per gli slot 0, 1, 2, 3 a pagina 0 |
| --- | --- | --- |
| CaptureMenu `0x4800` | 3 / 1 / 3 | `(0x87,0)`, `(0x9D,2)`, `(0x9D,3)`, nessuna |
| CaptureMenu `0x4801` | 4 / 0 / 4 | `(0x87,0)`, `(0x07,0)`, `(0x0A,0)`, `(0xBB,0)` |
| ChangeColorMenu `0x4800` | 3 / 1 / 4 | `(0x02,5)`, `(0x06,0)`, `(0x06,1)`, `(0x06,2)` |

Le coppie sono ID e argomento registrati dalla fixture del servizio di apertura `0x1453E4`, non finestre realmente aperte. La lista ChangeColorMenu ha quindi un prefisso iniziale di una voce e dimensione pagina **3**, pur contenendo quattro record. I nomi dei descrittori e i testi candidati sono nei rapporti [CaptureMenu](S33_GUI_CaptureMenu_Destinazioni_20261027.md) e [ChangeColorMenu](S33_GUI_ChangeColorMenu_Voci_20261027.md).

Con pagina **1 forzata**, il primo slot delle liste con prefisso 1 continua a richiedere il record zero; i tre restanti calcolano indici 4, 5, 6 e vengono respinti perché oltre il numero di record. Senza prefisso anche lo slot zero calcola 4 e viene respinto. La pagina 1 è una prova artificiale delle guardie, non una pagina raggiungibile dimostrata per queste liste. Il banco verifica indice passato alla fixture di selezione, conteggio delle chiamate, richiesta di apertura, ritorno e stack.

Le finestre originali degli handler, la tabella eventi, i tre descrittori e i record sono confrontati byte per byte con `DUMPS/MainCode.dmp`. Gli eventi `0x580`, `0x700`, `0x2180`, `0x2700` sono associati staticamente agli handler, che nel banco sono chiamati **direttamente**. Otto servizi sono fixture su copie temporanee, inclusi selezione e apertura. L'istruzione `MULUDW` è eseguita nel modello GNU DSP v7 sperimentale; il modello non dimostra la semantica fisica dell'hardware. Il contesto e la pagina sono sintetici, i flag sono quelli iniziali del payload e possono cambiare a runtime.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_four_slots_original_cpu.py), [casi](../Risultati/GUI_S33/four_slots_original_cpu_20261027T214833Z/cases.json), [fixture](../Risultati/GUI_S33/four_slots_original_cpu_20261027T214833Z/fixture_patches.json), [evidenza e hash](../Risultati/GUI_S33/four_slots_original_cpu_20261027T214833Z/verified_evidence.json), [finestre GNU](../Risultati/GUI_S33/four_slots_original_cpu_20261027T214833Z/gnu_windows.txt). Il primo tentativo `214827Z` è conservato: ha rilevato l'assunzione errata di geometria ChangeColor 4/0, corretta in 3/1 prima della prova PASS.

Non sono provati dispatcher e coda reali, ordine dei tasti fisici, caricamento/lifetime delle risorse, rendering, uso effettivo della pagina o comportamento della fotocamera. Nessuna area RAM fisica è dichiarata libera; firmware e ambiente GNU originali non sono stati modificati. **NON_INSTALLARE**.
