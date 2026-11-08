# GUI — scelte ISO e calcolo esposizione

Il 30 ottobre 2026 ho esteso il [banco conferme e calcolo](S33_GUI_Conferme_ISO_Tempo_Calcolo_CPU_20261030.md) a quattro voci della lista diagnostica originale. Prima della conferma il banco inizializza intenzionalmente l'indice ISO software a 19 e il valore a 1600. Poi inietta l'evento ISO, inietta la conferma tempo con valore di lavoro 42 e chiama esplicitamente `0xD8CA4`; la copia finale è letta dopo il ritorno.

| Voce di lista | Indice / valore software dopo conferma | Chiamate a `0xFDA28` | Tempo / ISO / byte confronto nel buffer finale |
|---|---|---:|---|
| Exit | 19 / 1600 | 1 | 42.000 / 1600 / 1 |
| Auto | 0 / 0 | 2 | 42.000 / 0 / 0 |
| ISO 125 | 6 / 125 | 1 | 42.000 / 125 / 1 |
| ISO 1600 | 19 / 1600 | 1 | 42.000 / 1600 / 1 |

Exit conserva il valore iniziale predisposto dal banco. Nel caso Auto la traccia mostra una seconda chiamata originale a `0xFDA28` dal sito `0xD8F64`; i tre campi controllati dopo il ritorno coincidono con quelli registrati dopo la prima. Ciò non dimostra che l'intero buffer sia invariato o che Auto comporti sempre due chiamate. L'unica differenza imposta fra i quattro casi è la selezione ISO, con contesti, tempo e fixture uguali.

Questa sequenza **non invoca** il ripristino `0xCA654`. Nel [precedente banco di ripristino](S33_GUI_Modello_Richiesta_ISO_Conferma_CPU_20261029.md), il banco lo chiamava esplicitamente dopo Auto con un record sintetico che riportava indice 19: lì il valore software tornava 1600. I risultati descrivono due ordini sintetici diversi e non stabiliscono quale avvenga dopo una selezione reale.

Il primo tentativo Auto `102339Z` ha raggiunto una chiamata indiretta con puntatore zero a `0x3663C0` e si è fermato in un ciclo sintetico a zero. Il banco finale assegna a tale cella una callback fixture che ritorna zero, uguale negli altri tre casi. Anche controllo, apertura GUI, copia byte, `0x18C634` e callback grafica sono fixture; a `0xD8E22` il registratore sostituisce e riproduce il ramo sintetico `r16=0`. Il secondo tentativo Auto `102404Z` è arrivato al ritorno ma ha fatto emergere che l'assert del banco prevedeva erroneamente una sola chiamata: le tracce mostrano due. Il verificatore finale controlla esplicitamente entrambi i conteggi.

[Verificatore](../Python_Trace_Scripts/s33_probe_gui_iso_choices_to_calc_cpu.py): [Exit](../Risultati/GUI_S33/gui_iso_choices_calc_probe_0_20261030T102428Z/verified_evidence.json), [Auto](../Risultati/GUI_S33/gui_iso_choices_calc_probe_1_20261030T102428Z/verified_evidence.json), [125](../Risultati/GUI_S33/gui_iso_choices_calc_probe_2_20261030T102428Z/verified_evidence.json), [1600](../Risultati/GUI_S33/gui_iso_choices_calc_probe_3_20261030T102428Z/verified_evidence.json). DSP, tabelle e RAM sono sperimentali o sintetici; eventi e ordine sono imposti. Nessuna conclusione su sensibilità fisica, AE, tasti o scatto. Firmware e dispositivo invariati; **NON_INSTALLARE**.
