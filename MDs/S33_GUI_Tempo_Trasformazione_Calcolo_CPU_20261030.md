# ISO e tempo: ramo di trasformazione, prova CPU

Il 30 ottobre 2026 ho esteso il [banco del prefisso `0xFDA28`](S33_GUI_ISO_Tempo_Ingresso_Calcolo_CPU_20261030.md) al ramo in cui i quattro fattori controllati sono tutti nonzero. Il banco chiama i setter originali, copia il contesto, cambia i valori correnti a ISO software 1600 / tempo 121.000 e passa a `0xFDA28` la copia precedente con ISO software 125. Il codice originale esegue la trasformazione e la soglia fino a `0xFDBFA`; una fixture al posto di `0xFDE08` registra l'input e termina l'esecuzione.

| Tempo nella copia | Campo signed `+0x0E` | Limite sintetico | Tempo passato alla fixture |
|---:|---:|---:|---:|
| 42.000 | 0 | 1.000.000 | 42.000 |
| 84.000 | 0 | 1.000.000 | 84.000 |
| 42.000 | 0 | 20.000 | 20.000 |
| 42.000 | 100 | 1.000.000 | 44.941 |

Tutti e quattro i casi verificano i campi passati ISO 125 e byte `+0x21` 1, la correzione argomento 17, la copia, i valori correnti cambiati, la lettura del limite e il passaggio dalle routine originali `0xFCC44`, `0x336364`, `0x335C4C`. Il caso base è confrontato cambiando **un solo parametro per volta**: tempo, limite o campo signed. Questi risultati mostrano che in tale contesto il percorso può trasformare e limitare il valore copiato; non dimostrano una formula generale o una durata in secondi.

Altri ingressi restano fissi e sintetici: modalità 4, byte `+0x21` 1, campo contesto `+0x474` 1, gate `+0x478` 1, tabella `0x43BB68` valore 16, puntatore `0x3663A4` verso una struttura sintetica non nulla, limite a `0x3826A4`. La fixture `0x128C20` copia byte fra buffer sintetici non sovrapposti; `0xFDE08` non esegue il calcolo reale. Il simulatore DSP è sperimentale e il percorso contiene `MULDW`; i numeri ottenuti sono risultati del modello, non misure fisiche.

[Verificatore](../Python_Trace_Scripts/s33_probe_gui_exposure_transform_cpu.py), da invocare con caso 0–3: [base](../Risultati/GUI_S33/exposure_calc_transform_probe_0_20261030T101609Z/verified_evidence.json), [tempo doppio](../Risultati/GUI_S33/exposure_calc_transform_probe_1_20261030T101609Z/verified_evidence.json), [limite](../Risultati/GUI_S33/exposure_calc_transform_probe_2_20261030T101609Z/verified_evidence.json), [campo +0x0E](../Risultati/GUI_S33/exposure_calc_transform_probe_3_20261030T101609Z/verified_evidence.json). Il tentativo iniziale `101543Z` ha restituito zero perché la soglia effettiva letta da `0x3826A4` era zero: la traccia ha permesso di individuare e impostare tale campo, distintamente dalla struttura usata per scegliere la tabella.

Non sono provati il calcolo dopo `0xFDE08`, l'esecuzione da `0xD8CA4`, la scelta reale delle condizioni, la persistenza fino allo scatto, AE, GUI fisica o sensore. Firmware e dispositivo non modificati; **NON_INSTALLARE**.
