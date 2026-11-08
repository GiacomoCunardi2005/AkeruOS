# GUI — ritorno del calcolo e campi del risultato

Il 30 ottobre 2026 ho esteso i [casi di confronto](S33_GUI_Tempo_Copia_e_Confronto_CPU_20261030.md) fino al ritorno delle routine originali `0xFDE08` e `0xFDA28` nel simulatore GNU ARC700 DSP sperimentale. In sei casi, dopo setter e snapshot sintetici, `0xFDA28` ritorna 0 e lo stack è conservato. Il buffer di risultato passato dal banco contiene:

| Tempo trasformato | Seconda word nel confronto | Word a risultato `+52` | Byte a risultato `+80` |
|---:|---:|---:|---:|
| 42.000 | 1 | 42.000 | 1 |
| 84.000 | 1 | 84.000 | 1 |
| 20.000 | 1 | 20.000 | 1 |
| 44.941 | 1 | 44.941 | 1 |
| 42.000 | 42.000 | 42.000 | 0 |
| 42.000 | 50.000 | 42.000 | 0 |

In tutti i casi la halfword a risultato `+64` vale 125, proveniente dallo snapshot, mentre i campi correnti sono stati cambiati dal banco a 1600 e 121.000 dopo lo snapshot. `+52`, `+64`, `+80` sono offset **decimali**. La traccia mostra il byte di confronto scritto da `0xFDE08` a `+44` di una propria struttura locale; successivamente `0xFDA28` lo copia a `+80` del buffer esterno. Analogamente scrive il tempo trasformato a `+52`. Sono buffer software distinti, non registri del sensore.

Un primo tentativo `101903Z` ha eseguito le routine fino al ritorno ma fallito l'assert del banco: controllava erroneamente `+44` del buffer esterno, che è distinto dal `+44` interno. Le istruzioni e il risultato hanno permesso di correggere l'offset a `+80` e aggiungere i controlli su ritorno, stack, tempo e ISO. Sei casi corretti PASS.

[Verificatore](../Python_Trace_Scripts/s33_probe_gui_exposure_full_return_cpu.py), casi 0–5: [base](../Risultati/GUI_S33/exposure_calc_return_attempt_0_20261030T101923Z/verified_evidence.json), [tempo doppio](../Risultati/GUI_S33/exposure_calc_return_attempt_1_20261030T101923Z/verified_evidence.json), [limite](../Risultati/GUI_S33/exposure_calc_return_attempt_2_20261030T101923Z/verified_evidence.json), [campo +0x0E](../Risultati/GUI_S33/exposure_calc_return_attempt_3_20261030T101923Z/verified_evidence.json), [uguaglianza](../Risultati/GUI_S33/exposure_calc_return_attempt_4_20261030T101923Z/verified_evidence.json), [ordine inverso](../Risultati/GUI_S33/exposure_calc_return_attempt_5_20261030T101923Z/verified_evidence.json).

Le due routine originali tornano **con fixture**: `0x128C20` sostituita da copia byte per buffer sintetici, `0x18C634` e callback indiretta con ritorni zero. RAM, tabella, limite e ordine chiamate sono sintetici. Non è eseguito il chiamante reale `0xD8CA4`, non è provato l'uso finale di questi campi, l'unità di tempo, AE, sensore, tasti o scatto. Firmware e fotocamera invariati; **NON_INSTALLARE**.
