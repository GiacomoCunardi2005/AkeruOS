# GUI — chiamante originale del calcolo esposizione

Il 30 ottobre 2026 il banco GNU ARC700 DSP sperimentale esegue `0xD8CA4` originale dall'ingresso. Il banco imposta ISO/tempo con i setter Nikon, poi chiama `0xD8CA4` con cinque argomenti sintetici. È il **chiamante originale**, a `0xD8D06`, a invocare `0xF6F54` e creare la copia del contesto; a `0xD8E1E` chiama `0xFDA28` con la copia e un buffer locali. Dopo il ritorno, una fixture a `0xD8E22` legge il buffer locale e termina intenzionalmente l'esecuzione del chiamante.

| Tempo impostato | Campo signed `+0x0E` | Limite sintetico | Seconda word confronto | Tempo nel risultato | ISO nel risultato | Byte confronto |
|---:|---:|---:|---:|---:|---:|---:|
| 42.000 | 0 | 1.000.000 | 1 | 42.000 | 125 | 1 |
| 84.000 | 0 | 1.000.000 | 1 | 84.000 | 125 | 1 |
| 42.000 | 0 | 20.000 | 1 | 20.000 | 125 | 1 |
| 42.000 | 100 | 1.000.000 | 1 | 44.941 | 125 | 1 |
| 42.000 | 0 | 1.000.000 | 42.000 | 42.000 | 125 | 0 |
| 42.000 | 0 | 1.000.000 | 50.000 | 42.000 | 125 | 0 |

La fixture verifica anche che `0xFDA28` sia ritornata 0. Tracce e assert coprono `D8CA4 → F6F54 → FDA28` e il punto successivo alla prima chiamata. Il primo risultato è nel buffer a `fp-200`: tempo `+52`, ISO `+64`, byte confronto `+80`, offset decimali. Non si dimostra che resti tale: il chiamante può chiamare ancora `0xFDA28` e successivamente copiare il buffer, come descritto nell'[analisi statica](S33_GUI_ISO_Soglia_e_Buffer_20261027.md).

Rispetto al banco precedente, non è il test a chiamare direttamente la routine di copia o il calcolo. Restano però sintetici i cinque argomenti iniziali, i contesti, tabelle, limiti e ordine degli eventi; `0x128C20` è una fixture di copia, `0x18C634` e callback indiretta ritornano zero, e il registratore a `0xD8E22` ferma il chiamante prima della sua continuazione. Il risultato è limitato alla prima chiamata, non al ritorno completo di `0xD8CA4`.

[Verificatore](../Python_Trace_Scripts/s33_probe_gui_exposure_caller_cpu.py), casi 0–5: [base](../Risultati/GUI_S33/exposure_caller_probe_0_20261030T102023Z/verified_evidence.json), [tempo doppio](../Risultati/GUI_S33/exposure_caller_probe_1_20261030T102024Z/verified_evidence.json), [limite](../Risultati/GUI_S33/exposure_caller_probe_2_20261030T102023Z/verified_evidence.json), [campo +0x0E](../Risultati/GUI_S33/exposure_caller_probe_3_20261030T102024Z/verified_evidence.json), [uguaglianza](../Risultati/GUI_S33/exposure_caller_probe_4_20261030T102024Z/verified_evidence.json), [ordine inverso](../Risultati/GUI_S33/exposure_caller_probe_5_20261030T102024Z/verified_evidence.json).

Non sono dimostrati ingresso reale nella funzione, persistenza dei risultati, AE, unità fisiche, scatto, sensore o mapping dei tasti. Firmware e fotocamera invariati; **NON_INSTALLARE**.
