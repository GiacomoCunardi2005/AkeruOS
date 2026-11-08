# GUI — valore del tempo nella chiamata successiva

Il 30 ottobre 2026 il [banco precedente](S33_GUI_Tempo_Trasformazione_Calcolo_CPU_20261030.md) è stato esteso: esegue ora anche `0xFDE08` originale, chiamata da `0xFDA28`, fino a `0xFDF82`. Lì la chiamata a `0x18C99C` incontra una fixture che registra il primo argomento e termina volutamente la prova. Sono quindi eseguiti i setter, la copia, la trasformazione e il prefisso della routine successiva, non `0x18C99C` o il completamento del calcolo.

| Tempo nella copia | Campo signed `+0x0E` | Limite sintetico | Argomento passato a `0x18C99C` |
|---:|---:|---:|---:|
| 42.000 | 0 | 1.000.000 | 42.000 |
| 84.000 | 0 | 1.000.000 | 84.000 |
| 42.000 | 0 | 20.000 | 20.000 |
| 42.000 | 100 | 1.000.000 | 44.941 |

I quattro casi variano un parametro alla volta rispetto alla prima riga. In ogni esecuzione il banco aveva già cambiato il contesto corrente a ISO software 1600 e tempo 121.000 dopo aver copiato il contesto iniziale; questi valori correnti sono verificati nel banco. L'argomento osservato è quello prodotto nel percorso della copia. Il confronto mostra propagazione fino a una chiamata successiva **nelle condizioni sintetiche scelte**, non che il valore sia applicato allo scatto.

La routine originale percorre condizioni interne e una tabella. Per renderle raggiungibili il banco predispone RAM e tabella sintetiche, una callback indiretta che ritorna zero e una fixture che sostituisce `0x18C634` con ritorno zero. Il wrapper `0x128C20` è sostituito con una copia byte per buffer sintetici non sovrapposti; `0x18C99C` è sostituita dal registratore che termina il test. La traccia verifica che le fixture e il percorso originale `0xFDE08 → 0xFDF7C → 0xFDF82` siano stati effettivamente raggiunti. Il modello DSP è sperimentale.

[Verificatore](../Python_Trace_Scripts/s33_probe_gui_exposure_downstream_cpu.py), casi 0–3: [base](../Risultati/GUI_S33/exposure_calc_downstream_probe_0_20261030T101710Z/verified_evidence.json), [tempo doppio](../Risultati/GUI_S33/exposure_calc_downstream_probe_1_20261030T101710Z/verified_evidence.json), [limite](../Risultati/GUI_S33/exposure_calc_downstream_probe_2_20261030T101710Z/verified_evidence.json), [campo +0x0E](../Risultati/GUI_S33/exposure_calc_downstream_probe_3_20261030T101710Z/verified_evidence.json).

Le condizioni effettive di raggiungibilità sulla macchina, l'effetto di `0x18C99C`, le unità fisiche, AE, la GUI, i tasti e lo scatto restano non verificati. Le fixture non descrivono callback o tabelle reali; nessun firmware o dispositivo modificato, **NON_INSTALLARE**.
