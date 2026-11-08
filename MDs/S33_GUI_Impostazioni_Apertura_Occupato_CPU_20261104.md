# Apertura impostazioni e manager occupato — CPU emulata

Il 4 novembre 2026 il [banco di apertura impostazioni](../Python_Trace_Scripts/s33_verify_gui_model_open_settings_cpu.py) è stato esteso con `--busy-matrix`. In due casi parte dal tasto **logico** 78 e dalla coda originale; il banco passa esplicitamente l'evento `0x2700` al modello e traduce l'azione `AKERU_OPEN_SETTINGS` nella chiamata Nikon originale `0x1453E4(0xB7, 1)`.

| Guardia manager sintetica | Risultato chiamata | Descrittore corrente |
|---|---:|---|
| 0 | 1 | `GeneralSetupMenu` `0x99242C` |
| 1 | 0 | Descrittore precedente `0x9802AC` |

Nel caso con guardia 1, il banco la azzera e constata che il descrittore precedente è ancora corrente; poi **inietta un secondo evento `0x2700` direttamente nel modello** e richiama esplicitamente il manager sulla nuova richiesta. In quel momento la chiamata ritorna 1 e il descrittore diventa `0x99242C`. Entrambi i casi verificano azione del modello, evento di pressione e rilascio estratti, risultati del manager e stack. [Evidenze 2/2](../Risultati/GUI_S33/model_settings_busy_cpu_20261104T162309Z/verified_evidence.json); regressione originale [1/1](../Risultati/GUI_S33/model_open_settings_cpu_20261104T162309Z/verified_evidence.json). Riproduzione: `python3 Python_Trace_Scripts/s33_verify_gui_model_open_settings_cpu.py --busy-matrix`.

Il secondo evento non attraversa scanner e coda. La prova mostra solo questo ordine sequenziale imposto: non dimostra se uno scheduler reale riprovi o meno. RAM, MMIO, guardia e servizi sono sintetici; il DSP è sperimentale. La finestra corrente non prova visualizzazione, navigazione, ritorno, tasti fisici o persistenza delle impostazioni. Nessuna operazione su hardware, firmware originale o SD. **NON_INSTALLARE**.
