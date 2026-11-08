# S33 — modello del menu flash e scelte originali, 31 ottobre 2026

Il [verificatore](../Python_Trace_Scripts/s33_verify_gui_flash_choices_cpu.py), opzione `--model`, compila il modello C del menu ed esegue in GNU ARC700 una sequenza continua di eventi sintetici: schermata principale → esposizione → seconda pagina → flash → sì/no. Il banco traduce esplicitamente `AKERU_FLASH_ON` nell'evento Nikon `0x2700` e `AKERU_FLASH_OFF` in `0x2180`, poi invoca il wrapper originale `0x6646C0` con un contesto menu sintetico. Questo adattamento esiste **nel banco**, non in un'integrazione installabile.

I [sei casi PASS](../Risultati/GUI_S33/flash_model_bridge_cpu_20261031T204714641323Z/verified_evidence.json) combinano le due azioni con tre modi forniti dal banco:

| Scelta nel modello | Modo sintetico 0x2C o 0x46 | Modo sintetico 0x08 |
|---|---:|---:|
| Flash no | record e oggetto 1 | record 1, oggetto 26 |
| Flash sì | record e oggetto 8 | record 8, oggetto 26 |

Il banco verifica l'azione e la schermata del modello, i byte del contesto Nikon, l'oggetto dopo `0xDE3A4`, getter e stack. In modo `0x46` la guardia è una fixture che ritorna 1. In `0x08` le due scelte non si propagano all'oggetto: non è dimostrato che il menu sia disponibile in quel modo reale. Il banco impone eventi, contesto e modi; apertura, refresh e notifiche sono fixture. Non sono verificati attuazione, scatto, tasti fisici o lifecycle reale.

Dopo la modifica sono passate anche le regressioni [scelte](../Risultati/GUI_S33/flash_choices_cpu_20261031T204718460345Z/verified_evidence.json), [applicazione originale](../Risultati/GUI_S33/flash_apply_original_cpu_20261031T204718486736Z/verified_evidence.json) e [consumatore](../Risultati/GUI_S33/flash_menu_consumer_cpu_20261031T204718458710Z/verified_evidence.json), rispettivamente 9, 9 e 18 casi. **NON_INSTALLARE**.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_gui_flash_choices_cpu.py --model`.
