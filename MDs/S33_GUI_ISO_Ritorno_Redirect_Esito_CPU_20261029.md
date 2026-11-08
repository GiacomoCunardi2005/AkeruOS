# S33 V1.1 — ritorno ISO con deviazione del WindowManager

Il 29 ottobre 2026 una prova GNU estende la [verifica del consumo dopo transizione](S33_GUI_ISO_Ritorno_Consumo_Dopo_Transizione_CPU_20261029.md). Una fixture sostituisce il callback di lifecycle del CaptureMenu: nel caso aggiunto, quando riceve `0x4403`, risponde con l'ID `0x36`, chiedendo al WindowManager originale di deviare verso `DEBUG MODE MENU`. La risposta è sintetica: non viene attribuita al callback reale.

Il callback ISO originale è eseguito con un trampoline sperimentale nella copia di laboratorio. Con flag sintetico 1 chiede CaptureMenu (`0x02`), e cancella il flag solo se il servizio restituisce 1 **e** il descrittore corrente è effettivamente `0x9802AC`. Nel caso della deviazione:

| Passo | Ritorno del servizio | Descrittore osservato | Flag sintetico |
|---|---:|---|---:|
| Richiesta a CaptureMenu, fixture devia a debug | 1 | `0x987AF8` (debug) | 1 |
| Fixture disattivata dal banco, ISO riaperto e conferma reiniettata | verificato dalla transizione | `0x9802AC` (CaptureMenu) | 0 |

Questo caso dimostra nel modello che **ritorno 1 non implica necessariamente il descrittore richiesto**: cancellare il flag sulla sola base del ritorno avrebbe perso il contesto. Il controllo aggiuntivo del descrittore preserva il flag nel caso sintetico verificato. La seconda apertura e conferma sono esplicitamente imposte dal banco; non è dimostrato che l'utente possa o debba ripeterle sulla macchina.

Sette sequenze **PASS**, 195.442 istruzioni nel modello: il caso di deviazione si aggiunge ai sei casi di normale ritorno, Exit, flag alternativo e guardia; stack e campi ISO sono verificati. [Script](../Python_Trace_Scripts/s33_verify_gui_iso_return_redirect_cpu.py), [casi](../Risultati/GUI_S33/iso_return_redirect_cpu_20261028T233001Z/cases.json), [manifest e traccia](../Risultati/GUI_S33/iso_return_redirect_cpu_20261028T233001Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/iso_return_redirect_cpu_20261028T233001Z/fixture_patches.json).

La prova usa RAM, eventi, flag e stato sintetici, lifecycle CaptureMenu modificato e lifecycle della lista no-op; l'ID 2 è una destinazione di prova, non il nuovo sottomenu. Non copre redirect reali, concorrenza, altre cause di fallimento, risorse, disegno o stato fisico. Il controllo del descrittore da solo non certifica un menu funzionante. Nessuna operazione su fotocamera o SD; firmware originale immutato, **NON_INSTALLARE**.
