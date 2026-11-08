# S33 V1.1 — eventi ISO durante transizioni accettate e bloccate

**Data:** 2026-11-01. Il banco GNU esegue codice originale con descrittori, servizi e stato parzialmente sintetici; non opera sulla fotocamera.

La prova estende il [banco sul contesto obsoleto](S33_GUI_ISO_Contesto_Obsoleto_Uscita_CPU_20261101.md): delimita nella trace la consegna degli eventi e registra i valori effettivamente ricevuti dal wrapper ISO originale `0x7D252C`. Nove sequenze PASS includono una guardia del manager forzata durante il tentativo `0x2180`.

| Sequenza nel banco | Descrittore dopo pressione / conferma | Eventi osservati al wrapper ISO nel tratto delimitato |
| --- | --- | --- |
| Uscita `0x2180` accettata, flag armato | live view `0x783AE8` | `2180`, `4404`, `4406`, `4402` |
| Uscita `0x2180` con guardia forzata | ISO `0x989FCC` | `2180`, `2181` |
| Conferma Exit con ritorno sperimentale | modello sintetico `0x2050000` | `4801`, `4404`, `4406`, `4402` |
| Conferma con guardia forzata | ISO `0x989FCC` | `4801` |
| Conferma dopo ripristino artificiale del descrittore ISO | modello sintetico `0x2050000` | `4801` |

Nel primo e nel secondo caso il flag sintetico era armato prima dell'evento; nel caso bloccato il banco rimuove successivamente la guardia e impone un'altra conferma. Gli eventi `4404/4406/4402` sono candidati da studiare per il ciclo di vita, ma **non sono una prova universale di abbandono o di transizione riuscita**. In particolare, l'ultima riga usa un contesto artificialmente ripristinato dopo live view e mostra che il solo confronto col descrittore non basta a dedurre gli eventi emessi: non dimostra che lo stesso stato si presenti nella camera. Anche la conferma corretta può attraversare gli stessi eventi dell'uscita alternativa, quindi cancellare indiscriminatamente un flag al primo evento osservato potrebbe interferire con il ritorno voluto. L'ordine rispetto al consumo del flag e tutti i casi di errore richiedono ulteriori verifiche.

Il callback live view è una fixture, il controllo attivo viene forzato nullo nella fase dei tasti, e il ritorno AkeruOS usa un trampoline e un descrittore sperimentali in RAM sintetica. Il banco impone gli eventi, la guardia e la riconferma. Le trace non dimostrano scheduler, concorrenza, risorse, display, pulsanti fisici o stato hardware. Nessuna cancellazione automatica viene installata.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_gui_iso_escape_lifecycle_cpu.py`; [eventi durante il tasto](../Risultati/GUI_S33/iso_escape_lifecycle_cpu_20261101T094122Z/modal_lifecycle.json), [eventi durante la conferma](../Risultati/GUI_S33/iso_escape_lifecycle_cpu_20261101T094122Z/confirm_lifecycle.json), casi, trace, fixture, snapshot e hash nella stessa cartella. Regressioni PASS: `iso_escape_context_cpu_20261101T094133Z/` e modello menu host/GNU `akeru_menu_model_20261101T094133Z/`. Il primo tentativo `...094033Z` resta FAIL per un conteggio atteso degli ingressi manager non aggiornato dopo l'aggiunta del caso guardia. Nessun firmware originale, GNU, fotocamera o SD modificati; **NON_INSTALLARE**.
