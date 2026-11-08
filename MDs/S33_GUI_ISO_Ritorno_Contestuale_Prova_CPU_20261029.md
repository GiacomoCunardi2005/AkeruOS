# S33 V1.1 — ritorno ISO condizionato da contesto sintetico

Il 29 ottobre 2026 ho verificato in laboratorio un'alternativa al [ritorno ISO globale](S33_GUI_Ritorno_ISO_CaptureMenu_Esperimento_CPU_20261029.md). In una copia isolata viene inserito un piccolo trampoline al punto in cui il callback originale `0x7D25B0` chiede l'apertura del menu diagnostico: legge un indicatore sintetico associato al singolo caso. Se vale **1**, chiede `CaptureMenu` (ID 2); se vale **0 o 2**, mantiene `DEBUG MODE MENU` (ID `0x36`). Poi chiama il servizio originale `0x1453E4` e torna al callback. L'indicatore viene impostato direttamente dal banco: non esiste qui un produttore reale collegato all'apertura del menu, né una posizione RAM fisica accertata.

| Scelta ISO iniettata | Indicatore sintetico | Descrittore finale osservato | Stato ISO dopo conferma: diagnostico / indice / valore |
|---|---:|---|---|
| ISO 125 | 0 | `0x987AF8` debug | 6 / 6 / 125 |
| Exit | 0 | `0x987AF8` debug | 88 / 77 / 555 invariati |
| ISO 125 | 1 | `0x9802AC` CaptureMenu | 6 / 6 / 125 |
| Exit | 1 | `0x9802AC` CaptureMenu | 88 / 77 / 555 invariati |
| ISO 125 | 2 | `0x987AF8` debug | 6 / 6 / 125 |

Cinque casi **PASS**, 71.048 istruzioni nel modello; controllo di coda, descrittore iniziale e finale, valori ISO, stack e numero di aperture. Il percorso comprende codice originale della coda, dispatcher, callback ISO e WindowManager; l'evento è consegnato dal banco e la posizione ISO è iniettata. L'uscita contiene codice sostitutivo in una copia di laboratorio: gli 8 byte sostituiti a `0x7D25E6`, la destinazione del trampoline e le altre fixture sono elencati nel manifest. [Verificatore](../Python_Trace_Scripts/s33_verify_gui_iso_return_context_cpu.py), [casi](../Risultati/GUI_S33/iso_return_context_cpu_20261028T232715Z/cases.json), [evidenza](../Risultati/GUI_S33/iso_return_context_cpu_20261028T232715Z/verified_evidence.json), [fixture e modifiche](../Risultati/GUI_S33/iso_return_context_cpu_20261028T232715Z/fixture_patches.json).

Questa è una verifica di principio: il flag non è collegato alla provenienza effettiva, non viene gestito nel ciclo di vita, non è testato con riaperture concorrenti o errori, e la RAM di laboratorio non rappresenta spazio disponibile sulla macchina. I lifecycle di CaptureMenu e della lista sono fixture che ritornano zero; non sono verificati caricamento risorse, disegno e funzionamento della schermata. L'ID 2 serve solo da destinazione originale dimostrativa, non rappresenta il nuovo sottomenu esposizione. Il trampoline cambia istruzioni in una copia ed è un esperimento, **non una patch firmware pronta**.

Non sono coperti tempo, f/, ISO fisico, AE, scatto o tasti fisici. Occorre ancora progettare e verificare il proprietario del contesto, attivazione, cancellazione anche in caso di fallimento e protezione dalla concorrenza, oltre a implementare il menu e i suoi lifecycle. Nessuna operazione su fotocamera o SD; **NON_INSTALLARE**.
