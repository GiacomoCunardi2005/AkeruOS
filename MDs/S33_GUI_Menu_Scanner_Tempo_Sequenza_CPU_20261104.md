# Menu AkeruOS → tempo diagnostico originale — CPU emulata

Data 2026-11-04, firmware V1.1. Scanner, fan-out, coda e dispatcher originali consegnano al modello C su descrittore sintetico tre pressioni/rilasci logici: `0x580/581` apre la pagina esposizione, `0x2700/2701` passa alla seconda pagina e `0x700/701` produce `OPEN_SHUTTER`. Dopo ogni azione il banco la preleva; per la terza chiama esplicitamente il manager originale `0x1453E4(0x3E,0)`. I record sono estratti e inviati al dispatcher dal banco. Le finestre originali sono confrontate con i payload verificati dopo il link.

## Apertura: 4/4 PASS

Due ordini callback × busy 0/1. Con busy 0 il manager esegue il lifecycle e rende corrente il descrittore originale della schermata diagnostica tempo `0x989CD8`, accodando `0x4409`. Con busy 1 rifiuta e rimane corrente il descrittore sperimentale. La richiesta del modello è stata consumata: non è dimostrata una ripetizione automatica o il ritorno dopo rifiuto.

## Modifica e conferma: 4/4 PASS

Due ordini × due direzioni, busy 0. Il banco estrae e consegna `0x4409` (handler stub), impone controllo attivo nullo e inizializza la word di lavoro a 120. Lo scanner genera un evento direzionale seguito dalla conferma:

| Evento logico | Word di lavoro | Campi dopo conferma |
|---|---:|---:|
| `0x380/381` | 120 → 121 | 121.000 / 121.000 |
| `0x400/401` | 120 → 119 | 119.000 / 119.000 |

I due campi software conservano la sentinella prima della conferma. Il callback tempo e i setter sono originali; la conferma richiede il ritorno ID `0x36`, ma il banco impone count tabella zero e il ritorno non avviene. I valori e il fattore 1000 non provano tempi fisici o unità.

Il descrittore AkeruOS iniziale è imposto corrente, le azioni vengono prelevate e tradotte dal banco, e i record sono consegnati esplicitamente. Controllo, valore iniziale, gate, lock, risorse, formattazione, visualizzazione e timer sono fixture o stub; anche l'handler `0x4409` è stub. Non sono dimostrati ritorno, annullo in questa sequenza, mapping fisico dei pulsanti, esposizione automatica, persistenza o otturatore/sensore. Nessun hardware o firmware originale modificato. **NON_INSTALLARE**.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_key_scanner_menu_time_open_cpu.py` ([4/4](../Risultati/GUI_S33/key_scanner_menu_time_cpu_20261104T155606878875Z/verified_evidence.json)); `python3 Python_Trace_Scripts/s33_verify_key_scanner_menu_time_session_cpu.py` ([4/4](../Risultati/GUI_S33/key_scanner_menu_time_cpu_20261104T155606893895Z/verified_evidence.json)). Regressione scanner e finestra tempo [12/12](../Risultati/GUI_S33/key_scanner_time_window_cpu_20261104T155606884206Z/verified_evidence.json).
