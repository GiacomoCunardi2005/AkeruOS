# S33 V1.1 — contesto ISO osservato dopo la transizione

**Data:** 2026-11-01. Nove sequenze GNU ARC700 PASS con manager Nikon originale e servizi in parte sintetici. È un esperimento di laboratorio, non una patch installabile.

Per il solo sito che richiede AutoSceneLiveView (`0x20EA46`), il banco sostituisce otto byte **nella copia di laboratorio** con un osservatore: richiama il manager originale `0x1453E4(0x87,0)`, attende il ritorno e cancella il flag ISO sintetico soltanto se il risultato è 1 **e** il descrittore corrente è `0x783AE8`. Il banco arma il flag prima dell'evento `0x2180` e confronta tre condizioni:

| Condizione sintetica | Ritorno manager / descrittore corrente | Flag dopo richiesta | Conferma ISO successiva |
| --- | --- | --- | --- |
| Lifecycle live view permissivo | 1 / live view `0x783AE8` | 0 | Dopo riapertura ISO imposta, ritorno diagnostico |
| Live view rifiuta `0x4405` | 1 / ISO `0x989FCC` ripristinato | 1 | Conferma imposta torna al modello sintetico |
| Guardia iniziale del manager attiva | 0 / ISO `0x989FCC` | 1 | Dopo rimozione della guardia, conferma imposta torna al modello sintetico |

Il caso centrale dimostra che **il ritorno 1 da solo non prova che il descrittore richiesto sia diventato corrente**: nelle condizioni del banco il manager ripristina ISO e restituisce comunque 1. L'osservazione combinata evita il controesempio della precedente [cancellazione su 4402](S33_GUI_ISO_Guardia_Lifecycle_Fallimento_CPU_20261101.md) per questi casi. Non dimostra però che il descrittore resti corrente in presenza di altri task, né copre tutte le destinazioni, uscite, errori o chiamanti del servizio. Dopo l'uscita riuscita la coda del modello rimane sospesa: la sua riattivazione su un futuro ingresso resta da progettare.

L'osservatore, il flag, il descrittore AkeruOS e il trampoline ISO sono sintetici. Il controllo attivo è nullo, il callback live view è una fixture che in un caso restituisce `-1`, e il banco impone pressione, rilascio, riapertura e conferma. I valori software ISO, i flag, i descrittori e lo stack sono verificati. Non si dimostrano lifecycle fisico, pulsanti, rendering, concorrenza, proprietà RAM, sensore o scatto; gli indirizzi sono soltanto V1.1.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_gui_iso_return_after_transition_cpu.py`; [casi](../Risultati/GUI_S33/iso_return_after_transition_cpu_20261101T094555Z/cases.json), trace, fixture e snapshot nella stessa cartella. Regressioni PASS: controesempio `iso_lifecycle_guard_failure_cpu_20261101T094602Z/` e modello menu host/GNU `akeru_menu_model_20261101T094602Z/`. Il tentativo `...094527Z` è conservato FAIL per un'aspettativa del flag non aggiornata dopo la cancellazione; `...094530Z` per conteggi di chiamate non aggiornati dopo la rimozione di una riapertura. Nessun firmware originale, GNU, fotocamera o SD modificato. **NON_INSTALLARE.**
