# S33 V1.1 — consumo del contesto di ritorno ISO, prova CPU

Il 29 ottobre 2026 ho esteso la [prova contestuale](S33_GUI_ISO_Ritorno_Contestuale_Prova_CPU_20261029.md) con un indicatore sintetico consumato **prima** della richiesta di apertura. Il trampoline sperimentale nella copia di laboratorio tratta soltanto valore 1 come richiesta speciale: lo azzera, poi chiede il `CaptureMenu` originale ID 2. Con altri valori chiede il menu diagnostico originale ID `0x36` senza modificare l'indicatore. Il banco riapre quindi esplicitamente ISO e inietta una seconda conferma, senza reimpostare l'indicatore.

| Primo input | Indicatore iniziale | Dopo prima conferma: descrittore / indicatore | Dopo riapertura e seconda conferma: descrittore / indicatore |
|---|---:|---|---|
| ISO 125 o Exit | 0 | debug `0x987AF8` / 0 | debug `0x987AF8` / 0 |
| ISO 125 o Exit | 1 | CaptureMenu `0x9802AC` / 0 | debug `0x987AF8` / 0 |
| ISO 125 | 2 | debug `0x987AF8` / 2 | debug `0x987AF8` / 2 |
| ISO 125, guardia manager forzata | 1 | ISO `0x989FCC` / 0 | debug `0x987AF8` / 0 |

Nel caso di guardia il banco scrive 1 al byte di guardia del WindowManager prima della prima conferma, quindi lo riporta a zero prima della riapertura esplicita. La prima richiesta viene intercettata dal manager e il descrittore rimane ISO, ma il flag è già stato cancellato. Questo è un **fallimento importante del criterio scelto**: il consumo anticipato evita il riuso nel percorso provato, ma perde la richiesta speciale se la transizione viene rifiutata. La seconda conferma porta al debug, non al ritorno desiderato; non è stata testata una ripetizione spontanea sulla fotocamera. L'indicatore 2 rimane invariato: non interpretare valori diversi da 1 come automaticamente ripuliti.

Sei sequenze **PASS**, 175.113 istruzioni nel modello, assert su ISO 125/Exit, descrittori, flag, riapertura e stack. Il primo tentativo [232759Z](../Risultati/GUI_S33/iso_return_once_cpu_20261028T232759Z/) è conservato FAIL: il secondo ciclo sovrascriveva una cella del registratore di test prima dell'asserzione; la prova corretta salva la prima osservazione separatamente. [Script](../Python_Trace_Scripts/s33_verify_gui_iso_return_once_cpu.py), [casi](../Risultati/GUI_S33/iso_return_once_cpu_20261028T232814Z/cases.json), [manifest/trace](../Risultati/GUI_S33/iso_return_once_cpu_20261028T232814Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/iso_return_once_cpu_20261028T232814Z/fixture_patches.json).

Il flag è in RAM sintetica ed è iniettato dal banco; il trampoline modifica una copia di laboratorio, i lifecycle del menu CaptureMenu e della lista sono fixture no-op, altri servizi e lo stato del manager sono sintetici. Non c'è un nuovo sottomenu né un flag reale, non si prova atomicità o concorrenza, tutte le cause di fallimento, tasti fisici, display, AE o scatto. La scelta del momento di consumo deve considerare successo, fallimento, riapertura e cancellazione senza affidarsi alla sola richiesta. Nessun firmware originale, fotocamera o SD modificato. **NON_INSTALLARE**.
