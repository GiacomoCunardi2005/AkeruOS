# S33 V1.1 — consumo del contesto ISO dopo la transizione

Il 29 ottobre 2026 ho confrontato una variante della [prova precedente](S33_GUI_ISO_Ritorno_Contesto_Consumo_CPU_20261029.md), che cancellava il flag prima dell'apertura e lo perdeva quando il gestore rifiutava la transizione. Nel nuovo banco, una modifica sperimentale alla copia di laboratorio chiede il `CaptureMenu` originale (`ID 2`) se il flag sintetico è 1; **solo dopo la chiamata**, cancella il flag se la chiamata restituisce 1, il descrittore corrente è `0x9802AC` e il flag è ancora 1. Altri valori usano il ritorno diagnostico originale. Questo controlla risultato e destinazione software, non la visualizzazione o l'inizializzazione completa del menu.

| Scelta ISO | Flag iniziale | Prima conferma: descrittore / flag | Secondo evento imposto dal banco | Descrittore / flag finali |
|---|---:|---|---|---|
| 125 o Exit | 0 | debug `0x987AF8` / 0 | riapertura ISO e conferma | debug / 0 |
| 125 o Exit | 1 | CaptureMenu `0x9802AC` / 0 | riapertura ISO e conferma | debug / 0 |
| 125 | 2 | debug / 2 | riapertura ISO e conferma | debug / 2 |
| 125, guardia manager forzata | 1 | ISO `0x989FCC` / 1 | disattiva guardia e riconferma, senza riaprire ISO | CaptureMenu / 0 |

Nel caso di guardia, la prima transizione è rifiutata e il flag rimane 1; alla seconda conferma iniettata, con guardia disattivata dal banco, il gestore raggiunge il descrittore scelto e il flag diventa 0. Questa sequenza evita la perdita osservata nel caso precedente. Non prova però che nella macchina reale il tasto venga riaccettato, che non intervengano altre attività, o che ogni successo/errore del manager sia coperto. Il valore 2 rimane invariato. ISO 125 produce indice 6 e valore software 125; Exit conserva le sentinelle della prova.

**6 casi PASS, 163.912 istruzioni nel modello**, con assert su stack, descrittori e flag dopo entrambe le conferme. [Script](../Python_Trace_Scripts/s33_verify_gui_iso_return_after_commit_cpu.py), [casi](../Risultati/GUI_S33/iso_return_after_commit_cpu_20261028T232906Z/cases.json), [manifest e traccia](../Risultati/GUI_S33/iso_return_after_commit_cpu_20261028T232906Z/verified_evidence.json), [fixture e modifiche](../Risultati/GUI_S33/iso_return_after_commit_cpu_20261028T232906Z/fixture_patches.json). Il banco esegue WindowManager, callback ISO e diversi tratti originali; la selezione, la guardia, il contesto e la consegna degli eventi sono sintetici. I lifecycle di CaptureMenu e della lista e altri servizi sono fixture; il trampoline modifica solo una copia di laboratorio. La memoria del flag non è provata disponibile o sicura sulla macchina.

La transizione verso CaptureMenu è una destinazione dimostrativa, non il sottomenu esposizione richiesto. Restano da progettare origine e proprietà del flag, sincronizzazione, annullamento, transizioni alternative, failure e cleanup, poi verificare risorse e menu reali. Nessuna prova di tasti fisici, rendering, sensore, AE, scatto o hardware; nessun firmware originale o SD modificato. **NON_INSTALLARE**.
