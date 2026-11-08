# GUI — origine e azzeramento dell'indice ISO nel record

Il 30 ottobre 2026 ho sostituito la chiamata diretta di laboratorio a `0xCA654` con una chiamata esplicita al suo chiamante originale `0x65BC60(4)`. Questo costruisce il record locale con `0xCA5DC` e poi invoca `0xCA654`. Il banco inietta prima le conferme diagnostiche ISO/tempo e, dopo il ritorno del chiamante, invoca esplicitamente `0xD8CA4` e osserva il buffer finale. La sequenza è imposta dal banco.

Il getter originale `0x17C3F0` letto da `0xCA5DC` restituisce il byte operativo `0x367BC8`, salvato inizialmente a `record+8`. Tuttavia, nel percorso originale `0x65BC60`, l'istruzione `0x65BCDC` azzera la halfword a `fp-24`, che coincide proprio con **`record+8`** (`record=fp-32`), prima della chiamata a `0xCA654`. La traccia verifica entrambe le scritture.

| Scelta diagnostica | Indice operativo letto dal getter | `record+8` dopo `CA654` | ISO software nel buffer finale |
|---|---:|---:|---:|
| Auto | 0 | 0 | 0 |
| Auto | 19, imposto dal banco dopo la conferma | 0 | 0 |
| ISO 125 | 6 | 6 | 125 |
| ISO 125 | 19, imposto dal banco dopo la conferma | 6 | 125 |

Nei casi con aggiornamento, il banco chiama **artificialmente** `0x17C320(19)` dopo la conferma, cambiando l'indice operativo senza cambiare quello diagnostico. Per Auto l'indice diagnostico zero non sovrascrive il record azzerato; per 125 l'indice diagnostico nonzero 6 lo riscrive. Il campo tempo nel record finale vale 42.000 in tutti i casi; il calcolo finale riceve ISO 0 o 125 rispettivamente. Tutti e quattro i casi PASS, con osservazione del record prima della distruzione dello stack.

Questo chiarisce il limite del [precedente confronto con record indice 19](S33_GUI_ISO_Ripristino_Prima_Calcolo_CPU_20261030.md): quel banco chiamava `CA654` **direttamente** con un record prefabbricato. Non rappresenta il record così come viene preparato dal percorso `65BC60(4)` qui verificato. Non è una contraddizione: altri chiamanti, altri record, ordine reale o concorrenza possono differire.

[Verificatore](../Python_Trace_Scripts/s33_probe_gui_iso_wrapper_to_calc_cpu.py), [Auto/operativo 0](../Risultati/GUI_S33/gui_iso_wrapper_calc_probe_0_20261030T102645Z/verified_evidence.json), [Auto/operativo 19](../Risultati/GUI_S33/gui_iso_wrapper_calc_probe_1_20261030T102645Z/verified_evidence.json), [125/operativo 6](../Risultati/GUI_S33/gui_iso_wrapper_calc_probe_2_20261030T102645Z/verified_evidence.json), [125/operativo 19](../Risultati/GUI_S33/gui_iso_wrapper_calc_probe_3_20261030T102645Z/verified_evidence.json). Il primo oracolo del caso Auto/19 (`102626Z`) prevedeva erroneamente 1600; la traccia ha mostrato l'azzeramento intermedio e il verificatore finale controlla esplicitamente entrambe le scritture.

Il getter ISO, `CA5DC`, `65BC60`, `CA654` e calcolo sono originali; numerosi altri getter/setter, callback, copia e apertura GUI sono fixture. L'evento e le chiamate sono iniettati, il getter del tempo restituisce 90.000 sintetico, RAM e tabelle sono sintetiche e DSP sperimentale. Non si dimostrano ordine reale, attivazione del wrapper, AE, tasti, sensore o scatto; firmware e dispositivo invariati, **NON_INSTALLARE**.
