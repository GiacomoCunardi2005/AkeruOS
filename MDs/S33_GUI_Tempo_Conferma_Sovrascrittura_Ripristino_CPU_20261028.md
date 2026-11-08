# GUI V1.1 — conferma, sovrascrittura e ripristino tempo, 28 ottobre 2026

Quattro sequenze GNU ARC700 estendono la [prova di conferma e sovrascrittura](S33_GUI_Tempo_Conferma_e_Sovrascrittura_CPU_20261028.md): dopo la conferma diagnostica `120→121` e il setter concorrente invocato dal banco, il banco chiama anche la routine originale `0xCA654` con un record sintetico. Il campo diagnostico nonzero vale 121.000; il record parte con tempo 90.000, indice tempo 1 e indice ISO 19, mentre l'indice ISO diagnostico è posto a zero.

| Setter dopo conferma | Campo `0x37FBF4` dopo setter | Record tempo dopo `0xCA654` | Campo dopo `0xCA654` |
|---|---:|---:|---:|
| `0x1E1DC4(0)` | 0 | 121.000 | 121.000 |
| `0x1E1DC4(1.000.000)` | 1.000.000 | 121.000 | 121.000 |
| `0x1E1DC4(1.000.001)`, rifiutato | 121.000 | 121.000 | 121.000 |
| `0x17C49C(1)` | 500.000 | 121.000 | 121.000 |

In questo percorso la routine usa la word diagnostica nonzero, aggiorna il record e riscrive il campo operativo. È un recupero osservato nell'ordine imposto dal banco; non prova che `0xCA654` venga eseguita dopo quelle scritture durante uno scatto, né che nessun'altra attività cambi il valore in seguito. La condizione diagnostica zero è trattata nella [prova separata](S33_GUI_Ripristino_ISO_Tempo_CPU_20261028.md), non nei quattro casi qui sopra.

PASS: 68.634 istruzioni nel modello, assert sui campi prima e dopo ciascun passaggio, valore nel record, ritorno del setter e stack. [Verificatore](../Python_Trace_Scripts/s33_verify_gui_time_confirm_overwrite_restore_cpu.py), [casi](../Risultati/GUI_S33/time_confirm_overwrite_restore_cpu_20261028T142658Z/cases.json), [manifest e traccia](../Risultati/GUI_S33/time_confirm_overwrite_restore_cpu_20261028T142658Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/time_confirm_overwrite_restore_cpu_20261028T142658Z/fixture_patches.json). Finestre originali confrontate col dump V1.1, DSP GNU v7 sperimentale. Il primo tentativo `20261028T142649Z` è conservato come FAIL: i valori erano corretti ma l'asserzione cercava l'indirizzo della traccia senza lo zero iniziale; il successivo corregge la stringa verificata.

Tasto, eventi e ordine delle chiamate sono sintetici; quattordici servizi di altri campi della routine e i servizi GUI sono fixture. Non sono verificati display, unità del tempo, AE, concorrenza, sensore, persistenza o tasti fisici. Il sottomenu esposizione resta da costruire. **NON_INSTALLARE**.
