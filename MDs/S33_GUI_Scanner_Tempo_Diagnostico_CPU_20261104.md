# Scanner e schermata diagnostica del tempo — CPU emulata V1.1

Data 2026-11-04. Il banco collega scanner, fan-out, coda, dispatcher `0x169E1C`, finestra diagnostica `0x989CD8`, callback `0x7D22F0`, lookup e handler originali. Una direzione viene seguita dalla conferma `0x580/581`; per ogni evento il banco estrae il record e lo consegna esplicitamente. Il controllo attivo è nullo e la finestra diagnostica è imposta corrente. La tabella originale è verificata: `0x380→0x7D23C8`, `0x400→0x7D241C`, `0x580→0x7D2394`. Le finestre collegate sono confrontate con i payload verificati dopo il link.

**12/12 PASS**, sei scenari × due ordini delle callback:

| Evento | Word iniziale → modificata | Word dopo conferma, in entrambi i campi |
|---|---:|---:|
| `0x380` | 0 → 120 | 120.000 |
| `0x380` | 120 → 121 | 121.000 |
| `0x380` | 3999 → 0 | 0 |
| `0x400` | 0 → 119 | 119.000 |
| `0x400` | 1 → 0 | 0 |
| `0x400` | 2 → 1 | 1.000 |

Dopo la sola modifica le word `0x365788` e `0x37FBF4` conservano entrambe la sentinella `0x12345678`; non è stata ancora richiesta alcuna apertura. La conferma esegue callback e setter originali e scrive la word modificata moltiplicata per 1000 in entrambi i campi; richiede `(0x36,0)` allo stub del manager. Le pressioni e i rilasci `0x380/381`, `0x400/401` e `0x580/581` sono generati dallo scanner e verificati in coda. Questi casi estendono la [prova precedente](S33_GUI_Debug_Tempo_Modifica_Conferma_CPU_20261027.md), che iniettava direttamente gli handler.

La schermata, lo stato iniziale, i gate, RAM, ordine delle callback e servizi sono fixture; formattazione, risorse, testo, refresh, timer e apertura sono stub. Non sono eseguiti rendering, ripetizione del timer, ritorno, AE, sensore, otturatore fisico o salvataggio; eventi logici non identificano i tasti fisici. I numeri e il fattore 1000 sono valori software, **non tempi fisici o unità confermate**. Nessun dispositivo o firmware modificato. **NON_INSTALLARE**.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_key_scanner_time_window_cpu.py`; [evidenze 12/12](../Risultati/GUI_S33/key_scanner_time_window_cpu_20261104T155254522798Z/verified_evidence.json). Regressione scanner colore/mono [8/8](../Risultati/GUI_S33/key_scanner_menu_color_cpu_20261104T155254516248Z/verified_evidence.json).
