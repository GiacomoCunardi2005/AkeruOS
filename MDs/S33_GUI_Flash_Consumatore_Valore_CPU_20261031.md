# S33 V1.1 — consumo del valore flash, 31 ottobre 2026

La routine originale `0xE27E8` usa il valore restituito da `0xDE3E4`: nel ramo in cui una word locale è zero, confronta il getter con 1. Se diverso da 1 e il byte di contesto `+0x29` è diverso da 2, consulta una word a `+0x20` di un altro oggetto; se questa è diversa da zero, imposta il risultato intermedio a zero. Le istruzioni originali sono conservate nella [finestra GNU](../Risultati/GUI_S33/flash_consumer_cpu_20261031T204041507740Z/gnu_window.txt). L'interpretazione riguarda il ramo esaminato, non tutte le condizioni della routine.

Il [nuovo banco](../Python_Trace_Scripts/s33_verify_gui_flash_consumer_cpu.py) esegue in sequenza `0xDE3A4` originale, quindi `0xE27E8` originale, che chiama il getter `0xDE3E4` originale. Il banco impone il byte di contesto `+0x29=1`, la halfword con segno `+0x4C=0`, una misura uguale a zero e la word locale uguale a zero. Il servizio della word di condizione e il flag finale sono fixture. Gli otto casi GNU passano, senza fault e con stack preservato: [manifest, traccia e casi](../Risultati/GUI_S33/flash_consumer_cpu_20261031T204041507740Z/verified_evidence.json), 1.146 istruzioni.

| Valore scritto da DE3A4 | Word di condizione fixture | Risultato E27E8 |
|---:|---:|---:|
| 1 | 0 o 1 | 8 |
| 4, 8 o 26 | 0 | 8 |
| 4, 8 o 26 | 1 | 0 |

Il valore 1 corrisponde al record «No flash» nella [prova separata del menu](S33_GUI_Flash_Scelte_Valori_CPU_20261031.md); qui il setter è chiamato dal banco, non dalla GUI. Il risultato numerico non è ancora identificato come comando di accensione o spegnimento. La decompilazione candidata indica una chiamata da `0xF75D4`, ma il suo contesto e il successivo uso del risultato non sono verificati in questa prova. Restano ignoti sequenza reale, misura, significato della word di condizione, scatto e funzionamento hardware. **NON_INSTALLARE**.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_gui_flash_consumer_cpu.py`.
