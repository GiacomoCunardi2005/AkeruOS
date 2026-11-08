# S33 V1.1 — dal menu flash al consumatore, 31 ottobre 2026

Un'unica esecuzione GNU collega la selezione del record originale al valore letto dal consumatore: evento iniettato → wrapper `0x6646C0` e selezione originali → `0xCDE44`/`0xCDC80` → `0xDE3A4` → chiamata al consumatore `0xE27E8` **imposta dal banco** → getter originale `0xDE3E4`. Il banco non riscrive l'oggetto tra selezione e consumatore. Il [manifest](../Risultati/GUI_S33/flash_menu_consumer_cpu_20261031T204128032394Z/verified_evidence.json), la traccia e i casi documentano 18 combinazioni PASS, 9.353 istruzioni, nessun fault e stack preservato.

La matrice combina tre scelte, tre modi forniti da fixture e due valori della word di condizione. Il consumer usa byte di contesto `+0x29=1`, halfword `+0x4C=0`, misura e word locale zero, e flag finale zero, tutti controllati dal banco.

| Modo sintetico | Scelta | Valore letto nell'oggetto | Risultato con condizione 0 / 1 |
|---|---|---:|---|
| `0x2C` o `0x46` | Auto | 4 | 8 / 0 |
| `0x2C` o `0x46` | No flash | 1 | 8 / 8 |
| `0x2C` o `0x46` | Sempre attivo | 8 | 8 / 0 |
| `0x08` | qualunque delle tre | 26 | 8 / 0 |

Per `0x46` la guardia originale è sostituita con una fixture che rende 1; in `0x08` la rilettura 26 non dimostra che quel menu sia utilizzabile nel modo reale. Il banco inietta gli eventi, impone il contesto e richiama il consumatore dopo il ritorno dal menu: scheduler, chiamante reale, persistenza, tasti fisici e scatto non sono verificati. Misura, inizializzazione locale, oggetto della condizione, flag finale, notifica, refresh e apertura sono fixture. I valori 0 e 8 restituiti dal consumatore non sono ancora identificati come comandi fisici. **NON_INSTALLARE**.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_gui_flash_choices_cpu.py --consumer`. Le due modalità preesistenti sono state rieseguite dopo la modifica: [9 casi standard](../Risultati/GUI_S33/flash_choices_cpu_20261031T204130834682Z/verified_evidence.json) e [9 con applicazione originale](../Risultati/GUI_S33/flash_apply_original_cpu_20261031T204130827866Z/verified_evidence.json), entrambe PASS.
