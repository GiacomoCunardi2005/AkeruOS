# S33 V1.1 — scelta flash fino all'oggetto, 31 ottobre 2026

La prova precedente terminava con una fixture al posto di `0xDE3A4`. Il verificatore esistente, eseguito con `--apply-original`, percorre ora questa funzione originale e il getter `0xDE3E4`, dopo la selezione dal menu e il setter/getter già analizzati. [Risultati e traccia](../Risultati/GUI_S33/flash_apply_original_cpu_20261031T203932447297Z/verified_evidence.json): nove casi, 3.754 istruzioni, uscita 0, nessun fault. Il verificatore confronta con il dump le finestre usate e controlla gli hash di input a fine prova.

| Scelta originale | Valore record | Modi sintetici 0x2C e 0x46: valore nell'oggetto | Modo sintetico 0x08: valore nell'oggetto |
|---|---:|---:|---:|
| Flash auto | 4 | 4 | 26 |
| No flash | 1 | 1 | 26 |
| Flash sempre attivo | 8 | 8 | 26 |

Per ogni caso il banco inizializza l'oggetto a valori sentinella. La traccia originale mostra `0xDE3A4` ottenere la base da `0xF6F0C`, scrivere il byte basso dell'argomento a offset `+0x1A6` e `+6`, e scrivere `argomento & 0xFFFFFF00` come word a `+0x1AC`. Con i valori osservati quest'ultima diventa zero. Il getter originale legge `+0x1A6`; il banco controlla entrambi i byte, la word, il valore riletto e lo stack. La base `0x37FBD0` è usata in RAM sintetica: la prova non osserva il contenuto della fotocamera.

Il percorso e i record sono descritti nella [prova precedente](S33_GUI_Flash_Scelte_Valori_CPU_20261031.md). Eventi, contesto menu, modi e guardia per `0x46` sono imposti; notifiche, refresh e apertura sono fixture. Il risultato 26 deriva dal getter nella modalità sintetica `0x08`, senza dimostrare che il menu sia disponibile in quella modalità reale. Non sono verificati propagazione successiva, persistenza, scatto, impulso flash o tasti fisici. Non scrivere direttamente questi indirizzi sulla fotocamera: candidati **NON_INSTALLARE**.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_gui_flash_choices_cpu.py --apply-original`.
