# GUI esposizione — rami FEE03C0 in CPU, 28 ottobre 2026

Il [banco precedente](S33_GUI_Esposizione_FEB0000_Bit0_CPU_20261028.md) si fermava alla prima lettura di `0x0FEE03C0`. Due nuove continuazioni modellano questa halfword come memoria ordinaria con valori iniziali sintetici `0xA5A0` e `0xA5A1`, mantenendo `0x0FEB0000=0xA5A0`. Il contesto, i servizi e gli altri registri restano quelli del banco precedente.

| Bit 0 iniziale | Percorso CPU osservato in `0x20A2CC` | Esito nel backing | Arresto successivo |
|---|---|---|---|
| 0 (`A5A0`) | seconda lettura, impostazione bit 0, scrittura; azzera bit 4 della word RAM sintetica `0x369694`, inizialmente zero; ritorno `0` | `A5A1` | lettura `0x0FEE04B0` a `0x20A78C`, 13.621 istruzioni |
| 1 (`A5A1`) | salta la scrittura e carica `0x01E03710` nel delay slot prima del ritorno | `A5A1` | stessa lettura, 13.613 istruzioni |

Il chiamante osservato ripristina subito `r0=0` dopo il ritorno; il valore restituito nel secondo ramo non dimostra quindi un effetto sulla GUI in questa sequenza. La traccia della scrittura riporta l'operando esteso `0xFFFFA5A1`; il backing finale contiene `A1 A5`. Il fault successivo avviene ancora nel primo dei quattro casi: **entrambe le prove GUI sono FAIL** e il ritorno al sottomenu non è verificato.

[Script del banco](../Python_Trace_Scripts/s33_verify_gui_exposure_return_fee03c0_cpu.py), [run bit 0](../Risultati/GUI_S33/exposure_return_fee03c0_a5a0_20261028T144136Z/verified_evidence.json), [run bit 1](../Risultati/GUI_S33/exposure_return_fee03c0_a5a1_20261028T144136Z/verified_evidence.json). [Audit](../Python_Trace_Scripts/s33_audit_gui_fee03c0_branches.py) PASS per hash di traccia, seed, snapshot e backing, fault, letture e rami osservati; PASS riguarda l'audit, non la GUI. Gli snapshot e i seed sono conservati nei run; mapfile finali non sono necessariamente immagini iniziali.

I valori e le reazioni MMIO sono fixture, non misure o un modello delle periferiche fisiche; DSP v7 e AUX 69 sono sperimentali. Non si dimostrano tasti fisici, visualizzazione, impostazioni dello scatto, persistenza o sicurezza dell'installazione. Analizzare il nuovo accesso prima di scegliere eventuali input per proseguire. **NON_INSTALLARE**.
