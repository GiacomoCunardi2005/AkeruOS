# Impostazioni: controllo prima e dopo l'apertura

Il 29 ottobre 2026 ho esteso il [confronto sul controllo attivo](S33_GUI_Impostazioni_Controllo_Attivo_CPU_20261029.md) aggiungendo una terza sequenza: il banco predispone il puntatore al controllo attivo a zero **prima** dell'apertura di `GeneralSetupMenu` e non lo azzera dopo. Il codice originale di apertura, nelle condizioni sintetiche della prova, lascia quel puntatore a zero; l'evento `0x700` consegnato dal banco raggiunge `SoundSettingMenu`.

| Stato predisposto | Controllo osservato dopo apertura | Destinazione dopo `0x700` |
|---|---|---|
| Lista precedente sintetica attiva | stessa lista | `ChangeColorMenu` |
| Lista precedente sintetica attiva; azzeramento dopo apertura | stessa lista prima dell'azzeramento | `SoundSettingMenu` |
| Nessun controllo attivo iniziale | zero, senza azzeramento successivo | `SoundSettingMenu` |

[Tre casi PASS](../Risultati/GUI_S33/settings_initial_control_cpu_20261029T053438Z/verified_evidence.json): verificati puntatore predisposto e osservato, descrittori, contesto impostazioni 1, esiti e stack. I casi sono sequenziali e condividono RAM sintetica; servizi e controlli restano fixture. [Casi](../Risultati/GUI_S33/settings_initial_control_cpu_20261029T053438Z/cases.json), [traccia](../Risultati/GUI_S33/settings_initial_control_cpu_20261029T053438Z/cases.trace), [verificatore](../Python_Trace_Scripts/s33_verify_gui_settings_initial_control_cpu.py).

Questo precisa il risultato precedente: il controllo residuo dipende dallo stato iniziale predisposto in quel banco e non prova che il firmware reale lasci sempre un controllo obsoleto. Non è verificato il ciclo di vita completo del controllo sulla fotocamera, né l'apertura dal nuovo descrittore in un ciclo reale, la visualizzazione, il ritorno o la persistenza delle impostazioni. Nessuna modifica a firmware originale o dispositivo; **NON_INSTALLARE**.
