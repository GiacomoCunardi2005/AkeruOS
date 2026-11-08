# S33 V1.1 — instradamento impostazioni e scelte suono

27 ottobre 2026. Analisi **statica** dei byte originali, verificati contro `MainCode.dmp`: le chiamate di apertura sono richieste condizionali, non schermate effettivamente aperte. Le tabelle e i puntatori nell'immagine iniziale non dimostrano stato runtime o associazione ai pulsanti fisici.

- L'handler ImageMode per evento `0x580`, se `0x1457D4` restituisce `0x4800`, richiede `GeneralSetupMenu` (`0xB7`, argomento 1). Questo collegamento era già noto.
- Il dispatcher di `GeneralSetupMenu` associa `0x700` all'handler `0x7EAB18`. Se la word di contesto `0x89A04C` è 2, l'handler richiede `ReviewMenu` (`0x5F`, argomento 3); altrimenti richiede `SoundSettingMenu` (`0xBD`, argomento 0). L'evento `0x2700` richiede `SetupMenu` (`0x78`), con argomento 2 se la word è 2 e altrimenti 1. Il nome `SetupMenu` è un identificativo della tabella, non una prova del contenuto mostrato.
- `SoundSettingMenu` associa `0x700` e `0x2180` a handler separati. Entrambi chiamano il getter `0xD2468`, che legge il byte a `0xC8EC6B`: se questo vale 1 richiedono `SoundOnOffMenu` (`0xC3`), altrimenti `SoundSetting` (`0x93`); passano rispettivamente gli argomenti 1 e 2. Non è dimostrato che quei due argomenti corrispondano a denominazioni specifiche dei suoni.
- Nel solo ramo `SoundOnOffMenu`, gli handler `0x700` e `0x2180` possono scrivere attraverso setter originali `0xCBCC4` e `0xCBD38` nei byte `0xC8EAB7` e `0xC8EAB5`, a seconda della word `0x89A70C` e del getter `0xD2468`. Nel caso getter=1 e word=1, `0x700` scrive 4 nel primo byte e `0x2180` scrive 0; con word=2 scrivono rispettivamente 8 e 0 nel secondo. In altri casi queste scritture possono non avvenire. Gli handler scrivono anche `0xC8EAF0` tramite `0xCE4D4` in condizioni diverse e chiamano il getter `0xCBDF8` seguito da `0x176D64` e dalla richiesta `SoundSettingMenu(0xBD,0)`.

Queste scritture sono in indirizzi del modello software: non dimostrano che l'impostazione venga conservata dopo spegnimento o riavvio, né che `0x176D64` salvi su memoria non volatile. Il percorso di persistenza effettivo e l'eventuale ritorno del valore dopo riapertura rimangono da verificare. Non è dimostrato il contenuto preciso dell'interfaccia, il recapito dell'evento, il suono fisico o la disponibilità della navigazione in un contesto particolare.

## Riproduzione e limiti

```bash
python3 Python_Trace_Scripts/s33_verify_gui_settings_sound_static.py
```

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_settings_sound_static.py), [risultato e hash](../Risultati/GUI_S33/settings_sound_static_20261027T215102Z/verified_evidence.json), [finestre GNU](../Risultati/GUI_S33/settings_sound_static_20261027T215102Z/gnu_verified.txt). La verifica controlla descrittori, tabelle, costanti e istruzioni selezionate; non esegue la CPU o i servizi. Nessuna operazione su fotocamera, NAND o SD; firmware e strumenti GNU invariati. **NON_INSTALLARE**.
