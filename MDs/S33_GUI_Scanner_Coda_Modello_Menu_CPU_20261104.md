# Scanner e coda originali verso il modello del menu — CPU emulata

Data 2026-11-04. Nel firmware V1.1, il banco genera pressione e rilascio usando scanner, generatore, fan-out delle due callback e inserimento/estrazione della coda originali. Per ciascun record estratto, il banco passa **esplicitamente** l'evento al `akeru_menu_event` del prototipo C `AkeruOS/ui/menu.c`, compilato per ARC700 nello stesso ELF. Le finestre originali sono confrontate con i payload verificati dopo il link; i sorgenti del modello sono identificati da hash nelle evidenze. Il modello è software AkeruOS sperimentale, non parte del firmware originale.

**40/40 casi PASS**: cinque schermate × quattro coppie pressione/rilascio × due ordini delle callback. La tabella descrive il contratto corrente del modello, con associazione logica ipotetica:

| Schermata iniziale | 0x580 | 0x700 | 0x2180 | 0x2700 |
|---|---|---|---|---|
| Principale | schermata esposizione | schermata colore | nessuna azione | richiede impostazioni |
| Esposizione | principale | richiede ISO | richiede apertura | altra pagina esposizione |
| Colore | principale | richiede colore | richiede mono | nessuna azione |
| Altra pagina esposizione | esposizione | richiede tempo | schermata flash | nessuna azione |
| Flash | altra pagina esposizione | richiede flash acceso | richiede flash spento | nessuna azione |

Per ogni caso il test verifica il contenuto dei due record originali estratti, l'azione e la schermata dopo la pressione, la risposta a ciascun evento e azione `NONE` al rilascio. Il flag `0xC9BF8=0`, snapshot, inizializzazione e ordine delle callback sono imposti; lock e segnali sono stub. Si tratta di invocazione diretta del modello dal banco **dopo** estrazione, non di callback originale registrata né di instradamento automatico. Le azioni sono richieste del modello: non dimostrano apertura dei sottomenu, applicazione di ISO/iride/tempo/flash, pipeline monocromatica o rendering.

Le quattro classi logiche e i loro slot sono una convenzione sperimentale, non una identificazione dei tasti fisici. La gestione di focus, proprietà eventi e ritorno tra finestre richiede ulteriori prove; con altri gate le classi possono essere intercettate a monte. Nessuna fotocamera, supporto o firmware installato è stato modificato. **NON_INSTALLARE**.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_key_scanner_menu_model_cpu.py`. [Evidenze 40/40](../Risultati/GUI_S33/key_scanner_menu_model_cpu_20261104T112916056463Z/verified_evidence.json). Regressione setter ISO e soglia: [8/8](../Risultati/GUI_S33/iso_threshold_slice_cpu_20261104T112916036703Z/verified_evidence.json).
