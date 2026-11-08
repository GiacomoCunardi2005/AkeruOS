# Snapshot tasti fino al modello AkeruOS — CPU emulata

Data 2026-11-04, firmware V1.1. Il banco esegue il lettore originale `0x2D62D8` su due halfword di memoria **simulata** a `0xFE70224/228`. Passa esplicitamente il risultato al callback originale `0x1406D0`, che raggiunge l'adattatore `0x16EC38`, il normalizzatore originale `0x16E6E0`, scanner/generatore, fan-out e coda originali. Il banco estrae pressione e rilascio e li consegna esplicitamente al dispatcher originale; un descrittore/callback sintetico li inoltra al modello C. Finestre e pool del codice originale sono confrontati con i payload verificati dopo il link.

**16/16 PASS**: quattro snapshot × schermata principale/esposizione × due ordini callback. Le halfword del banco partono dall'ipotesi `FFFF/FFFF`; per bit 12 e 13 sono abbassate entrambe le sorgenti che il lettore combina con OR. Nessun interruttore fisico è misurato.

| Bit snapshot candidato | Evento pressione/rilascio | Modello: principale | Modello: esposizione |
|---:|---|---|---|
| 12 | `0x580/581` | pagina esposizione | pagina principale |
| 7 | `0x700/701` | pagina colore | richiesta ISO |
| 8 | `0x2180/2181` | nessuna azione | richiesta apertura |
| 13 | `0x2700/2701` | richiesta impostazioni | seconda pagina esposizione |

Il banco verifica snapshot pressione e riposo, due record estratti, consegna al callback, azione e schermata. I valori precedenti del normalizzatore, abilitazioni, guardie, ordine, RAM e descrittore sono fixture; lock, segnale e altri servizi sono stub. Il monitor di input e la registrazione del callback non sono eseguiti. Queste sono associazioni **logiche sperimentali**, non prova dell'identità, ordine o polarità dei quattro tasti fisici, né delle pressioni simultanee o del rendering.

## Limite della scelta f/

Le [specifiche Nikon S33](https://nij.nikon.com/products/lineup/compact/s33/spec.html) descrivono una selezione con filtro ND ad azionamento elettromagnetico, due passi equivalenti a f/3.3 e f/6.6 alla posizione grandangolare. Gli stati software iride 1 e 9 e la relativa richiesta sono stati verificati separatamente sotto fixture ([esiti setter](S33_GUI_Iride_Esiti_Setter_Prova_CPU_20261027.md)); non è dimostrata l'associazione degli stati a quei valori, né l'effetto fisico o l'esito a ogni zoom. Il modello emette solo la richiesta di apertura del sottomenu; non è dimostrato un controllo f/ funzionante sulla camera.

Riproduzione `python3 Python_Trace_Scripts/s33_verify_key_snapshot_menu_bridge_cpu.py`; [evidenze 16/16](../Risultati/GUI_S33/key_snapshot_menu_bridge_cpu_20261104T155945375737Z/verified_evidence.json). Regressione sequenza tempo [4/4](../Risultati/GUI_S33/key_scanner_menu_time_cpu_20261104T155945374020Z/verified_evidence.json). Nessuna operazione su fotocamera, SD o firmware; **NON_INSTALLARE**.
