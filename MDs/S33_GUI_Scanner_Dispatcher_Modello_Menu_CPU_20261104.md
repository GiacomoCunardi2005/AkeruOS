# Scanner e dispatcher originali verso il modello menu — CPU emulata

Data 2026-11-04, firmware V1.1. **49/49 casi PASS** collegano scanner, generatore, fan-out, post/coda, estrazione, dispatcher e consegna finestra originali (`0x169E1C → 0x16A6E4 → 0x16A028`) a una copia sintetica del descrittore `CaptureMenu` puntata a un callback di laboratorio. Il callback chiama `akeru_menu_defer_event` del modello C compilato per ARC700. Le finestre originali sono confrontate con i payload verificati dopo il link; gli hash del modello sono nelle evidenze.

Il banco impone corrente il descrittore sintetico, senza aprirlo tramite il manager. Il descrittore è copiato da `0x9802AC` in RAM di laboratorio, con callback sostituito e risorse disabilitate. Il banco **estrae i record e invoca esplicitamente il dispatcher**; la consegna dal dispatcher al callback e poi al modello avviene nel codice eseguito. Non è un thread o scheduling runtime autonomo.

## Casi

- **40 casi:** gate `0xC9BF8=0`, cinque schermate × quattro classi × due ordini delle callback. Pressione e rilascio raggiungono il callback; verificati evento, nuova schermata e azione differita. Il rilascio non cancella l'azione pendente. Il modello logico è descritto nella [prova precedente](S33_GUI_Scanner_Coda_Modello_Menu_CPU_20261104.md).
- **8 casi:** gate fixture `0xC9BF8=1`, schermata principale, quattro classi × due ordini. Classi 11 e 14 non generano record consegnati; per 67 e 78 sono consegnati `0x4006`, pressione, `0x4006`, rilascio. Il modello lascia invariata l'azione per le notifiche estranee; classe 78 arriva alla richiesta impostazioni. Ciò dimostra che le quattro pressioni **non sono sempre disponibili** per il menu sotto le condizioni del banco.
- **1 caso:** finestra corrente nulla, nessuna chiamata al callback e stato immutato.

La prova precedente [colore/mono](S33_GUI_Colore_Mono_Callback_C_20261029.md) già collegava coda e dispatcher a callback C in due casi partendo dal generatore; questa prova aggiunge lo scanner, cinque schermate, due ordini e confronto del gate. Le associazioni tra classe logica e posizione restano ipotetiche. RAM, snapshot, ordine, guardie, controllo attivo assente, lock e notifiche sono fixture o stub; non sono provati apertura e ritorno reali, coda concorrente, rendering, pulsanti fisici, applicazione delle impostazioni, persistenza o sensore. Le azioni restano pendenti nel modello e non vengono eseguite. **NON_INSTALLARE.**

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_key_scanner_menu_bridge_cpu.py`. [Evidenze 49/49](../Risultati/GUI_S33/key_scanner_menu_bridge_cpu_20261104T113206114315Z/verified_evidence.json). Regressione passaggio diretto al modello [40/40](../Risultati/GUI_S33/key_scanner_menu_model_cpu_20261104T113134138126Z/verified_evidence.json).
