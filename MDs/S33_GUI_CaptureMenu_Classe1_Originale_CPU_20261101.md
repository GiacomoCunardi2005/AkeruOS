# CaptureMenu: evento iniziale della classe 1 — 2026-11-01

## Risultato

Nel banco GNU ARC700 V1.1 la terza risorsa del CaptureMenu, `0x3ABA38` (classe 1), riceve l'evento `0x4401` tramite lookup e wrapper Nikon originali `0x145020` → `0x6333FC` → `0x633430`. La traccia verifica la coppia risorsa/evento prima della chiamata: il callback `0x633430` eseguito nel ramo osservato rientra senza operazioni visibili oltre alla gestione del frame. Le risorse `0x9801C0` e `0x980268`, classe `0x15`, continuano a eseguire i loro handler originali.

L'esperimento estende il banco [precedente](S33_GUI_CaptureMenu_Classe15_Inizializzazione_CPU_20261101.md): snapshot MMIO sintetico → normalizzatore e coda originali → estrazione e dispatch espliciti → AutoScene → manager → CaptureMenu con ID 2 originale. Per ognuno degli eventi `0x700` e `0x2180` sono testati apertura consentita e blocco mediante guardia. Con apertura consentita si osserva una chiamata alla classe 1 per caso e due alla classe `0x15`; con guardia attiva non si osserva inizializzazione di queste risorse. La prova verifica parent e stack e confronta le finestre originali rilevanti con `DUMPS/MainCode.dmp`.

Il servizio `0x1286BC` è una fixture e restituisce alternativamente `0` o `0x23`: in entrambi i gruppi i quattro casi passano. Gli stati condivisi di classe `0x15` rimangono quelli documentati nel banco precedente. Il modo `0x46` a monte è anch'esso imposto e distinto dal ritorno di `0x1286BC`.

## Riproduzione

- `python3 Python_Trace_Scripts/s33_verify_snapshot_capture_classes_cpu.py`: 4 PASS, `Risultati/GUI_S33/snapshot_capture_classes_cpu_20261101T100233991983Z/`.
- Stesso comando con `--ui-mode-23`: 4 PASS, `Risultati/GUI_S33/snapshot_capture_classes_cpu_20261101T100231391023Z/`.
- Regressione `python3 Python_Trace_Scripts/s33_verify_gui_debug_class_all_original_cpu.py`: 2 inizializzazioni diagnostiche PASS, `Risultati/GUI_S33/debug_class_original_handlers_cpu_20261101T100233Z/`.

I parent iniziali, MMIO, lifecycle AutoScene, servizi di recupero risorsa e visibilità, concorrenza e consegna degli eventi sono in parte modellati o imposti. Il callback vuoto nel percorso eseguito non prova che la classe 1 sia inerte per altri eventi. Non sono dimostrati rendering, tasti fisici, impostazioni, persistenza o comportamento hardware. **NON_INSTALLARE**.
