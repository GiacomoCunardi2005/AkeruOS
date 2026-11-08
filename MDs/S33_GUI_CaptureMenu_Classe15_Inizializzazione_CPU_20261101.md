# CaptureMenu: inizializzazione classe 0x15 — 2026-11-01

## Risultato e metodo

Nel banco GNU ARC700 V1.1, con ID 2 originale, l'enumerazione delle risorse di CaptureMenu usa il lookup originale `0x145020` e la tabella originale `0x77F728`. Per le risorse `0x9801C0` e `0x980268` (classe **0x15**, ID rispettivamente `0x4800` e `0x4801`), la consegna di `0x4401` raggiunge il dispatcher originale `0x631610` e l'handler originale `0x631674`. La terza risorsa `0x3ABA38` (classe 1) continua a usare un registratore sintetico; non è stata eseguita la sua implementazione originale.

Il banco riprende la catena snapshot sintetico → normalizzazione e coda originali → dispatch imposto → AutoScene → manager → CaptureMenu. La guardia è esercitata sia aperta sia chiusa per ciascuno degli eventi `0x700` e `0x2180`. La consegna del rilascio è esplicita. Gli stati iniziali dei parent e dei byte osservati sono fissati dal banco; la procedura verifica inoltre le porzioni originali usate contro `DUMPS/MainCode.dmp`.

## Osservazioni

| Ritorno sintetico di `0x1286BC` | Apertura consentita: byte `0x681B6C`, `0x681B6D`, `0x681B74` dopo l'evento | Guardia attiva |
| --- | --- | --- |
| `0` | `0, 0, 0` | Conservati i valori iniziali `A2, A3, A4` |
| `0x23` | `1, 0, 0` | Conservati i valori iniziali `A2, A3, A4` |

In entrambi i casi consentiti la traccia conta due chiamate dell'handler originale di classe 0x15 e una consegna alla fixture di classe 1; con guardia attiva nessuna. I byte osservati sono globali condivisi: la prova non attribuisce un valore indipendente a ciascun controllo. Il valore restituito da `0x1286BC` è imposto, distinto dal modo `0x46` anch'esso imposto nella catena a monte; il suo significato pratico non è stabilito. I casi `0x24` e gli altri valori non sono stati eseguiti.

## Riproduzione ed evidenze

- `python3 Python_Trace_Scripts/s33_verify_snapshot_capture_class15_cpu.py`: 4 casi PASS, `Risultati/GUI_S33/snapshot_capture_class15_cpu_20261101T100130178007Z/`.
- Stesso comando con `--ui-mode-23`: 4 casi PASS, `Risultati/GUI_S33/snapshot_capture_class15_cpu_20261101T100127298698Z/`.
- Regressione `python3 Python_Trace_Scripts/s33_verify_snapshot_capture_resources_cpu.py`: 4 casi PASS, `Risultati/GUI_S33/snapshot_capture_resources_cpu_20261101T100137901444Z/`.

Sono fixture MMIO, scheduler/dispatch, lifecycle AutoScene, classe 1 e diversi servizi di controlli e visibilità. La prova non dimostra costruzione completa o rendering della GUI, mappa dei tasti fisici, effetti su impostazioni o funzionamento hardware. Nessuna installazione: **NON_INSTALLARE**.
