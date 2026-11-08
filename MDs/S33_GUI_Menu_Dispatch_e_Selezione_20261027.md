# S33 V1.1 — richiesta menu, dispatcher e selezione

27 ottobre 2026. Analisi statica offline dei byte originali: la richiesta
`0x1453E4(2,0)` o `(0x9B,0)` prodotta da CaptureLiveview non è di per sé
una finestra visualizzata. Il wrapper `0x1453E4` chiama `0x14507C`, che
verifica puntatore alla tabella e limiti dell'indice, poi passa il risultato e
il secondo argomento al gestore `0x145180`. Quest'ultimo può rifiutare o
condizionare la transizione secondo descrittore, stato, hook e oggetto corrente.
La tabella originale collega ID 2 a `CaptureMenu` e ID 0x9B a `ImageMode`.

I descrittori puntano ai rispettivi main, che chiamano entrambi il dispatcher
`0x169F60`. Il dispatcher consulta prima una lista terminata da zero di
halfword che può filtrare l'evento, poi cerca nella tabella coppie
`evento/callback`; la coppia con evento zero fornisce il fallback. I dati
iniziali verificati nelle rispettive aree sono `0x0500,0` per CaptureMenu e
`0x0100,0` per ImageMode: **sono RAM iniziale, non stati runtime accertati**.

| Oggetto / evento | Callback | Evidenza statica |
| --- | --- | --- |
| CaptureMenu `0x4401` | `0x7CB020` | Scrive l'argomento ricevuto in `0x899860`. |
| CaptureMenu `0x4405` | `0x7CB03C` | Chiama `0x7CB118`, poi `0x7CB1B4`, servizi ulteriori e `0x145150`. |
| CaptureMenu `0x4406` | `0x7CB0A4` | Chiama servizi durante la chiusura; effetto complessivo non stabilito. |
| CaptureMenu `0x0180` / `0x0480` | `0x7CB0D8` / `0x7CB0F8` | Entrambi inoltrano `0x2180` con argomento zero a `0x20E814`. |
| ImageMode `0x4405` / `0x4406` | `0x7C8CA4` / `0x7C8E5C` | Ingresso e uscita con chiamate a servizi grafici e altri servizi. |
| ImageMode `0x0580` | `0x7C8E90` | Se `0x1457D4` restituisce `0x4800`, chiede `0x1453E4(0xB7,1)`, associato nella tabella originale a `GeneralSetupMenu`; l'altro ramo richiama servizi grafici. |
| ImageMode `0x0700` / `0x2180` | `0x7C8F04` / `0x7C90C4` | Handler distinti con rami in base al valore restituito da `0x1457D4`; semantica completa non ricostruita. |
| ImageMode `0x2700` | `0x7C92DC` | Se `0x1457D4` restituisce `0x4801` o `0x4802`, esegue servizi distinti e chiede `0x1453E4(0x9B,0)`. |
| ImageMode `0x0080` | `0x7C936C` | Inoltra evento e argomento a `0x20E814`. |

L'evento non presente nella tabella locale, se non filtrato, raggiunge il
fallback `0x20E814`; questo invoca lo stesso dispatcher sulla tabella comune
`0x3E8BB4`. Per `0x2180` la tabella comune punta a `0x20E940`, dove diverse
guardie possono impedire il ramo che richiede `0x1453E4(0x87,0)`. Quindi
l'inoltro da `0x0180`/`0x0480` **non prova una transizione incondizionata**.

In CaptureMenu `0x7CB118` usa il valore a `0x899860` per trattare in modo
distinto 4 e 5, passando ID risorsa `0x4800` oppure `0x4801` ai servizi.
`0x7CB1B4` percorre gli elementi del controllo a passo 28 e legge un
**halfword con segno a offset 20**, non l'intera word, nel ramo che confronta
il risultato di `0x1457D4` con `0x4801`. I valori 187 (`0xBB`) e 10
ricevono una condizione dipendente da `0xCAD30` e talvolta `0xCA310` prima
della chiamata `0x631E98` con argomento 1. Nella tabella verificata
`0x9801F8`, tali valori compaiono rispettivamente nei record 3 e 2. Questa
corrispondenza non dimostra che rappresentino direttamente la destinazione
dell'evento o che quegli elementi siano attivi in ogni ingresso.

**Seguito:** la [verifica del controllo di classe 0x15](S33_GUI_CaptureMenu_Destinazioni_20261027.md) collega condizionalmente il campo +20 alla richiesta di apertura; le guardie e lo stato runtime rimangono rilevanti.

## Riproduzione e limiti

```bash
python3 Python_Trace_Scripts/s33_verify_gui_capture_menu_dispatch.py
```

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_capture_menu_dispatch.py),
[risultato PASS e hash](../Risultati/GUI_S33/capture_menu_dispatch_20261027T174835Z/verified_evidence.json),
[disassemblaggio verificato](../Risultati/GUI_S33/capture_menu_dispatch_20261027T174835Z/gnu_verified.txt).
Byte di descrittori, tabelle, pool e finestre di codice confrontati con il
MainCode V1.1; il risultato non esegue il gestore né gli handler. Le evidenze
CPU precedenti si fermavano al registratore della richiesta: non provano
queste transizioni. Registrazione runtime della tabella, lifecycle completo,
risorse grafiche, rendering, coda e input fisico non sono qui verificati.
Nessuna operazione hardware/SD o modifica firmware; candidati NON_INSTALLARE.
