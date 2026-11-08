# S33 — comandi diagnostici dei tasti ed eventi GUI

27 ottobre 2026. Studio offline del firmware Nikon S33 V1.1. La ricerca
collega i nomi dei comandi diagnostici ai numeri evento usati nella GUI;
non identifica ancora elettricamente un pulsante fisico.

## Risultato

La tabella compatta `0x9A0D20` contiene 234 definizioni di comandi; i sei
comandi sotto sono stati collegati al dispatcher originale `0x809F78` e alle
routine che inviano due eventi consecutivi a `0x169EB4`:

| Comando | Indice | Evento iniziale | Evento successivo | Tasto logico corrispondente |
| --- | ---: | ---: | ---: | ---: |
| `KeyUp` | 58 | `0x380` | `0x381` | 7 |
| `KeyDown` | 38 | `0x400` | `0x401` | 8 |
| `KeyLeft` | 45 | `0x480` | `0x481` | 9 |
| `KeyRight` | 54 | `0x500` | `0x501` | 10 |
| `KeyOK` | 48 | `0x580` | `0x581` | 11 |
| `KeyMenu` | 46 | `0x700` | `0x701` | 14 |

Per i quattro comandi direzionali il primo evento porta argomento `255` e il
secondo `0`; per `KeyOK` e `KeyMenu` entrambi portano `0`. Per gli input
provati 0 e 1 il risultato è identico. Questi valori sono gli argomenti
inoltrati dai comandi, non una misura dei livelli elettrici dei tasti.

Il collegamento più utile per il progetto è:

```text
record diagnostico KeyMenu, indice 46
  → dispatcher 0x809F78 → routine 0x80BF34
  → richiesta evento 0x700, poi 0x701

CaptureLiveview, tabella eventi 0x7833EC
  → evento 0x700 → handler 0x65426C
  → richiesta CaptureMenu 0x02 oppure ImageMode 0x9B, secondo modalità/guardie
```

Le due parti sono state eseguite in **banchi CPU separati** con fixture;
non abbiamo ancora eseguito la coda e WindowMgr che le collega in tempo reale.
Il nome `KeyMenu` rende plausibile l'associazione del tasto logico 14 a una
funzione Menu, ma il comando diagnostico sintetico non prova quale interruttore
fisico o quale tasto laterale della S33 produca l'evento.

## Verifica riproducibile

[Script](../Python_Trace_Scripts/s33_verify_gui_script_key_events.py),
[risultato](../Risultati/GUI_S33/script_key_events_20261027T113104Z/verified_evidence.json),
[12 scenari](../Risultati/GUI_S33/script_key_events_20261027T113104Z/cases.json),
[finestre GNU](../Risultati/GUI_S33/script_key_events_20261027T113104Z/gnu_verified.txt).

Il verificatore decodifica tutti i 234 record, controlla nome e indice dei sei
comandi e confronta le finestre originali con `MainCode.dmp`. Esegue per ogni
comando il dispatcher originale e il relativo handler, con input 0 e 1:
**12 casi PASS, 2.201 istruzioni, stack conservato**. Il solo servizio
`0x169EB4` è sostituito nella copia di laboratorio con un registratore degli
argomenti; non si esegue la coda eventi. I byte originali e la sostituzione
sono salvati nel JSON di prova.

La prova non avvia il parser dei comandi né dimostra sintassi, disponibilità
di uno script su SD, dispatch fisico, visualizzazione o funzionamento sulla
fotocamera. L'identità fisica dei tasti, il percorso queue/WindowMgr e le
voci delle schermate rimangono oggetto di ricerca.

Precedente: [schermate e prova dell'handler CaptureLiveview](S33_GUI_Ripresa_Tasti_e_Risorse_20261027.md).
Nessuna patch firmware o operazione hardware; candidati NON_INSTALLARE.
