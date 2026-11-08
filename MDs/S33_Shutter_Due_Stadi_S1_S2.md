# S33 — shutter a due stadi: S1 prepara, S2 scatta

Analisi statica del 21 ottobre 2026 sul firmware V1.1. Nessuna esecuzione del firmware, nessun accesso USB o alla fotocamera, nessuna scrittura. Chiude il cerchio fra il [backend di ingresso dei pulsanti](S33_Pulsanti_Hardware_Backend_Ingresso.md), la [catena S2](S33_S2_Stato_CaptureImage.md) e i [marcatori S2](S33_S2_Marcatori_e_PTP_Vendor.md). La macchina osservata resta V1.0: gli indirizzi non sono portabili senza prova.

## Risultato

La tabella eventi di CaptureLiveview (`0x7833EC`, blocco 3, 40 voci) contiene **`0x80 → 0x654FE8`** (S1 premuto), **`0x81 → 0x655B68`** (S1 rilasciato) e `0x100 → 0x654CD4` (S2, già noto). Il tasto logico 1 genera `0x80/0x81` (id `1<<7`), il tasto 2 genera `0x100/0x101`: i due stadi dello shutter arrivano come due tasti distinti sullo stesso oggetto.

Il risultato nuovo: **l'handler S1 premuto prepara il byte di stato `0x681EAF`** che S2 leggerà. La chiamata `0x0CBAF0` a `0x6556F6` (documentata come «secondo chiamante» senza attribuzione) sta dentro l'handler `0x654FE8` dell'evento `0x80`. Il modello a due stadi è quindi:

```text
S1 premuto  (key 1 → evento 0x80 → handler 0x654FE8)
  → 0x0CBAF0 scrive lo stato preparato in 0x681EAF
  → interlock: stati tasti 1/2 via 0x16F920, codice modalità 0xCAD30
  → può riaprire oggetti via 0x1453E4 (es. (1,0) = CaptureLiveview)
S2 premuto  (key 2 → evento 0x100 → handler 0x654CD4)
  → legge 0x681EAF → 0x1453E4(4, stato) = CaptureImage
  → 0x4401 copia lo stato in 0x68200D → 0x4405 → CapMgr 0x1B9EA8   [noto]
S1 rilasciato (key 1 → evento 0x81 → handler 0x655B68)
  → servizi di rilascio/ripresa (0x17083C, 0xCB5B0, 0xDEBF0, 0xCD558…)
```

Statico: l'ordinamento runtime S1-poi-S2 non è eseguito, solo collegato. Avanzamento complessivo invariato: circa 10%.

## 1. La tabella eventi di CaptureLiveview

Prima lettura completa della tabella a `0x7833EC` (blocco 3), voci `{evento(16), handler(32)}` terminate da `(0, 0x20E814)`. Oltre agli eventi già noti (`0x4401→0x652758`, `0x4405→0x652794`, `0x100→0x654CD4`) contiene gli eventi-tasto `tasto<<7`:

| Evento | Tasto logico | Handler |
|---:|---:|---:|
| `0x80/0x81` | 1 (S1) | `0x654FE8 / 0x655B68` |
| `0x180/0x181` | 3 | `0x655F88 / 0x656050` |
| `0x380/0x381`, `0x400/0x401` | 7, 8 | `0x654720`, `0x6549F4` |
| `0x480`, `0x500`, `0x580` | 9, 10, 11 | `0x65440C` |
| `0x700`, `0x780`, `0x880` | 14, 15, 17 | vari |

CaptureLiveview consuma direttamente molti tasti logici; i tasti 9/11 (gate diagnostico) compaiono qui come eventi, senza che il produttore sia ancora noto (punto già aperto nel backend pulsanti).

## 2. Handler S1 premuto 0x654FE8

- a `0x655000` registra il marcatore **`0xB00100` = "S1 event"** via il logger `0x12CAD4`: l'identificazione della famiglia è nel [nome dei marcatori](S33_S2_Marcatori_e_PTP_Vendor.md).
- a `0x655026` richiede `0x158D04(0x2600001, 8, 0, 2000)`: richiesta di lavoro con costante `0x2600001` (pool `0x655378`) e valore 2000; la semantica non è attribuita.
- interlock: `0x16F920(1)` e `0x16F920(2)` (stati dei tasti 1/2: un pieno S2 durante S1 cambia il ramo), `0x17BE18`, poi il codice di modalità `0xCAD30` con rami `0x46` e `0x6C`, servizi `0xD0270`, `0x12F12C`, `0xCF554`, `0x145150`.
- a `0x65515C` chiama `0x1439D4(0x15)`; se `[ctx+0x40] == 0x100` lo azzera e **riapre CaptureLiveview** con `0x1453E4(1, 0)` a `0x655172`.
- a `0x655182..0x655196` inoltra l'evento `0x80` via `0x17BD98(fp-0x21, 0, 0x80, …)`.
- **a `0x6556F6` chiama `0x0CBAF0(getter 0xCA310, 0xCA38C(1), [fp-70], ctx+59)`**: prepara il byte `0x681EAF` secondo i discriminanti già ricostruiti ([stato di CaptureImage](S33_S2_Stato_CaptureImage.md), casi signed 2–9). Il puntatore di uscita è `r13+0x3B` con `r13 = 0x681E74` (pool `0x65537C`), cioè esattamente il byte che l'handler S2 legge a `0x654FBA`.

## 3. Handler S1 rilasciato 0x655B68

Chiama `0x17083C(1)`; se `[ctx+0x40] == 0x100` lo azzera e chiama `0xCB5B0`; se `[ctx+28] == 0` chiama `0x143AFC(0x16)` e `0x143AFC(0x15)` ed esce. Altrimenti `0x17BE18`, azzera `0x681F11`, quindi servizi `0xDEBF0([ctx+128])`, `0x177484`, `0x149DF4`, `0xDECD4([ctx+153])`, `0xCD558(1)`, con casi `0x38/0x39` e `0x657BD8`. Nel pool precedente l'ingresso c'è il letterale **`0xB00105` = "S1 display"** (0x655B5C). Nessuna di queste service è portata all'hardware: il tratto è documentato come struttura, non come comportamento misurato.

## 4. Famiglia marcatori S1/AE/AF

Inventario completo dei letterali allineati `0xB00100..0xB00107` (verificato dallo script):

| Codice | Nome | Siti |
|---|---|---|
| 0xB00100 | S1 event | 7 (blocchi 0,2,4,9) |
| 0xB00101 | AE start | blocco 0, 0xDB4C4 |
| 0xB00102 | AE lock | blocco 0, 0xDB7AC; blocco 12, 0x105EA10 |
| 0xB00103 | AF start | blocco 0, 0xDB4D8 |
| 0xB00104 | AF lock | blocco 0, 0xDB4E0; blocco 9, 0xCCF768 |
| 0xB00105 | S1 display | blocco 2, 0x655B5C e 0x65B004 |
| 0xB00106 | S2 event | 6 (già documentati) |
| 0xB00107 | Expo start | blocco 0, 0x1502F0 e 0x1B7FD0 |

I marcatori AE start/AF start/AF lock stanno nel pool della funzione del blocco 0 intorno a `0xDB470..` (chiamate `0x178640`, `0xD5840/0xD5858`, `0xEA650`, `0x145D1C`, `0xF6F4C`, `0x11D1B4`, `0xE12C4`), che registra un marcatore della famiglia via `0x12CAD4` a `0xDB4A0 (letterale 0xB00104)`. Il servizio AE/AF non è seguito fino all'ottica: resta un confine, non una ricostruzione.

## Limiti e prossimo confine

- Statico V1.1: nessuna esecuzione; l'ordine runtime S1→S2 è un modello di progetto, non un percorso eseguito.
- L'identità fisica dei tasti 1/2 come semi-corsa/piena corsa è inferenziale: nomi dei marcatori e interlock supportano l'attribuzione, ma non c'è misura.
- L'handler S1 premuto è lungo e pieno di rami di modalità: la maggior parte dei servizi (0xD0270, 0xCF554, 0x17BD98, 0x158D04) non è attribuita semanticamente.
- Il servizio AE/AF (blocco 0, 0xDB4xx) non è collegato né all'ottica né all'ingresso S1: è il prossimo confine utile, insieme ai produttori dei tasti 9/11.
- Circa 10% invariato, candidato firmware NON_INSTALLARE, nessuna azione hardware.

## Riproduzione

```bash
python3 Python_Trace_Scripts/s33_trace_shutter_two_stage.py
```

Verifica hash/dimensioni dei 16 blocchi, la tabella eventi completa (40 voci), i pool S1, l'inventario dei marcatori `0xB00100..0xB00107` e conserva **7 finestre radicate GNU ARC700** in [gnu_verified.txt](../Ghidra_Results/ghidra_reports/shutter_two_stage/gnu_verified.txt); il [JSON](../Ghidra_Results/ghidra_reports/shutter_two_stage/verified_evidence.json) registra hash, tabella, modello e limiti. Nessun firmware eseguito.
