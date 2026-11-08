# S33 V1.1 — risoluzione delle risorse di CaptureMenu

Analisi statica offline del 27 ottobre 2026 su payload originale V1.1, con
confronto delle finestre e dei record con `DUMPS/MainCode.dmp`. Gli indirizzi
sono quelli della mappa candidata dei payload. Non è una prova di rendering.

## Selezione grafica

La tabella del dispatcher di classe `0x15` già identificato per CaptureMenu
associa l'evento `0x4409` a `0x6316BC`; questa routine scorre record di passo 28 e, in un suo ciclo,
chiama `0x631F44` se i bit 0 e 2 del campo a `+24` sono entrambi chiari.
Ci sono anche altri rami nel ciclo: questa condizione descrive il percorso
esaminato, non tutte le possibilità di accesso al disegno.

`0x631F44` legge i tre halfword iniziali con segno. Nel ramo verificato a
`0x6322FA`–`0x63241A` sceglie un valore che, se non zero, passa come terzo
argomento a `0x26E3C0` insieme a coordinate calcolate:

| Condizione | Valore scelto |
| --- | --- |
| `0xD0A84` restituisce 4 | `+2`, salvo il caso speciale qui sotto |
| altro risultato e bit 1 a `+24` impostato | `+4` |
| altro risultato e bit 1 a `+24` chiaro | `+0` |
| risultato 4 e `+0` uguale a 606 | costante 607, al posto di `+2` |

Il codice distingue anche la voce indicata dal contesto e calcola altre
coordinate e attributi; la tabella qui sopra riguarda solo la scelta del
valore passato nella chiamata. I flag sono modificabili a runtime; quelli
del payload sono valori iniziali, non una previsione dello stato reale.

| Lista | Indice | Record | `+0`, `+2`, `+4` | `+12` | Flag iniziale `+24` |
| --- | ---: | --- | --- | ---: | --- |
| `0x4800` | 0 | `0x98016C` | 606, 606, 606 | 59 | `0x08` |
| `0x4800` | 1 | `0x980188` | 284, 285, 284 | 91 | 0 |
| `0x4800` | 2 | `0x9801A4` | 806, 807, 806 | 92 | 0 |
| `0x4801` | 0 | `0x9801F8` | 606, 606, 606 | 60 | `0x08` |
| `0x4801` | 1 | `0x980214` | 633, 634, 633 | 61 | 0 |
| `0x4801` | 2 | `0x980230` | 413, 414, 413 | 1 | 0 |
| `0x4801` | 3 | `0x98024C` | 222, 223, 222 | 26 | 0 |

`0x26E3C0` passa il numero a `0x23B230`, che salta al lookup
`0x23B20C`. Quest'ultimo usa una tabella di puntatori riferita tramite il
contesto a `0x36A5E0` e controlla puntatore e limite a `+4`; in caso di
successo, `0x26E3C0` inoltra il descrittore a `0x26E338`, che può chiamare
`0x23B5C8`. La tabella dipende dallo stato runtime e non è stata ricostruita:
i numeri sono quindi **ID candidati di risorse grafiche**, non immagini
decodificate o etichette visibili dimostrate.

## Percorso separato del campo `+12`

`0x631F44` passa la word `+12` a `0x6337C4` e conserva il risultato. Per
valore zero la funzione restituisce zero; per 1–380 chiama `0x1286C4`; per
valori almeno 381 inoltra il valore ricevuto. Tutti e sette i valori sopra
sono nella fascia 1–380. A seconda delle guardie il risultato può essere
passato come quarto argomento a `0x186D08`.

Se il controllo runtime di `0x1286C4` consente il lookup, questo indicizza
word nella tabella all'indirizzo `0x43E174` e somma il risultato a
`0x43E768`; altrimenti restituisce un indirizzo di fallback dal contesto.
Questi indirizzi non sono coperti dalla mappa statica univoca dei payload
usata dal verificatore. Il percorso è compatibile con risorse testuali ma
non ne dimostra ancora contenuto, lingua, inizializzazione o visualizzazione.

**Seguito:** i [blocchi nel TBM](S33_GUI_CaptureMenu_Testi_Italiani_20261027.md) contengono corrispondenze italiane e inglesi per i sette ID; lingua e caricamento effettivi restano da dimostrare.

## Verifica e limiti

Il [verificatore](../Python_Trace_Scripts/s33_verify_gui_capture_resource_resolution.py)
ha dato PASS per i sette record, i letterali e le finestre GNU confrontati
col dump. [Risultati](../Risultati/GUI_S33/capture_resource_resolution_20261027T175254Z/evidence.json)
e [disassemblaggio](../Risultati/GUI_S33/capture_resource_resolution_20261027T175254Z/disassembly.txt).
È una verifica statica circoscritta; non esegue i rami, non controlla la
tabella di risorse runtime e non prova selezione, stringhe, pixel, avvio o
hardware. Firmware originale e dump non modificati; **NON_INSTALLARE**.
