# S33 V1.1 — testi candidati delle liste ImageMode

Analisi statica offline del 27 ottobre 2026. Le tre risorse di classe `0x15`
del descrittore `ImageMode` contengono 11 record con ID a `+12`. Applicando
la geometria del caricatore e del lookup già ricostruita per
[CaptureMenu](S33_GUI_CaptureMenu_Testi_Italiani_20261027.md), i blocchi 1 e
5 del TBM originale danno le seguenti stringhe ASCII terminate da zero.
Sono **candidati condizionali**, non una fotografia dello schermo.

| Risorsa | Indice | Record | ID | Blocco 5, italiano | Blocco 1, inglese |
| --- | ---: | --- | ---: | --- | --- |
| `0x4800` | 0 | `0x9811C4` | 21 | Scegli formato | Choose a size |
| `0x4800` | 1 | `0x9811E0` | 67 | Formato foto | Photo size |
| `0x4800` | 2 | `0x9811FC` | 68 | Formato fotogr. filmato | Movie frame size |
| `0x4801` | 0 | `0x981250` | 67 | Formato foto | Photo size |
| `0x4801` | 1 | `0x98126C` | 265 | Grande (13 megapixel) | Large (13 megapixels) |
| `0x4801` | 2 | `0x981288` | 22 | Medio (4 megapixel) | Medium (4 megapixels) |
| `0x4801` | 3 | `0x9812A4` | 23 | Piccolo (2 megapixel) | Small (2 megapixels) |
| `0x4802` | 0 | `0x9812F8` | 68 | Formato fotogr. filmato | Movie frame size |
| `0x4802` | 1 | `0x981314` | 266 | Grande (1080p) | Large (1080p) |
| `0x4802` | 2 | `0x981330` | 24 | Piccolo (640) | Small (640) |
| `0x4802` | 3 | `0x98134C` | 267 | Piccolo (antico) | Small (old-fashioned) |

La tabella oggetti collega ID `0x9B` al descrittore `0x9814B8`, nome
`ImageMode`, e al vettore di dieci risorse `0x981490`. Fra queste, le tre
risorse riportate hanno classe `0x15`, ID rispettivamente `0x4800`–`0x4802`
e puntano alle tre sequenze di record. Per la `0x4802` la dimensione pagina
iniziale a `+46` è **3**, mentre il numero totale a `+52` è **4**: il quarto
record esiste e non va escluso dall'inventario; questo non prova che sia
visualizzato su una particolare pagina o raggiungibile con un tasto.

Il percorso comune di classe collega condizionalmente l'evento di disegno
`0x4409` a `0x6316BC`, quindi a `0x631F44`, che legge il campo `+12` e lo
passa a `0x6337C4`. Tutti gli ID della tabella sono fra 1 e 380, dunque
il percorso può usare il lookup `0x1286C4`. Il lettore e l'inizializzazione
dei blocchi, il controllo del lookup e il possibile inoltro al servizio di
disegno sono discussi nei rapporti precedenti sulle
[risorse](S33_GUI_CaptureMenu_Risoluzione_Risorse_20261027.md) e sui
[testi](S33_GUI_CaptureMenu_Testi_Italiani_20261027.md).

Il [verificatore](../Python_Trace_Scripts/s33_verify_gui_imagemode_text.py)
ha confrontato descrittore, risorse, record e finestre GNU con il dump V1.1;
ha confrontato per intero i due blocchi con il dump e verificato gli 11 ID,
offset e stringhe. [Risultati e hash](../Risultati/GUI_S33/imagemode_text_20261027T175958Z/evidence.json),
[disassemblaggio](../Risultati/GUI_S33/imagemode_text_20261027T175958Z/disassembly.txt).

La prova dipende dal caricamento del blocco indicato e da un backend che
fornisca i byte confrontati. Registrazione effettiva delle risorse, lingua,
selezione, eventi, rendering e hardware restano non osservati. Nessuna
modifica firmware o operazione hardware/SD; **NON_INSTALLARE**.
