# HiddenMenu: mappa, attivazione e navigazione

Verifica statica locale del 19 ottobre 2026. Campione **Nikon S33 V1.1**: 29.602.084 byte, SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`. Indirizzi CPU della mappa candidata dei payload, salvo esplicita indicazione «offset file». Nessun risultato è una prova di esecuzione sulla S33 V1.0 dei log hardware.

Fonti riproducibili: [catalogo strutture](../S33-sections/analysis_codex/evidence/ui_catalog.json), [traccia e modelli locali](../S33-sections/analysis_codex/evidence/hiddenmenu_trace.json), [audit integrità](../S33-sections/analysis_codex/evidence/patch_audit.json). Esecuzione complessiva dalla radice: `python3 S33-sections/analysis_codex/run_analysis.py`, senza `-O`. GNU `-m arc:ARC700 -EL`, payload verificati e conversioni ELF temporanee ricontrollate byte per byte. Le finestre di contesto possono includere pool/tabelle: le righe che li interpretano come istruzioni non costituiscono flusso eseguibile; per i salti di selezione usare le finestre `case_…` riancorate.

## Risultati e confini

La tabella `0x003F5900` contiene **197 indici, uno nullo (0) e 196 descrittori con ID interno coerente**. Il catalogo risolve 192 wrapper di tabella eventi; per `0x01/0x7E/0x87/0xB1` il prefisso limitato non basta. Non significa che questi quattro menu non funzionino. Il grafo elenca collegamenti locali con argomento ID letterale, non una chiusura completa di tutti gli eventi o dei chiamanti esterni.

Correzione terminologica: **`0x1453E4` risolve e apre/attiva un oggetto per ID** (`0x14507C → 0x145180`). **`0x169F60` è il filtro e dispatcher di tabella eventi**. Non sono la stessa operazione.

## Radice e voci visibili

`0x20`: descrittore `0x9827DC`, main `0x7CC6DC`, tabella `0x982808`, tre risorse a partire dall'array `0x9827D0`. Titolo **HIDDEN MENU** a `0x982860`; lista `0x982780`, sette record da32byte a `0x9826A0`.

| Indice / evento | Etichetta letterale | ID aperto | Callback | Chiamata |
|---|---|---|---|---|
| 0 | INFO. MENU | 0x21 | 0x7cc8ac | 0x7cc8c4 |
| 1 | ERROR CODE | 0x25 | 0x7cc8cc | 0x7cc8e4 |
| 2 | CALI. MENU | 0x26 | 0x7cc8ec | 0x7cc904 |
| 3 | IQ DEBUG | 0x35 | 0x7cc90c | 0x7cc924 |
| 4 | DEBUG MODE | 0x36 | 0x7cc92c | 0x7cc944 |
| 5 | NAND TOOL | 0x4a | 0x7cc94c | 0x7cc964 |
| 6 | SKY TOOL | 0x4b | 0x7cc96c | 0x7cc984 |

Gli indici della tabella precedente corrispondono a `0x5000 + indice`. L'evento **`0x0480`** chiama invece `0x7CC88C → 0x1453E4(0x84,0)`: **non è un'ottava voce della lista**. Il descrittore `0x84`, `0x99F218`, contiene il nome interno **ResetCameraConfirmMenu** (`0x99F278`). Non attribuirgli il comportamento di un semplice ritorno o di un browser file.

`0x84/0x2700 → 0x806CD4`: costruzione percorso con suffisso `\HiddenMenu` (`0x99F26C`), sonda attributi `0x12BBB8`, controllo aggiuntivo `0x16F920(8)`, poi apertura `0x20` oppure `0x78`. `0x84/0x2180 → 0x806CA4` chiama `0xC9D84(1,1)`, `0xCBDF8`, `0x177030`, poi apre `0x78`. Il nome interno è verificato; il significato fisico di tutti questi effetti resta aperto. [Finestra riancorata](../S33-sections/analysis_codex/evidence/00806c40_reset_confirm_events.txt).

## Discendenti immediati e sottomenu

### ID `0x21` — INFO. MENU

Descrittore `0x982998`, main `0x7cc98c`; tabella eventi `0x9829c4`.

| Indice | Voce effettiva | ID destinazione dimostrato |
|---|---|---|
| 0 | FW VERSION | 0x22 |
| 1 | TOTAL INFO | 0x23 |
| 2 | SYSDEBUG INFO | 0x24 |

### ID `0x25` — ERROR CODE

Descrittore `0x984128`, main `0x7cd51c`; tabella eventi `0x984154`.

Lista di60 righe con testo inizialmente vuoto, popolato dal codice. Testi statici: `Latest Err Code Idx:` e `<Right>:Dump2File. <REV>:Clear`. Non classificare questa schermata come sola consultazione.

### ID `0x26` — CALIBRATION MENU

Descrittore `0x984580`, main `0x7cdae8`; tabella eventi `0x9845b0`.

| Indice | Voce effettiva | ID destinazione dimostrato |
|---|---|---|
| 0 | BATTERY CALI | 0x27 |
| 1 | IRIS 1 | 0x28 |
| 2 | IRIS 2 | 0x29 |
| 3 | BAD PIXEL | 0x2a |
| 4 | LIVEVIEW ISO | 0x2b |
| 5 | TAKE ISO | 0x2c |
| 6 | TAKE HI ISO | 0x2d |
| 7 | VIDEO ISO | 0x2e |
| 8 | VISTA ISO | 0x2f |
| 9 | COLOR SHADING | 0x30 |
| 10 | CLAMP BLACK OF SET | 0x31 |
| 11 | DLL DISPLAY | 0x32 |
| 12 | DLL ERASE | 0x33 |
| 13 | OIS CALI | 0x34 |

### ID `0x35` — IQDEBUG MENU

Descrittore `0x987000`, main `0x7cf024`; tabella eventi `0x987020`.

| Indice | Voce effettiva | ID destinazione dimostrato |
|---|---|---|
| 0 | ThumFormat | azione / collegamento non risolto |
| 1 | VGAFormat | azione / collegamento non risolto |
| 2 | FullFormat | [Verifica 27 ottobre](S33_HiddenMenu_RAW_Massimo_20261027.md):1=420,2=422,255=None; non profondità RAW |
| 3 | SaveCCDRawOnTake | [Verifica 27 ottobre](S33_HiddenMenu_RAW_Massimo_20261027.md):flag RAM36C26E condiviso con indice12; setter28D498 |
| 4 | SaveCFARawOnIRP | [Verifica 27 ottobre](S33_HiddenMenu_RAW_Massimo_20261027.md):flag RAM366C20 separato; setter13AF20 |
| 5 | SaveThumYRGB | azione / collegamento non risolto |
| 6 | SaveThumJPEG | azione / collegamento non risolto |
| 7 | SaveVGAYRGB | azione / collegamento non risolto |
| 8 | SaveVGAJPEG | azione / collegamento non risolto |
| 9 | SaveFullYRGB | azione / collegamento non risolto |
| 10 | SaveFullJPEG | azione / collegamento non risolto |
| 11 | SaveAEOnS1 | azione / collegamento non risolto |
| 12 | Take12BitCCDRawImage | [Verifica 27 ottobre](S33_HiddenMenu_RAW_Massimo_20261027.md):On→flag36C26E=1,modo366F90=3; export candidato4208x3152x2,non cattura hardware provata |
| 13 | Switch Require formating | [Verifica 20 ottobre](S33_Richiesta_Formattazione_Dopo_HiddenMenu.md):500D→7CF828→backend iniziale DEVNAND1695D0, non semplice interruttore RAM verificato; nessuna esecuzione hardware. |
| 14 | Log Clock Settings | azione / collegamento non risolto |
| 15 | Trigger Self_LED for PERF | azione / collegamento non risolto |
| 16 | Video LiveView | azione / collegamento non risolto |
| 17 | SaveCFAAtVideoLiveview | azione / collegamento non risolto |
| 18 | Fast DPS Error Message | azione / collegamento non risolto |
| 19 | Tune AF LED Current | azione / collegamento non risolto |
| 20 | LiveviewDisplayBatteyAD | azione / collegamento non risolto |

### ID `0x36` — DEBUG MODE MENU

Descrittore `0x987af8`, main `0x7cfb94`; tabella eventi `0x987b24`.

| Indice | Voce effettiva | ID destinazione dimostrato |
|---|---|---|
| 0 | Perf Log | azione / collegamento non risolto |
| 1 | LCD Select | azione / collegamento non risolto |
| 2 | LCD Brightness Adjust | azione / collegamento non risolto |
| 3 | LCD Timeout:ON | azione / collegamento non risolto |
| 4 | LCD Backlight:ON | azione / collegamento non risolto |
| 5 | LCD Smart Display:Disabled | azione / collegamento non risolto |
| 6 | Display ADC | azione / collegamento non risolto |
| 7 | BatGauge Info | azione / collegamento non risolto |
| 8 | BatGauge AutoPowerOff:ON | azione / collegamento non risolto |
| 9 | Temperature Protection:ON | azione / collegamento non risolto |
| 10 | High Temp. Trigger(10 Sec):OFF | azione / collegamento non risolto |
| 11 | High Temp. Trigger(HotKey):OFF | azione / collegamento non risolto |
| 12 | Audio Adjust | azione / collegamento non risolto |
| 13 | Audio Stereo Info | azione / collegamento non risolto |
| 14 | Play Sample.wav | azione / collegamento non risolto |
| 15 | Manual Focus | azione / collegamento non risolto |
| 16 | Exposure Time | azione / collegamento non risolto |
| 17 | ISO | azione / collegamento non risolto |
| 18 | Smart Display Testing | azione / collegamento non risolto |
| 19 | EV | azione / collegamento non risolto |
| 20 | AE Metering | azione / collegamento non risolto |
| 21 | Punch Through:ON | azione / collegamento non risolto |
| 22 | Color Sharding:ON | azione / collegamento non risolto |
| 23 | 10 Sec. Video Length Limit:OFF | azione / collegamento non risolto |
| 24 | Still HW Smear Comp | azione / collegamento non risolto |
| 25 | Video HW Smear Comp | azione / collegamento non risolto |
| 26 | S2S Test:Disabled | azione / collegamento non risolto |
| 27 | HDMI Output Mode | azione / collegamento non risolto |
| 28 | TV Test | azione / collegamento non risolto |
| 29 | Strobe Test | azione / collegamento non risolto |
| 30 | SD HotPlug:Enabled | azione / collegamento non risolto |
| 31 | SD High Speed:Enabled | azione / collegamento non risolto |
| 32 | SD High Speed Clock | azione / collegamento non risolto |
| 33 | SD Clock Current:4XmA | azione / collegamento non risolto |
| 34 | SD Data Current:4XmA | azione / collegamento non risolto |
| 35 | PWM Adjustment | azione / collegamento non risolto |
| 36 | MSDC Card:OFF | case7D02EE → setter138F7C,byte366B9D; [USB MSDC](S33_USB_MSDC_e_Accelerazione_Analisi_OS.md), enumerazione da verificare |
| 37 | NAND Flash BadBlock | azione / collegamento non risolto |
| 38 | Fast Lang Change:OFF | azione / collegamento non risolto |

### ID `0x4a` — NAND TOOL MENU

Descrittore `0x98bb30`, main `0x7d412c`; tabella eventi `0x98bb5c`.

28 voci collegate ai dati originali; tutte le etichette e gli indirizzi dei record sono in [HIDDENMENU_STRINGS.md](HIDDENMENU_STRINGS.md). Casi, chiamate e rischi sono in [FUNCTION_RISK_AUDIT.md](FUNCTION_RISK_AUDIT.md).

### ID `0x4b` — SKY TOOL MENU

Descrittore `0x98c3cc`, main `0x7d498c`; tabella eventi `0x98c408`.

16 voci collegate ai dati originali; tutte le etichette e gli indirizzi dei record sono in [HIDDENMENU_STRINGS.md](HIDDENMENU_STRINGS.md). Casi, chiamate e rischi sono in [FUNCTION_RISK_AUDIT.md](FUNCTION_RISK_AUDIT.md).

## Eventi, aperture e chiusure

`0x169F60`: prima scorre il filtro signed16 fino a0; un evento presente viene assorbito con ritorno0. Altrimenti cerca coppie evento/callback di8byte; evento0 è il default. L'indiretta invoca `(oggetto,evento,dati)`. I filtri non sono una lista di eventi da inoltrare. Tabella/filtri sono distinti dai record delle voci della lista.

`0x145180` verifica descrittore nonzero, bit0 del suo word iniziale e byte manager+39; un bit0 impostato o byte nonzero rifiuta l'apertura. Consulta proprietà e stato corrente, emette eventi di ciclo vita e modifica manager+`0x10/0x14`. I pool `0x145370/378/368/36C` valgono rispettivamente `0x4401/4405/4406/4402`: preparazione e inizializzazione del nuovo oggetto, chiusura/disattivazione in rami dipendenti dai flag. I nomi del ciclo vita sono inferenze dal loro uso. Il percorso può ripristinare l'oggetto precedente o rifiutare l'operazione; una chiamata non prova che sia visibile.

Il dispatcher superiore `0x169D78` può invocare un hook runtime attraverso `*(0x367808)` e interrompere con sentinella `0x55AA5AA5`; la callback effettiva del descrittore viene selezionata nei backend di ciclo vita. Questi hook e `*(0x367810)` nel ponte `0x16A028` rimangono dipendenze runtime. Il ponte chiama `0x14505C`: per i descrittori osservati con bit0=0, carica la main da descrittore+0x0C e la invoca a `0x16A054` con `(oggetto,evento,dati)`. Così le main20/4A/4B sono risolte staticamente quando l'oggetto runtime è il corrispondente descrittore. [Ponte](../S33-sections/analysis_codex/evidence/0016a028_descriptor_main_call.txt).

### Tabelle e filtro ID `0x20`

Filtro a `0x9827fc`: `0x80, 0x100, 0x280, 0x300, 0x580`.

| Evento | Callback | Record |
|---|---|---|
| 0x4401 | 0x7cc714 | 0x982808 |
| 0x440c | 0x7cc7d8 | 0x982810 |
| 0x480 | 0x7cc88c | 0x982818 |
| 0x5000 | 0x7cc8ac | 0x982820 |
| 0x5001 | 0x7cc8cc | 0x982828 |
| 0x5002 | 0x7cc8ec | 0x982830 |
| 0x5003 | 0x7cc90c | 0x982838 |
| 0x5004 | 0x7cc92c | 0x982840 |
| 0x5005 | 0x7cc94c | 0x982848 |
| 0x5006 | 0x7cc96c | 0x982850 |
| 0x0 | 0x20e814 | 0x982858 |

### Tabelle e filtro ID `0x4a`

Filtro a `0x98bb50`: `0x80, 0x100, 0x280, 0x300`.

| Evento | Callback | Record |
|---|---|---|
| 0x4405 | 0x7d417c | 0x98bb5c |
| 0x4406 | 0x7d4330 | 0x98bb64 |
| 0x440c | 0x7d4354 | 0x98bb6c |
| 0x580 | 0x7d4400 | 0x98bb74 |
| 0x480 | 0x7d442c | 0x98bb7c |
| 0x0 | 0x20e814 | 0x98bb84 |

### Tabelle e filtro ID `0x4b`

Filtro a `0x98c3ec`: `0x80, 0x100, 0x200, 0x880, 0x900, 0x280, 0x300, 0x700, 0x500, 0x600, 0x680, 0x780, 0x3301`.

| Evento | Callback | Record |
|---|---|---|
| 0x4405 | 0x7d49dc | 0x98c408 |
| 0x4406 | 0x7d4c5c | 0x98c410 |
| 0x440c | 0x7d4c80 | 0x98c418 |
| 0x580 | 0x7d4d2c | 0x98c420 |
| 0x480 | 0x7d4d58 | 0x98c428 |
| 0x0 | 0x20e814 | 0x98c430 |

### Tabelle e filtro ID `0x84`

Filtro a `0x99f238`: `0x100, 0x300, 0x280, 0x580, 0x700`.

| Evento | Callback | Record |
|---|---|---|
| 0x4405 | 0x806c40 | 0x99f244 |
| 0x4406 | 0x806c90 | 0x99f24c |
| 0x2180 | 0x806ca4 | 0x99f254 |
| 0x2700 | 0x806cd4 | 0x99f25c |
| 0x0 | 0x20e814 | 0x99f264 |

Per `0x4A` e `0x4B`, il main intercetta **`0x5000..0x53FF`** prima del dispatcher e chiama rispettivamente `0x7D444C/0x7D4D94`. Usa soltanto il byte basso dell'indice evento, poi legge il dato a `item+0x14` con `0x635DAC`. Non si deve indicizzare la jump table direttamente con l'indice visibile: NAND salta il dato103 e SKY il dato14. Sono state riancorate tutte le entrate, comprese quelle assenti dalla lista.

La guardia della selezione fuori lista restituisce0. Per NAND ciò esclude la dispatch dei dati100..128; per SKY conduce al caso0. Il modello locale verifica2.048 combinazioni evento/menu sotto precondizione di lista runtime inizializzata e coerente con quella statica. La UI ordinaria potrebbe non emettere quegli eventi.

`0x4A/0x0480` torna direttamente a `0x20`. `0x4B/0x0480` torna a `0x20` solo se la halfword del contesto di provenienza vale `0x20`; altrimenti invia evento `0x4002` con dato `0x16`. `0x0580` modifica un flag di conferma da1 a2 dopo un helper. Non attribuire nomi fisici ai pulsanti da questi numeri: le due indicazioni “Right” e “REV” sono testo originale, non una mappatura completa tastiera→evento. Il default comune `0x20E814` delega alla tabella `0x3E8BB4` e comprende eventi che possono aprire altre schermate; non è una funzione vuota.

## Attivazione della patch

1. Percorso riancorato a `0x135384`; il punto studiato è `0x1353F2 → 0x129920`.
2. Il getter legge il byte `0x366880`: nel payload originale è **1**. Setter `0x129904`, store `0x12990E`; chiamante verificato `0xC5DE8` passa1. È un valore iniziale statico, non un dump RAM dopo boot. Scrittori indiretti/alias e altri cammini di esecuzione non sono esclusi.
3. A `0x1353F6`, byte originali `83 E0`: `cmp_s r0,3`. Patch `81 E0`: confronto con1. `bne_s` a `0x1353F8` salta a `0x135410`.
4. Solo in caso di uguaglianza, `bl.d 0xCDA24` a `0x1353FA` carica nel delay slot `r0 = *(0x1355D4) = 0x38FF2F`, testo **B:\HiddenMenu**.
5. `0xCDA24 → 0x12BBB8 → 0x18B45C → 0x26E6BC`: lookup attributi. Con modalità1 restituisce il bit **0x10** dell'attributo solo se il lookup riesce; fallimento→0. L'interpretazione “directory” è plausibile per convenzione filesystem, non necessaria alla prova del bit. Non basta una generica stringa o qualsiasi file omonimo.
6. Con esito vero: `0x135404` prepara ID20 e `0x135408` chiama `0x1453E4(0x20,0)`. Se il main/framework o il backend non sono pronti, la chiamata non implica apertura riuscita.
7. Altrimenti legge nuovamente lo stato; se è almeno2 controlla **B:\ENABLE_NAND_TOOL**, pool `0x1355D8 → 0x38FF3D`, e può aprire direttamente `0x4A`. È un ingresso alternativo, non una guardia ripetuta nel callback root `0x7CC94C`.

Il modello confronta1.024 combinazioni stato byte / esito delle due sonde per originale e patch. Parte dal confronto, assume il ritorno delle sonde e stato stabile fra letture: non esegue il boot. La patch **sostituisce** lo stato ammesso3 con1; non aggiunge1 lasciando3 ammesso al percorso root.

Impedimenti concreti: stato diverso, lookup fallito o attributo senza bit0x10, percorso/volume non disponibile, codice di avvio non raggiunto o bloccato prima del confronto, tabella UI non registrata, flag/hook/ciclo vita che rifiutano il cambio, risorse non residenti o mutazioni runtime. La lettera B: non è stata dimostrata equivalente alla SD nel ramo studiato.

## Grafica e formato delle risorse

Il word a `resource+4` contiene **ID controllo (halfword bassa) e classe (halfword alta)**. `0x4800/4801/…` non identificano universalmente il tipo: il titolo IQDEBUG ha ID4801/classe7, la sua lista ID4804/classe4. Classe7: testo puntato da+`0x20`; classe4: conteggio byte+`0x20`, pointer record+`0x40`, stride32, testo item+`0x0C`, dato+`0x14`. I campi classe2 a+`0x1C` forniscono altri testi; la decodifica completa di stile/rendering resta aperta.

Titolo root: rettangolo memorizzato `(40,24,600,52)`, espresso in unità UI non dimostrate come pixel fisici. `0x3AB98C` è una risorsa condivisa classe10 collegata al disegno laterale; la lettura come indicatore/scrollbar deriva da dimensioni e uso `0x23D478`. Palette, font, compositing e scaling sul display reale non sono risolti. Stringhe `(ENABLE)/(DISABLE)` sono etichette iniziali sostituite anche con store a `item+0x0C`, non un blocco di sicurezza.

## Collegamenti locali verificati

| Origine | Evento / dato | Callback / case | Chiamata | Destinazione |
|---|---|---|---|---|
| 0x20 | 0x480 | 0x7cc88c | 0x7cc8a4 | 0x84 |
| 0x20 | 0x5000 | 0x7cc8ac | 0x7cc8c4 | 0x21 |
| 0x20 | 0x5001 | 0x7cc8cc | 0x7cc8e4 | 0x25 |
| 0x20 | 0x5002 | 0x7cc8ec | 0x7cc904 | 0x26 |
| 0x20 | 0x5003 | 0x7cc90c | 0x7cc924 | 0x35 |
| 0x20 | 0x5004 | 0x7cc92c | 0x7cc944 | 0x36 |
| 0x20 | 0x5005 | 0x7cc94c | 0x7cc964 | 0x4a |
| 0x20 | 0x5006 | 0x7cc96c | 0x7cc984 | 0x4b |
| 0x84 | 0x2180 | 0x806ca4 | 0x806ccc | 0x78 |
| 0x84 | 0x2700 | 0x806cd4 | 0x806d2e | 0x20 |
| 0x21 | 0x480 | 0x7cc9c4 | 0x7cc9dc | 0x20 |
| 0x21 | 0x5000 | 0x7cc9e4 | 0x7cc9fc | 0x22 |
| 0x21 | 0x5001 | 0x7cca04 | 0x7cca1c | 0x23 |
| 0x21 | 0x5002 | 0x7cca24 | 0x7cca3c | 0x24 |
| 0x25 | 0x480 | 0x7cd764 | 0x7cd77c | 0x20 |
| 0x26 | 0x480 | 0x7cdc98 | 0x7cdcb0 | 0x20 |
| 0x26 | 0x5000 | 0x7cdcb8 | 0x7cdcd0 | 0x27 |
| 0x26 | 0x5001 | 0x7cdcd8 | 0x7cdcf0 | 0x28 |
| 0x26 | 0x5002 | 0x7cdcf8 | 0x7cdd10 | 0x29 |
| 0x26 | 0x5003 | 0x7cdd18 | 0x7cdd30 | 0x2a |
| 0x26 | 0x5004 | 0x7cdd38 | 0x7cdd50 | 0x2b |
| 0x26 | 0x5005 | 0x7cdd58 | 0x7cdd70 | 0x2c |
| 0x26 | 0x5006 | 0x7cdd78 | 0x7cdd90 | 0x2d |
| 0x26 | 0x5007 | 0x7cdd98 | 0x7cddb0 | 0x2e |
| 0x26 | 0x5008 | 0x7cddb8 | 0x7cddd0 | 0x2f |
| 0x26 | 0x5009 | 0x7cddd8 | 0x7cddf0 | 0x30 |
| 0x26 | 0x500a | 0x7cddf8 | 0x7cde10 | 0x31 |
| 0x26 | 0x500b | 0x7cde18 | 0x7cde30 | 0x32 |
| 0x26 | 0x500c | 0x7cde38 | 0x7cde50 | 0x33 |
| 0x26 | 0x500d | 0x7cde58 | 0x7cde70 | 0x34 |
| 0x36 | 0x480 | 0x7cff90 | 0x7cffa8 | 0x20 |
| 0x4a | 0x480 | 0x7d442c | 0x7d4444 | 0x20 |
| 0x4b | 0x480 | 0x7d4d58 | 0x7d4d78 | 0x20 |
| 0x22 | 0x480 | 0x7ccee4 | 0x7ccefc | 0x21 |
| 0x23 | 0x480 | 0x7cd20c | 0x7cd224 | 0x21 |
| 0x24 | 0x480 | 0x7cd3cc | 0x7cd3e4 | 0x21 |
| 0x27 | 0x480 | 0x7cdf90 | 0x7cdfa8 | 0x26 |
| 0x28 | 0x480 | 0x7ce378 | 0x7ce390 | 0x26 |
| 0x29 | 0x480 | 0x7ce778 | 0x7ce790 | 0x26 |
| 0x2a | 0x480 | 0x7ce8e4 | 0x7ce8fc | 0x26 |
| 0x2b | 0x480 | 0x7d663c | 0x7d6654 | 0x26 |
| 0x2c | 0x480 | 0x7d6bf0 | 0x7d6c08 | 0x26 |
| 0x2d | 0x480 | 0x7ceb34 | 0x7ceb4c | 0x26 |
| 0x2e | 0x480 | 0x7d6e3c | 0x7d6e54 | 0x26 |
| 0x2f | 0x480 | 0x7d708c | 0x7d70a4 | 0x26 |
| 0x30 | 0x480 | 0x7ceeb4 | 0x7ceecc | 0x26 |
| 0x31 | 0x480 | 0x7d710c | 0x7d7124 | 0x26 |
| 0x32 | 0x480 | 0x7cef24 | 0x7cef48 | 0x26 |
| 0x33 | 0x480 | 0x7cefd0 | 0x7cefe8 | 0x20 |
| 0x33 | 0x5001 | 0x7cf004 | 0x7cf01c | 0x20 |
| 0x34 | 0x480 | 0x7d7390 | 0x7d73a8 | 0x26 |
| 0x4b | 0x5000 | 0x7d4df8 | 0x7d4e02 | 0x87 |

## Limiti e continuazione

Le52 connessioni sono collegamenti statici locali, non52 funzioni eseguite. Le finestre limitate e le chiamate indirette runtime impediscono una prova di raggiungibilità globale esaustiva. I rami diagnostici non ancora espansi sono segnalati nelle questioni aperte; il catalogo include tutti i197 indici per ulteriori ricerche. Prossimo punto verificabile: sonda attributi e ciclo vita isolati nel simulatore, con storage sostituito da stub che registrano richieste.

# Nuove prove salvate prima dello stop — 19 ottobre 2026

Lavoro sospeso su richiesta dell'utente dopo il salvataggio. Le prove sono statiche sul campione V1.1; nessuna funzione Nikon è stata eseguita e nessun firmware è stato modificato.

## SD Life: scrittura persistente richiesta

La voce SKY con dato0 entra in `0x7D58D8`. A `0x7D5B44` apre un file con modo2 e nome costruito dal formato `%s\Test%d.log` (pool `0x7D5D48 → 0x98CE85`). A `0x7D5B60` chiama la scrittura `0x12DE3C`; a `0x7D5BC8/0x7D5C84` rilegge con `0x12D530`, confronta con `0x32E508` a `0x7D5CAA` e può ripetere dal salto `0x7D5CDE → 0x7D59E8`. Il contatore a `0x899BA4` viene incrementato a `0x7D5CD4`. Classificazione aggiornata: **P, richiesta di scrittura persistente**, con completamento fisico non provato.

La routine usa anche il percorso `A:` e i messaggi `Format card ...` / `Format Err=%X`; chiama `0x21C420` a `0x7D5A12`. Quest'ultima inoltra la richiesta `0x2018` a `0x1F2348`, che chiama indirettamente il campo+0x1C della tabella del dispositivo. L'endpoint runtime di questa richiesta resta da risolvere: la prova di scrittura file non dipende dall'interpretazione del messaggio di formato.

Fonti: [GNU della routine](../S33-sections/analysis_codex/evidence/007d58d8_sd_life_full_code.txt), [coda dopo il pool](../S33-sections/analysis_codex/evidence/007d5d80_sd_life_tail.txt), [JSON con stringhe e chiamate](../S33-sections/analysis_codex/evidence/storage_followup.json).

## Collegamento al livello MMIO

Nel ramo di aggiornamento partizione0: `0x1EE0FA → 0x2606B4 → 0x260624 → 0x25E0A4`. La routine `0x260624` carica byte dal buffer a `0x26063A` e li passa nel delay slot al writer; `0x25E0B0` esegue `sth.di r0,[r1]`, con r1 dal pool `0x25E0AC = 0x0FF05000`.

Il wrapper comandi `0x25CB3C` usa lo stesso porto tramite `0x25E064/0x25E070`; il chiamante prepara0x80 a `0x2606DA` e0x10 a `0x260786`. `0x25DF24/4C` modificano i bit8/9 del controllo `0x0FF04020`. Sono istruzioni statiche e accessi espliciti: sostengono la categoria F, possibile scrittura NAND/flash. Non provano il modello del chip, la temporizzazione o il completamento di erase/program.

Fonti: [caricamento byte e invio](../S33-sections/analysis_codex/evidence/00260624_storage_data_output_loop.txt), [store MMIO riancorato](../S33-sections/analysis_codex/evidence/0025e0b0_data_port_store.txt), [controllo comandi](../S33-sections/analysis_codex/evidence/0025df24_command_enable_bits.txt).

## Stato di attivazione: ricerca nei16payload

Scansione separata dei16payload, comprese le residenze sovrapposte11–15: un solo candidato di chiamata diretta al setter `0x129904`, a `0xC5DE8`, verificato nuovamente con r0=1; unica occorrenza LE32 del pointer `0x366880` nel pool `0x12991C`.

Tre coincidenze del pattern halfword-swapped del setter nel blocco09 non dimostrano chiamate. La scansione lineare produce anche falsi salti da dati; non esclude scrittori indiretti, gp-relative o indirizzi calcolati. Non è una prova che lo stato resti sempre1 dopo il boot.

Fonti: [ricerca riproducibile](../S33-sections/analysis_codex/sweep_activation_references.py), [risultati e limiti](../S33-sections/analysis_codex/evidence/activation_reference_sweep.json), [writer riancorato](../S33-sections/analysis_codex/evidence/000c5ddc_writer_reanchored.txt).

## Callback di ingresso, uscita e navigazione

| Menu / evento | Callback | Classe locale | Prova e limite |
|---|---|---|---|
|4A /4405|0x7D417C|R + U|Store guardia+4 a7D4198 e pointer lista a7D41A0; chiamate12DF54/129888 e cambi modalità. Effetti transitivi non tutti chiusi.|
|4A /4406|0x7D4330|R + U|169FBC(1),143AFC(1C); chiusura non certificata come priva di effetti.|
|4A /440C|0x7D4354|R + U|23D478 e azzeramento flag a7D43EC; renderer non chiuso.|
|4A /0580|0x7D4400|R + U|7D4928, poi byte contesto+8 da1 a2 a7D4424.|
|4A /0480|0x7D442C|R + U|1453E4(20,0) a7D4444; ciclo vita dell'oggetto successivo.|
|4B /4405|0x7D49DC|R + U|Preparazione lista e riscrittura etichette aitem+0C; chiamate e cambi modalità da chiudere.|
|4B /4406|0x7D4C5C|R + U|169FBC(1),143AFC(1C), analoghi a4A.|
|4B /440C|0x7D4C80|R + U|23D478 e azzeramento flag a7D4D18.|
|4B /0580|0x7D4D2C|R + U|7D5240, poi byte contesto+6 da1 a2 a7D4D50.|
|4B /0480|0x7D4D58|R + U|Apre20 sotto guardia provenienza; altrimenti evento4002/dato16.|
|4A/4B default|0x20E814|U|Delega alla tabella comune; effetti transitivi non chiusi.|

R indica modifiche RAM osservate; U conserva gli effetti dei chiamati ancora aperti. L'ingresso nei menu non è certificato come privo di effetti persistenti.

**Correzione della sintesi precedente:** il nome “chiusura file” attribuito a `0x12DF54` non era provato. Il corpo osservato modifica flag del contesto, chiama `0x5FE90C` e programma un evento; è ora descritto come routine di flag runtime, con effetti transitivi aperti. `0x129888` costruisce uno snapshot INFO nel buffer fornito, senza provare un reset della memoria persistente.

## Controlli effettivi e punto di ripresa

Eseguiti `python3 S33-sections/analysis_codex/sweep_activation_references.py` e `python3 S33-sections/analysis_codex/audit_storage_followup.py`:16identità payload e16roundtrip ELF;23finestre e40istruzioni controllate; stringhe, pointer, loop file e store MMIO verificati. [Evidenza del secondo controllo](../S33-sections/analysis_codex/evidence/storage_followup.json). I due hash firmware sono rimasti invariati.

Alla ripresa: risolvere l'endpoint runtime della richiesta2018 e gli effetti dei callback di inizializzazione/chiusura. Se si passa al simulatore, intercettare le richieste storage. Nessuna compilazione dell'emulatore svolta. Nessun processo di analisi resta da attendere.
