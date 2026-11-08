# GUI — ripristino ISO prima del calcolo

Il 30 ottobre 2026 ho confrontato otto esecuzioni GNU ARC700 DSP sperimentali, a coppie: stessi dati sintetici e stessa selezione ISO, con o senza chiamata esplicita del banco a `0xCA654` tra conferme diagnostiche e chiamata a `0xD8CA4`. Il record passato a `CA654` parte con indice ISO 19 e tempo 90.000; il banco conferma tempo 42, producendo 42.000 nel contesto. Il valore ISO iniziale nel contesto è 1600.

| Scelta ISO | Dopo conferma | Senza ripristino: ISO nel buffer finale | Con ripristino: ISO nel buffer finale |
|---|---:|---:|---:|
| Exit | 1600 | 1600 | 1600 |
| Auto | 0 | 0 | 1600 |
| 125 | 125 | 125 | 125 |
| 1600 | 1600 | 1600 | 1600 |

Il banco verifica che `0xCA654` venga chiamata solo nei quattro casi previsti, legge il valore subito dopo la conferma e dopo l'eventuale ripristino, e verifica anche il record: con ripristino l'indice resta 19 tranne scelta 125, che lo aggiorna a 6; il tempo diventa 42.000. Senza ripristino il record resta 19 / 90.000. Nei casi Auto il percorso senza ripristino chiama `FDA28` due volte; quello con ripristino una. I campi controllati del risultato finale per Auto passano da tempo/ISO/byte confronto `42000/0/0` a `42000/1600/1`.

Questo **dimostra una dipendenza dall'ordine nel banco** e dal record sintetico predisposto: non dimostra che la macchina reale esegua `CA654` in quel momento o che il record contenga 19. Nel banco la routine originale `CA654` è eseguita, ma 14 setter ausiliari sono fixture che ritornano zero in *tutte* le otto prove; anche callback GUI, apertura, copia, `0x18C634`, callback indirette e registratore del ramo `0xD8E22` sono fixture. Nessun significato fisico dell'ISO, AE o tempo è stabilito.

[Verificatore](../Python_Trace_Scripts/s33_probe_gui_iso_restore_to_calc_cpu.py): [Exit senza](../Risultati/GUI_S33/gui_iso_restore_calc_probe_0_20261030T102527Z/verified_evidence.json) e [con](../Risultati/GUI_S33/gui_iso_restore_calc_probe_1_20261030T102527Z/verified_evidence.json); [Auto senza](../Risultati/GUI_S33/gui_iso_restore_calc_probe_2_20261030T102527Z/verified_evidence.json) e [con](../Risultati/GUI_S33/gui_iso_restore_calc_probe_3_20261030T102527Z/verified_evidence.json); [125 senza](../Risultati/GUI_S33/gui_iso_restore_calc_probe_4_20261030T102527Z/verified_evidence.json) e [con](../Risultati/GUI_S33/gui_iso_restore_calc_probe_5_20261030T102527Z/verified_evidence.json); [1600 senza](../Risultati/GUI_S33/gui_iso_restore_calc_probe_6_20261030T102527Z/verified_evidence.json) e [con](../Risultati/GUI_S33/gui_iso_restore_calc_probe_7_20261030T102527Z/verified_evidence.json).

Non sono verificati il ciclo reale, la provenienza del record, il sensore, i tasti o lo scatto. Firmware e dispositivo invariati; **NON_INSTALLARE**.
