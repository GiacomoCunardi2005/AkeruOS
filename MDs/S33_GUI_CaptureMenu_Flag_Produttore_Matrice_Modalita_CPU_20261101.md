# CaptureMenu: produttore del flag bit 1 e matrice modalità×guardia — 2026-11-01

Chiusura del lavoro interrotto della sessione precedente (verificatore già PASS, audit e documentazione mancanti). Tutto il percorso di aggiornamento è qui eseguito con codice originale del dump V1.1; l'unica fixture è il servizio ID risorsa corrente.

## Domanda

Chi produce il bit 1 dei flag word a `record+0x18` delle due liste CaptureMenu (controlli `0x9801C0`/ID `0x4800` e `0x980268`/ID `0x4801`) e sotto quali condizioni. I banchi del 1 novembre ([snapshot e aggiornamento](S33_GUI_Snapshot_CaptureMenu_Flag_Record_CPU_20261101.md), [pressione successiva](S33_GUI_CaptureMenu_Flag_Pressione_Successiva_CPU_20261101.md)) seminavano il bit artificialmente e usavano getter sintetici; qui il produttore `0x7CB1B4` gira con i getter originali e le condizioni sono decodificate byte per byte.

## Risultato

`0x7CB1B4` (unico chiamante `0x7CB076`, nel gestore `0x7CB03C` dell'evento `0x4405` installato dalla tabella `0x982384` del descrittore `0x9802AC` in `0x169f60` con ctx `0x899858`) è il produttore del bit 1:

- primo loop: azzera il bit 1 di tutti i record del controllo corrente `[[0x899858]+4]=[0x89985C]` (count a `+0x34`, lista a `+0x30`, stride 28) tramite `0x631E98(record, 0)`;
- ramo ID `0x4801`: per ogni record con halfword destinazione `+0x14` pari a `0xBB` o `0x0A`, bit 1 = 1 se `mode != 0x2C`, oppure `mode == 0x2C` e guardia `== 7` (mode da `0xCAD30`, guardia da `0xCA310`);
- ramo ID `0x4800`: per ogni record con byte categoria `+0x10` pari a 2, bit 1 = 1 se `mode ∈ {0x14, 0x1F, 0x6D, 0x68, 0x05, 0x7D}`; pari a 3 se `mode ∈ {0x14, 0x05, 0x15, 0x7E}`;
- `0x631E98(record, v)` imposta/azzera SOLO il bit 1 di `[record+0x18]` e solo se il valore attuale differisce.

I due getter sono originali in banco: `0xCAD30` restituisce il byte a RAM `0xC8E80C` (`ld.as r0,[pcl,-155]`, EA `0xCAAC4`, word `0xC8E80C`); `0xCA310` il byte a `0x365751` (pool `0xCA30C`). Il pool `0xCAD58 = 0x365753` appartiene solo al setter `0xCAD38`/stub `0xCAD5C`, non al getter.

**Collegamento importante**: `0xC8E80C` è il byte a `+0xC` del record TBIB 8 (base `0xC8E800`, magic `C1C2C3C4`, «NotRunOneCard») — lo stesso byte classificato da `0x16E440` nell'[iterazione 27 del checkpoint](S33_Vibe_Offline_Checkpoint.md), valore statico V1.1 `0x2C`. Il selettore del flag è quindi il byte di variante/configurazione di boot, non una modalità di scatto runtime (significato fisico aperto). Conseguenza sul dump: con `0x2C` la lista `0x4800` non riceve mai il bit 1 dal ramo categorie, e `0x4801` lo riceve sui record `0x0A`/`0xBB` solo se la guardia vale 7.

Matrice CPU di 14 casi (risorsa × mode × guardia × seed; flag word dopo l'aggiornamento):

| Risorsa | Mode | Guardia | Flag dopo | Note traccia |
| --- | --- | --- | --- | --- |
| 0x4801 | 0x46 | 0 | 8, 8, A, A | 2×0xCAD30, 0×0xCA310 |
| 0x4801 | 0x2C | 0 | 8, 8, 8, 8 | guardia consultata, ≠7 |
| 0x4801 | 0x2C | 7 | 8, 8, A, A | guardia consultata, ==7 |
| 0x4801 | 0x2C | 6 | 8, 8, 8, 8 | controesame guardia ≠7 |
| 0x4801 | 0x2B | 0 | 8, 8, A, A | mode ≠ 0x2C senza guardia |
| 0x4800 | 0x14 | 0 | 8, A, A | mode in entrambe le liste |
| 0x4800 | 0x68 | 0 | 8, A, 8 | solo categoria 2 |
| 0x4800 | 0x15 | 0 | 8, 8, A | solo categoria 3 |
| 0x4800 | 0x46/0x0A | 0 | 8, 8, 8 | mode fuori lista |

(casi completi in `cases.json`; seed 0x08 e 0x0A equivalenti). I conteggi di `0xCAD30` confermano i confronti short-circuit: le liste di categoria 2 (6 modalità) e 3 (4 modalità) sono consultate solo per il record di quella categoria — totale 2 chiamate per mode `0x14`, 8 per `0x68`, 9 per `0x15`, 10 per mode fuori lista; nel ramo `0x4801` una chiamata per record consultato (dest `0xBB`/`0x0A`) e `0xCA310` solo se `mode == 0x2C`.

I record dell'altro controllo (sentinella `0x13572468`) restano intatti in tutti i casi; stack preservato. Il bit 1 è quello che nella [pressione successiva](S33_GUI_CaptureMenu_Flag_Pressione_Successiva_CPU_20261101.md) fa ritornare `1` agli handler `0x631A38`/`0x631B14` senza chiamare selezione né apertura: questo banco chiude il lato produttore di quella catena.

## Revisione indipendente (agente `flag-audit-3`)

Punti 1–3 CONFERMATI con byte di prova; punto 4 (altri scrittori) nessun controesempio statico; punto 5 censimento. Aggiunte accolte e riverificate in coordinatore:

- Percorso di raggiungibilità: descrittore `0x9802AC` → `0x7CAFE8` → `0x169f60`(ctx `0x899858`, tabella eventi `0x982384`: `0x4401→0x7CB020`, `0x4405→0x7CB03C`, `0x4406→0x7CB0A4`, `0x180→0x7CB0D8`, `0x480→0x7CB0F8`); `0x7CB03C` chiama `0x7CB118` (a `0x7CB058`) e `0x7CB1B4` (a `0x7CB076`).
- `[0x89985C]` è scritta solo da `0x7CB118` (store `st_s r0,[r14,4]` a `0x7CB15A`/`0x7CB196`): per argomento 4 memorizza il ritorno di `0x145654(arg, 0x4800)`, per argomento 5 quello di `0x145654(arg, 0x4801)` — coerente con la mappa argomento→risorsa già nota. Prima dello store il ramo arg 4 chiama `0x145764(a,0x4800)`, `0x145b08(a,0x4800,1)`, `0x145b08(a,0x4801,0)`; il ramo arg 5 `0x145764(a,0x4801)`, `0x145b08(a,0x4801,0)`, `0x145b08(a,0x4801,1)`.
- Strutture in copia unica nel file; flag iniziali nel dump `8,0,0` (lista 1) e `8,0,0,0` (lista 2): bit 1 mai settato all'origine. Correzione minore all'audit, che riportava `0,0,0,0` per la lista 2.
- `0x631E98` ha 128 siti di chiamata e 5 pool a puntatore, ma gli altri menu usano celle proprie (es. `0x7C86F0` → `0x8997D8`): nessun altro menu tocca queste liste.
- **Censimento cella modalità `0xC8E80C`: nessuno scrittore statico nel firmware.** Lettori: getter `0xCAD30` (434 `bl` diretti) e inline `0xCA418`, `0xCA726` (logica con confronto mode `0x2C` e valore 3), `0xD04C0`; le scritture del banco `0xC8E8xx` toccano `+1`, `+3`, `+7` e l'array `0xC8EB30+`, mai `+0xC`. Il produttore del byte è runtime (coerente con il record TBIB 8 caricato dal loader, iterazione 27).
- **Cella guardia `0x365751`: esattamente due riferimenti statici**, entrambi via pool `0xCA30C` — getter `0xCA310` (58 `bl`) e setter `0xCA2F4` (27 `bl`, `stb_s r0,[r1,0]`): la guardia HA un produttore software identificabile.

## Riproduzione e limiti

- `python3 Python_Trace_Scripts/s33_verify_capture_flag_mode_matrix_cpu.py`: 14 casi PASS `PASS_CAPTURE_FLAG_MODE_MATRIX`. Prima esecuzione della sessione interrotta `Risultati/GUI_S33/capture_flag_mode_matrix_cpu_20261101T103519423275Z/`; riesecuzione indipendente di questa sessione `capture_flag_mode_matrix_cpu_20261101T104243668736Z/`, esito identico.
- Regressioni rieseguite in questa sessione, tutte PASS: `s33_verify_snapshot_capture_record_init_cpu.py` (4), `s33_verify_snapshot_capture_followup_key_cpu.py` (4), `s33_verify_gui_key_queue_capture_original_items_cpu.py` (8), `s33_verify_gui_autoscene_key_reenter_cpu.py` (9), `s33_verify_autoscene_capture_entry_cpu.py` (4).

Assunzioni: l'unica fixture è `0x1457D4`, patchato per leggere `[0x89985C]+4`; l'originale legge dalla cella WindowManager `0x366EAC` (pool `0x1457D0`), diversa da `[0x89985C]` — il banco allinea il getter all'enumerazione dell'aggiornamento stesso, ma su fotocamera le due celle potrebbero divergere. Byte modalità, guardia, controllo corrente e flag sono semi sintetici in RAM; immagini dei blocchi {0,1,2,3,4,5,8}.

Limiti: ingresso diretto a `0x7CB1B4` come nel singolo sito `0x7CB076` (init classe 15), senza catena AutoScene/manager; il produttore runtime di `0xC8E80C` non è visibile staticamente e il significato fisico di modi e guardia resta aperto; `0x145764`/`0x145b08` non decodificati; l'unicità assoluta del produttore non è dimostrabile con la sola analisi statica (data-flow del WindowManager `0x169f60` non tracciato). V1.1 campione vs macchina V1.0. Nessun tasto fisico, rendering, scatto o hardware; **NON_INSTALLARE**; progresso funzionale ~10% invariato.
