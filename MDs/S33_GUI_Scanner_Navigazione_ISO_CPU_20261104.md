# S33 V1.1 — Navigazione ISO dallo scanner, CPU emulata — 2026-11-04

## Risultato

Il banco esegue byte originali verificati del firmware V1.1 in CPU ARC700 emulata. Inizializza la lista ISO tramite la funzione originale `0x641064`: l’indice software iniziale 6 produce la posizione 7, ISO 125. Esegue quindi lo scanner originale, estrae e inoltra gli eventi al controllo classe 9, conferma e verifica selezione e setter ISO originali. Superati **8/8 casi**: due ordini di callback iniziali, due direzioni, attributo di navigazione abilitato o disabilitato.

| Evento logico scanner | Attributo | Posizione iniziale → finale | Indice software | Parametro ISO |
|---|---|---|---|---|
| bit 20, classe 7 | `0x2D0000` | 7 → 6 | 5 | 120 |
| bit 16, classe 8 | `0x2D0000` | 7 → 8 | 7 | 140 |
| bit 20 o 16 | `0x290000` | 7 → 7 | 6 | 125 |

`0x2D0000` è l’attributo verificato della risorsa originale a `0x989F84`; il confronto disabilita soltanto il bit `0x40000`. Gli handler originali `0x640E64` e `0x640EE4`, la routine `0x641174`, i rispettivi helper `0x6413A0` e `0x641314`, il selettore `0x641064` e il percorso di conferma fino al setter sono verificati anche nelle tracce. I byte delle finestre originali collegate sono confrontati con il payload verificato. La conferma segue gli eventi classe 11 `0x580`/`0x581` generati dallo scanner; il controllo produce `0x4801` per il parent ISO.

## Riproduzione e limiti

- Verificatore: `python3 Python_Trace_Scripts/s33_verify_key_scanner_iso_navigation_cpu.py`.
- Evidenze: `Risultati/GUI_S33/key_scanner_iso_navigation_cpu_20261104T112130736882Z`.
- Regressione conferma controllo: **16/16**, evidenze `Risultati/GUI_S33/key_scanner_control_confirm_cpu_20261104T112122878596Z`.
- La schermata iniziale, il controllo attivo e il suo collegamento al parent sono fixture; alcune funzioni di sistema, refresh, risorse, focus e ritorno sono stub o modellate. Eventi estratti e inoltrati esplicitamente dal banco, senza dimostrare scheduling o temporizzazione reali. Attributi e identificatore del controllo confrontati con la risorsa; il collegamento al parent è imposto nel modello.
- I numeri 7 e 8 indicano classi logiche, non identificano ancora tasti fisici. Non sono verificati schermo reale, sensore, esposizione automatica, persistenza o funzionamento su fotocamera. La lista completa e i limiti di ISO 6400 sono documentati in `MDs/S33_GUI_ISO_Mappa_Lista_Completa_CPU_20261104.md`. Stato candidati **NON_INSTALLARE**.
