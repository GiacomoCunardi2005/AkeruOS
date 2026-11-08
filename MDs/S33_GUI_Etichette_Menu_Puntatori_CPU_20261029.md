# GUI S33 — etichette originali e stringhe nuove

Il campo `+12` di un record del controllo studiato può essere passato alla routine originale `0x6337C4`: zero restituisce zero, gli ID 1–380 passano al lookup delle risorse, e i valori da 381 in su sono restituiti invariati. Il percorso dal record a questa routine e, sotto guardie, al disegno del testo è documentato nella [risoluzione risorse](S33_GUI_CaptureMenu_Risoluzione_Risorse_20261027.md); non è stato rieseguito integralmente qui.

Il 29 ottobre 2026 ho verificato le routine originali `0x6337C4` e `0x1286C4` in GNU ARC700 usando i blocchi lingua V1.1 originali come RAM sintetica. Per le voci richieste si possono riutilizzare i seguenti ID:

| ID | Blocco italiano | Blocco inglese |
|---:|---|---|
| 26 | Cambia colore | Change colors |
| 64 | Impostazioni | Settings |
| 88 | Impostazioni fotocamera | Camera settings |

Nel medesimo banco, quattro valori `0x2200000`, `0x2200008`, `0x2200010` e `0x2200020` sono restituiti invariati dal wrapper e puntano alle stringhe sintetiche ASCII `ISO`, `f/`, `Tempo` e `Mono RAW`. Il banco legge e controlla il testo alle destinazioni: la CPU ha eseguito il **lookup**, non il disegno. La lingua delle quattro stringhe nuove è fissa nella fixture, mentre i tre ID usano il blocco lingua caricato.

**28 casi PASS** su due blocchi, comprese guardie e valori limite; stack e buffer delle stringhe invariati. [Verificatore](../Python_Trace_Scripts/s33_verify_gui_custom_menu_text_cpu.py), [casi](../Risultati/GUI_S33/custom_menu_text_cpu_20261029T225143Z/cases.json), [manifest e tracce](../Risultati/GUI_S33/custom_menu_text_cpu_20261029T225143Z/verified_evidence.json). I blocchi originali sono confrontati con il dump, ma sono caricati direttamente dal banco; flag e indirizzi RAM sono sintetici.

Il wrapper non controlla la validità, la durata o la codifica del puntatore diretto. Non si può usare `0x2200000` come RAM fisica sulla base di questo test: occorrono memoria e lifetime verificati. Mancano la prova del controllo completo con queste voci, font, clipping, rendering e display fisico; nessun firmware o dispositivo modificato. **NON_INSTALLARE**.
