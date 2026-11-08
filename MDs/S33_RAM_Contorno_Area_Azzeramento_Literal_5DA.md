# RAM: inventario delle literal verso la coda dell'area di azzeramento (5DA000..5DC000) — versione corretta

21 ottobre 2026 — R0/R3. **Correzione importante dell'inventario pubblicato poc'anzi**: la scansione naive di word allineate produce negli stream di istruzioni ARC molti falsi positivi (straddle di encoding: tabelle di salti a allineamento 2-mod-4, coppie `st`/`asl`, `blc`). La versione classificata di `s33_inventory_zero_area_literals.py` distingue i siti **reali** (letterali caricati via `ld [pcl,…]` o immediati limm visualizzati) dagli artefatti.

## Risultato corretto

|Grandezza|Valore|
|---|---|
|candidati word allineate grezze|135|
|**riferimenti reali**|**12** (11 in payload0, 1 in payload4)|
|straddle di encoding (artefatti)|123 (88 in payload6, 27 in payload4, 6 in payload9, 2 in payload0)|
|siti non classificabili|0|
|valori reali distinti|`0x5DA174, 0x5DA202, 0x5DA270, 0x5DA280, 0x5DA310/14/18, 0x5DA4A0, 0x5DA4C0, 0x5DA4DC, 0x5DA55C, 0x5DA5DC`|
|riferimenti reali sopra il confine `0x5DA5DC`|**0**|

La **«griglia a passo pagina 0x100» sopra il confine era un artefatto**: le 88 word di payload6 con valori `0x5Dxx00`/`0x5DA9xx` sono i byte delle istruzioni `b`/`b.d` della jump table a `0xAF454E..0xAF46C0` (allineamento 2-mod-4), lette a cavallo. Anche le 27 ripetizioni di `0x5DA202` in payload4 erano quasi tutte straddle di codice ripetitivo: **un solo** sito reale punta a `0x5DA202`. Lettura corretta: la coda dell'area di azzeramento `[0x42D140,0x5DA5DC)` contiene gli oggetti runtime realmente referenziati (inclusi `0x5DA280` noto dal Capitolo 4, il default del servizio tmp `0x5DA4A0`, e il limite del ciclo `0x5DA5DC`); sopra il confine — dove vive `sp=0x5DADCC` — **nessuna literal statica punta**.

## File e riproduzione

- [Inventario classificato](../Python_Trace_Scripts/s33_inventory_zero_area_literals.py), [evidenza v2](../Ghidra_Results/ghidra_reports/zero_area_top_literals_20261021T170130Z/verified_evidence.json), [indice latest](../Ghidra_Results/ghidara_reports/zero_area_top_literals_latest.json).
- L'evidenza della prima versione ([zero_area_top_literals_20261021T165813Z](../Ghidra_Results/ghidra_reports/zero_area_top_literals_20261021T165813Z/verified_evidence.json)) resta come storia della scansione grezza; i suoi conteggi non sono riferimenti.

```bash
python3 Python_Trace_Scripts/s33_inventory_zero_area_literals.py
```

## Semantica del cluster `0x333968` (confermata, indipendente dalla correzione)

- `0x33412C`/`0x334130`/`0x334134` sono **stub di push** (`st.aw r15/r14/r13,[sp,-4]`), non allocatori: la destinazione del template `0x35BB04` è la `r0` del chiamante.
- `0x333968` è il **servizio nomi file temporanei**: azzera 16 byte nella struttura del chiamante, usa la tabella stringhe a `0x3708F4` (`B:`, `A:`, `A:\tmp`, `B:\tmp`, `tmp.%lu.@@@`, `\%s` — verificata nei byte) e il contatore a `0x37091C`; argomento facoltativo con default `0x5DA4A0`.
- Il cluster `0x333924..0x333A80` ha 9 ingressi diretti `bl`/`b.d`, nessuno verso `0x333968` (solo indiretto/calcolato).

## Nota metodologica

La lezione vale per tutte le scansioni di word allineate: negli stream di istruzioni i byte di encoding producono valori plausibili a ogni allineamento. Le conclusioni dello [sweep estensione](S33_NAND_PC_Sweep_Scrittori_Estensione.md) non sono toccate, perché fondate sui **referencer pcl** (load `ld rX,[pcl,…]` realmente decodificati) e non sui conteggi grezzi; anche lì i conteggi "word in range" (307/92/…) vanno letti come candidati grezzi, non riferimenti. Le analisi future devono sempre classificare pcl/limm/copertura di istruzione.

## Limiti

- La classificazione «reale» copre solo letterali pcl-referenziati e immediati limm: tabelle dati mai caricate via pcl restano invisibili al metodo.
- Nessuna esecuzione; scrittori/DMA/ownership invariati; nessun hardware.
- Candidato `0bb25fd6…` invariato NON_INSTALLARE; circa 10% invariato.

## Continuazione

Il passo decisivo del ramo resta il nuovo export MainCode con l'[analizzatore pronto](S33_NAND_PC_Analizzatore_Export_MainCode.md). Sul fronte statico, il prossimo passo utile è applicare la classificazione pcl/limm/straddle all'inventario del vicinato dell'estensione per purificare i conteggi grezzi pubblicati.
