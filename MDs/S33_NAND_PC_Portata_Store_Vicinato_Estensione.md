# NAND dal PC: portata degli store del vicinato verso l'estensione

21 ottobre 2026 — R0/R3/R4, secondo stadio dello [sweep statico](S33_NAND_PC_Sweep_Scrittori_Estensione.md). **Analisi di portata di tutti gli store di prossimità registrati dallo sweep**: per ogni scrittura la cui base è un letterale del vicinato `[35B000,361000)`, è calcolato l'intervallo effettivamente scritto (base + offset immediato + dimensione dello store) e confrontato con l'estensione `[35BC00,35CE00)`.

## File e riproduzione

- [Analizzatore](../Python_Trace_Scripts/s33_analyze_extension_reach.py), [evidenza](../Risultati/USB_SCSI/Accesso_NAND_PC/extension_reach_20261021T163850Z/verified_evidence.json), [indice latest](../Risultati/USB_SCSI/Accesso_NAND_PC/extension_reach_latest.json); input: l'[evidenza dello sweep](../Risultati/USB_SCSI/Accesso_NAND_PC/extension_writers_sweep_20261021T161112Z/verified_evidence.json) (hash verificato).

```bash
python3 Python_Trace_Scripts/s33_analyze_extension_reach.py
```

## Risultato

|Grandezza|Valore|
|---|---|
|store con base = letterale del vicinato (ruolo base)|333|
|offset immediato positivo massimo|**0xB6**|
|offset negativi (ruolo base)|**0** (i due casi negativi osservati sono ruolo valore: il puntatore viene scritto altrove)|
|base più alta sotto l'estensione con store di ruolo base|`0x35BAFE` → distanza `0x102`|
|**margine rispetto all'estensione**|**0x4C** byte|
|forme con offset a registro (portata statica illimitata)|0|
|operandi non analizzabili|0|
|store di ruolo valore (puntatore installato in altre basi r0..r22, sp, fp)|617, destinazioni non tracciate|
|intersezioni con `[35BC00,35CE00)`|**0**|
|istruzioni limm con immediato dentro l'estensione|**0** (tutti gli immediati osservati sono nel vicinato sotto o nell'area dati di payload1)|

## Lettura

Nessuno degli store statici con base nel vicinato raggiunge l'estensione: l'offset immediato massimo (0xB6) non copre nemmeno la distanza dalla base più vicina (0x102), con margine 0x4C. Insieme al risultato dello sweep (nessun referencer pcl dentro l'estensione) e alla [prova del memcpy](S33_NAND_PC_Memcpy_Guardia_Template_e_Canarie.md), il quadro statico del vicinato è ora quantificato, non solo qualitativo.

## Limiti

- Analisi di prossimità (24 istruzioni dopo ogni load del letterale), non dataflow completo: uno store oltre quella finestra sfuggirebbe.
- I 617 store di ruolo valore installano i puntatori del vicinato in altre strutture (r0..r22, sp, fp): le loro destinazioni non sono tracciate in questo stadio.
- Restano fuori, come già noto: offset a registro (qui zero casi nel ruolo base, ma la finestra non è esaustiva), DMA/cache/alias e puntatori calcolati.
- Candidato `0bb25fd6…cb324e9` invariato NON_INSTALLARE; nessun hardware; circa 10% invariato.

## Continuazione

Chiudere i rami speciali del memcpy `0x32F410/0x32F4C0/0x32F570` (percorsi per gli intervalli che toccano `[423900,428600)`) eseguendoli come il caso `0x128C20`, oppure proseguire con il nuovo export MainCode (operazione utente) che resta il passo decisivo del ramo.
