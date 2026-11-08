# NAND dal PC: rami speciali del memcpy eseguiti (32F410/32F4C0/32F570)

21 ottobre 2026 — R0/R3/R4, chiusura del limite lasciato aperto dal [rapporto memcpy](S33_NAND_PC_Memcpy_Guardia_Template_e_Canarie.md). **Eseguiti con l'engine GNU i tre rami speciali del servizio di copia `0x128C20`**, quelli che il dispatcher sceglie quando sorgente o destinazione toccano `[0x423900,0x428600)`. Sono copie normali con accessi `.di` (bypass della cache dati) su store e/o load: **nessun MMIO, nessuna scrittura fuori da `[r0,r0+len)`**. Otto casi superati, due dei quali attraverso il servizio completo (guardia + dispatch).

## File e riproduzione

- [Verificatore](../Python_Trace_Scripts/s33_verify_nand_pc_memcpy_special.py), [evidenza](../Risultati/USB_SCSI/Accesso_NAND_PC/memcpy_special_cpu_20261021T164008Z/verified_evidence.json), [finestre GNU](../Risultati/USB_SCSI/Accesso_NAND_PC/memcpy_special_cpu_20261021T164008Z/gnu_verified.txt), [indice latest](../Risultati/USB_SCSI/Accesso_NAND_PC/memcpy_special_latest.json).

```bash
python3 Python_Trace_Scripts/s33_verify_nand_pc_memcpy_special.py
```

## Semantica identificata

|Ramo|Quando è scelto da `0x128C20`|Accessi|
|---|---|---|
|`0x32F4C0`|destinazione tocca la regione speciale (r4=1), sorgente normale|`st.di` (store bypass cache)|
|`0x32F410`|sorgente tocca la regione speciale, destinazione normale|`ld.di` (load bypass cache)|
|`0x32F570`|sorgente e destinazione nella regione speciale|`ld.di` + `st.di`|

Tutti e tre: `len=0` → ritorno immediato; percorsi allineati a parole e percorsi byte per indirizzi disallineati; ritorno via `[blink]`. La «regione speciale» `[423900,428600)` è la coda di payload1 (fondo del suo intervallo): i rami servono a evitare interferenze di cache su di essa.

## Casi eseguiti (byte originali, fixture mapfile)

|Caso|Ingresso|Esito|
|---|---|---|
|special_dest_copy_16 / _3 / _0|`0x32F4C0`, dest speciale, len 16/3/0|copia esatta e delimitata; len 0 nessuna scrittura|
|special_src_copy_16|`0x32F410`, src speciale → scratch gap|copia esatta, sorgente invariata|
|special_src_unaligned|`0x32F410`, len 5 disallineato|percorso byte, 5 byte esatti|
|special_both_copy_16|`0x32F570`, src e dest speciali|copia esatta fra le due fixture|
|integration_memcpy_special_dest|`0x128C20` completo, dest speciale|guardia superata e dispatch a `0x32F4C0`: copia delimitata|
|integration_memcpy_special_src|`0x128C20` completo, src speciale|dispatch al ramo sorgente: copia delimitata|

In tutti i casi: immagine payload0 invariata, estensione `[35BC00,35CE00)` sentinella A5 **intatta**, zero fault.

## Limiti

- L'effetto *runtime* della semantica cache di `.di` non è modellato dal simulatore: qui si prova delimitazione e correttezza dei byte, non il comportamento della cache.
- Nessuna prova che altri percorsi non scrivano la regione speciale; non riguarda direttamente l'estensione, che resta fuori da questi rami.
- Candidato `0bb25fd6…cb324e9` invariato NON_INSTALLARE; nessun hardware; circa 10% invariato.

## Continuazione

Il servizio di copia `0x128C20` è ora interamente eseguito (corpo base + tre rami + guardie). Restano aperti: gli altri potenziali servizi di scrittura (nessuno finora punta all'estensione), DMA/cache/alias e puntatori calcolati — tutti fuori dal perimetro statico-dinamico finora coperto. Il passo decisivo del ramo NAND/PC resta il **nuovo export MainCode** (operazione utente da HiddenMenu) per stabilire quale immagine è avviata.
