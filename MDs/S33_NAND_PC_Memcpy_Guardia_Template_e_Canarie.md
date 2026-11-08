# NAND dal PC: memcpy 128C20, template 35BB04 e canarie nell'estensione

21 ottobre 2026 — R0/R3/R4, continuazione dello [sweep statico dei riferimenti](S33_NAND_PC_Sweep_Scrittori_Estensione.md). **Eseguito con l'engine GNU il servizio di copia originale `0x128C20`, il più vicino sospetto scrittore del vicinato dell'estensione.** Due risultati che ridefiniscono la questione residua dei «pool»:

1. **`0x35BB04` non è un pool che cresce**: è un template di 16 byte a zero nella coda di payload0, usato come *sorgente* dal tratto `0x333968..0x33397A` (`r1=35BB04`, `r2=16`, chiamata a `0x128C20`). La vecchia lettura «pool 333B78» va corretta: il riferimento noto sotto l'estensione è una lettura, non una scrittura che possa estendersi verso `[35BC00,35CE00)`.
2. **`0x128C20` è un memcpy con guardia di destinazione**: ammesso solo `(r0+len ≤ 0xAD800)` oppure `r0 ≥ 0xBB534`; la zona `[0xAD800,0xBB534)` provoca un **auto-loop intenzionale a `0x128C3C`** (blocco non-progressivo, verificato: timeout senza alcun byte scritto). Le copie sono limitate esattamente a `[r0, r0+len)`; i rami speciali `0x32F410/0x32F4C0/0x32F570` riguardano gli intervalli che toccano `[0x423900,0x428600)` e restano finestre statiche.

**Punto onesto negativo**: la guardia *permette* l'estensione come destinazione (`0x35BD00` ≥ `0xBB534`): il caso `copy_into_extension` ha scritto esattamente 16 byte dentro l'estensione. La protezione dell'estensione non viene quindi da questo servizio ma dall'assenza di chiamanti con destinazioni là — coerente con lo sweep statico (nessun referencer pcl verso l'intervallo).

## File e riproduzione

- [Verificatore](../Python_Trace_Scripts/s33_verify_nand_pc_memcpy_guard.py), [evidenza](../Risultati/USB_SCSI/Accesso_NAND_PC/memcpy_guard_cpu_20261021T162124Z/verified_evidence.json), [finestre GNU](../Risultati/USB_SCSI/Accesso_NAND_PC/memcpy_guard_cpu_20261021T162124Z/gnu_verified.txt), [indice latest](../Risultati/USB_SCSI/Accesso_NAND_PC/memcpy_guard_latest.json).
- Infrastruttura riusata senza modifiche: `Runner`/`compile_probe`/`static_common`; immagine originale payload0 mappata a `0xAD800`; scratch `0x35D000` e sorgente `0x35E000` come mapfile nel gap sopra l'estensione; sentinella A5 su `[35BC00,35CE00)`.

```bash
python3 Python_Trace_Scripts/s33_verify_nand_pc_memcpy_guard.py
```

## Casi eseguiti (byte originali, driver di laboratorio)

|Caso|r0/r1/r2|Esito|
|---|---|---|
|template_copy_16|`0x35D000` ← `0x35BB04`, 16|16 byte a zero copiati; payload0 invariato (il template è solo letto); estensione intatta|
|pattern_copy_16|`0x35D004` ← `0x35E000`, 16|pattern trasportato esattamente, resto scratch C3, estensione intatta|
|pattern_copy_3|`0x35D002` ← `0x35E000`, 3|percorso byte: solo 3 byte, estensione intatta|
|boundary_bb534|`0xBB534` ← sorgente, 16|primo byte scrivibile della zona alta: esattamente 16 byte dentro l'immagine payload0, resto invariato|
|boundary_last_below|`0xAD7F0` ← sorgente, 16|`r0+len == 0xAD800` ammesso (bls inclusivo): 16 byte sotto payload0, niente oltre|
|copy_into_extension|`0x35BD00` ← sorgente, 16|la guardia ammette l'estensione: esattamente 16 byte dentro, resto sentinella A5|
|guard_forbidden_low|`0xADA00` ← sorgente, 16|destinazione nella zona vietata: auto-loop a `0x128C3C`, timeout 124, zero byte scritti, payload0 ed estensione invariati|

Nota di laboratorio: il codice di uscita del simulatore è il byte basso di `r0` alla `trap_s`; il driver azzera `r0` prima della trap (senza questo, destinazioni come `0x35D004` restituiscono exit 4 e vengono scambiate per errori).

## Cosa cambia per la valutazione del candidato

Il caso «scrittori del vicinato» si restringe ulteriormente: il riferimento statico più vicino sotto l'estensione è un template in sola lettura, e il servizio di copia che lo usa è a scansione delimitata e con guardia verificata. Restano aperti e non coperti qui: gli altri servizi di copia/scrittura, le destinazioni calcolate a runtime da qualunque chiamante di `0x128C20`, DMA/cache/alias, e i rami speciali `0x32F410/0x32F4C0/0x32F570` non eseguiti.

Candidato `0bb25fd6…cb324e9` invariato NON_INSTALLARE; nessun hardware, GNU in sola lettura, circa 10% invariato.

## Continuazione

Prossimi passi utili: estendere lo stesso schema di prova agli altri servizi di scrittura che puntano al vicinato (i 229 store di prossimità candidati dello sweep), oppure il passo decisivo del ramo: nuovo export MainCode (operazione utente da HiddenMenu) per stabilire quale immagine è avviata. L'accesso al resto NAND dal PC resta il goal aperto.
