# NAND dal PC: sweep statico dei riferimenti all'intervallo di estensione

21 ottobre 2026 — R0/R3/R4, continuazione delle verifiche di residenza ([regioni RAM](S33_NAND_PC_Regioni_RAM_Applicative_e_Limite_Installazione.md), [API](S33_NAND_PC_API_Regioni_e_Configurazione_Successiva.md)). **Sweep statico completo dei 16 payload originali, del corpo TBIB e del payload0 candidato per tutti i riferimenti all'intervallo `[0x35B000,0x361000)`** che contiene l'estensione del candidato `[35BC00,35CE00)`. Risultato principale: **nessun riferimento statico originale cade dentro l'estensione**, e l'intero tratto `[35BC00,0x360800)` fino a payload1 è privo di riferimenti diretti nel codice. Candidato invariato NON_INSTALLARE; la questione scrittori si restringe ai soli accessi calcolati, DMA/cache e ai pool del vicinato.

## File e riproduzione

- [Sweep](../Python_Trace_Scripts/s33_sweep_extension_writers.py), [evidenza](../Risultati/USB_SCSI/Accesso_NAND_PC/extension_writers_sweep_20261021T161112Z/verified_evidence.json), [finestre disassemblate](../Risultati/USB_SCSI/Accesso_NAND_PC/extension_writers_sweep_20261021T161112Z/windows.txt), [indice latest](../Risultati/USB_SCSI/Accesso_NAND_PC/extension_writers_sweep_latest.json).
- Metodo riusato dal progetto: `verified_payloads`/`objdump_text` di `s33_trace_state_dispatch`, listato GNU ARC `-m arc:ARC700 -EL`, letterali PC-relative con formula `(PC & ~3) + offset*4` risolta da objdump; corpo TBIB estratto con `parse_firmware` e checksum corpo verificato.

```bash
python3 Python_Trace_Scripts/s33_sweep_extension_writers.py
```

## Copertura

Per ciascun blocco: scansione di tutte le word LE a passo 2 byte in `[0x35B000,0x361000)`; listato GNU ARC completo; ogni `ld rX,[pcl,…]` il cui letterale ricade nell'insieme; flag di prossimità (24 istruzioni) per store che usano il registro caricato come base o come valore; usi `limm` diretti dell'intervallo; candidati `movhi/ori` con mezzo-alto 0x35b/0x35c.

|Blocco|Word in range|Dentro estensione|Referencer pcl|Con store candidati|limm|
|---|---|---|---|---|---|
|payload0 (0xAD800)|307|0|497|229|176|
|payload1 (0x360800)|92|0|0|0|0|
|payload2..3, 5, 7..8, 10..15|≤70|0|0|0|0|
|payload4 (0x796800)|54|16|2|0|0|
|payload6 (0x9A3800)|55|3|0|0|0|
|payload9 (0xC8F800)|479|2|1|0|0|
|TBIB corpo (0x1000000)|12|0|0|0|0|
|candidato payload0|307|0|497|229|176|

## Lettura dei risultati

- **Nessun referencer pcl punta a una word dentro `[35BC00,35CE00)`** in tutta l'immagine originale. Le poche word 4-allineate che cadono dentro (payload6: `0x35C2D0`, `0x35BD71`×2; payload9: `0x35C725`) sono immerse in tabelle dense non-puntatore (dati multimediali/DSP, campioni), senza alcun load pcl; le 16 di payload4 sono tutte lo stesso valore `0x35CC9E` a allineamento 2 dentro dati ripetitivi: coincidenze di byte, non letterali.
- **Il tratto `[35BC00,0x360800)` è staticamente muto**: i riferimenti del vicinato si fermano sotto a `0x35BB04` (l'oggetto pool 16byte già noto, caricato da `0x333972` verso `0x128C20` con lunghezza16) e riprendono sopra a `0x3608A0`, cioè dentro payload1. Nessun valore dell'intervallo né della coda fino a payload1 è caricato dal codice di payload0.
- I 497 referencer di payload0 riguardano il vicinato: strutture a `0x35B4DA..E0`, `0x35B8E1`, il pool `0x35BB04`, e i dati di payload1 da `0x3608A0` in poi; 229 hanno store di prossimità candidati (sotto/ sopra, mai dentro l'estensione). Le finestre complete sono in `windows.txt` per revisione manuale.
- **Candidato**: payload0 differisce dall'originale per 1 solo byte (`0xC5EEA`); tutti i 497 referencer originali sono preservati, nessun referencer nuovo verso l'intervallo. Hook `820C88` e slot `9A3460` stanno in payload4/payload5, fuori da questo confronto, come già noto nelle [generazioni](S33_NAND_PC_Generazioni_MainCode_Slot_FF_e_Assenza_Scrittori.md).
- Il corpo TBIB contiene 12 word in range, nessuna dentro l'estensione e nessun referencer: lo stadio boot non referenzia staticamente il tratto.

## Cosa questo aggiunge e cosa non prova

Aggiunge un inventario statico esaustivo (tutti i blocchi, non solo finestre scelte) che integra le prove dinamiche già esistenti (azzeramento iniziale, ingresso loader BB540, 111 regioni con 96 riempimenti, API) sullo stesso intervallo: nessun percorso statico originale punta all'estensione.

Non prova l'assenza di scrittori a runtime: restano aperti accessi calcolati da basi diverse (puntatori derivati, stack, heap), DMA/cache/alias, l'estensione effettiva dei pool del vicinato (in particolare se `0x128C20` e simili possono crescere oltre i 16 byte dichiarati), e regioni decodificate come dati nel listato lineare che potrebbero nascondere load pcl. I flag di prossimità sono candidati, non dataflow. Scansione a passo 2 byte: letterali disallineati di 1 byte non coperti.

Candidato `0bb25fd6…cb324e9` invariato NON_INSTALLARE; nessun hardware, GNU in sola lettura, circa 10% invariato.

## Continuazione

Prossimo utile sul fronte scrittori: eseguire con l'engine GNU la routine `0x128C20` dal tratto `0x333968..0x33397A` (r1=`35BB04`, r2=16) con canarie nell'estensione, per misurare dinamicamente l'effettiva estensione del pool e chiudere il caso del vicino più prossimo. Alternativa: applicare lo stesso sweep all'intervallo del buffer privato e delle altre zone candidate. Il passo decisivo del ramo resta il nuovo export MainCode (utente) per l'immagine avviata.

## Continuazione — purificazione dei conteggi grezzi (21 ottobre 2026)

Applicata la classificazione pcl/limm/straddle (vedi la [correzione dell'inventario 5DA](S33_RAM_Contorno_Area_Azzeramento_Literal_5DA.md)) ai candidati word 4-allineati dell'intervallo `[35B000,361000)`: payload0 240 candidati → **200 reali** (letterali pcl o immediati limm) e 40 straddle di encoding; payload9 256→1 reale; payload4 8→1; payload1/3/5/6/12 restano candidati non classificabili (payload di dati decodificati come istruzioni dal listato lineare: limite del metodo, non falsificati come artefatti). **Zero riferimenti reali dentro `[35BC00,35CE00)` in tutti i payload.** Anche concedendo reali tutti i candidati non classificabili, nessuno di essi cadeva dentro l'estensione (lo sweep originale lo aveva già escluso per tutte le word a passo 2). La conclusione principale — nessun riferimento statico originale all'interno dell'estensione — è quindi confermata dal metodo raffinato, non indebolita dagli artefatti.
