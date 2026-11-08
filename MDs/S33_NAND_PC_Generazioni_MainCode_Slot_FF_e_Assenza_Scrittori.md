# NAND dal PC: generazioni del MainCode, slot FF e assenza di scrittori della tabella

21 ottobre 2026 — R0/R3/R4. **Verifica statica completa della parola `9A3460`** (slot FF della tabella dispatch SCSI) in cinque immagini: originale V1.1, tre contenitori sperimentali e l'export `DUMPS/MainCode.dmp` fornito dall'utente. Risultato centrale: l'export della fotocamera contiene il puntatore **originale** `820B2C` e coincide byte per byte col TBM del candidato SD, quindi rispecchia la generazione precedente alle installazioni MSDC-default e NAND/PC e **non può discriminare l'immagine attualmente avviata**. Nessun codice scrive la tabella a runtime: il puntatore FF in esecuzione decide solo quale immagine è caricata.

## Prove e riproduzione

- [Verificatore](../Python_Trace_Scripts/s33_verify_nand_pc_maincode_generations.py), [manifest](../Risultati/USB_SCSI/Accesso_NAND_PC/maincode_generations_latest.json).
- Run: `maincode_generations_20261021T154754Z/verified_evidence.json`, esito PASS, input invariati per hash.

```bash
python3 Python_Trace_Scripts/s33_verify_nand_pc_maincode_generations.py
```

Tutti gli input sono verificati per SHA-256 prima dell'uso. Nessun hardware, nessuna scrittura GNU, nessun comando alla fotocamera.

## Lo slot FF nelle cinque immagini

La tabella dispatch a `0x9A33D4` è una sequenza di 18 coppie `[opcode, handler]` da 8 byte, finale `0x9A345C=0xFF`, `0x9A3460=handler`. Slot per immagine:

| Immagine | Slot `9A3460` | Significato |
|---|---|---|
| originale V1.1 (`1d34e990…`) | `00820B2C` | noop `j_s.d [blink]; mov_s r0,0` |
| candidato SD (`ce504526…`) | `00820B2C` | invariato |
| candidato MSDC-default (`af65ab0e…`) | `00820B2C` | invariato |
| candidato NAND/PC (`0bb25fd6…`) | `0035BD40` | handler RAW record 17 |
| `DUMPS/MainCode.dmp` (`00551af5…`) | `00820B2C` | generazione candidato SD |

`DUMPS/MainCode.dmp` è identico per l'intero TBM (17.615.360 byte) al candidato SD, coda FF: è l'export dell'era candidato SD, classificato il 20 ottobre. Da allora l'utente riferisce due installazioni (MSDC-default, poi NAND/PC): l'export disponibile è di una generazione precedente e non dice nulla sui byte attuali.

Il delta esatto del candidato NAND/PC rispetto all'originale nel corpo TBM è di tre tratti: `C5EEA 02→01` (ereditato dal candidato MSDC-default), hook parser 4 byte a `820C88`, slot `9A3460`; più header/record 17 e coda di 4.608 byte (4.597 non-FF) oltre la fine del TBM originale.

## Nessuno scrittore della tabella nel MainCode

- La sequenza `[0x12→81FB4C, 0x1A→81FC5C]` occorre **una sola volta** nell'intero export (la tabella stessa a `9A33EC`): non esiste una copia template da cui ripristinarla.
- Nessuna word limm in alcun payload punta a `9A3460` o all'interno della tabella; i soli riferimenti al perimetro sono dieci literal noti del codice USB (base `9A33D4`, marcatore di fine `9A3464`, tabella descrittori successiva `9A3478`), tutti nel payload 4.
- La catena di dispatch è verificata sui byte: lookup `81F89C` carica la base da `81F940`, scandisce le 18 coppie con `ADD3 r14,r14,r0` (passo 8), confronta l'opcode, e a `81FA14` legge l'handler con `ld_s r2,[r14,0x4]` — direttamente dalla parola statica — chiamandolo con `jl_s.d [r2]` a `81FA1E`. Nella finestra `81F89C..81FA22` non esiste uno store con base `r14`.
- La cella RAM `89ABBC` (`[89AB7C+0x40]`), letta e chiamata dentro il gestore `81FB4C`, è un callback distinto dell'oggetto MSC RAM, non il percorso dello slot FF.

Conseguenza: se l'immagine avviata contenesse lo slot candidato `35BD40`, nessun percorso noto lo riscriverebbe in `820B2C`. Il comportamento hardware osservato il 21 ottobre (FF con magic errato → status GOOD, zero dati, residuo 2112) corrisponde a un'immagine con slot originale e differisce dai 31 casi CPU col puntatore candidato, che rifiutano il magic errato. Le cause compatibili restano: MainCode in NAND non aggiornato (l'INFO928=20 di completamento non prova i byte scritti, come già verificato nel fallback TBIB), oppure avvio da una copia non aggiornata; resta solo teorico uno scrittore via puntatore in registro senza literal, non motivato da alcun codice trovato.

## Cosa resta aperto e prossimo passo discriminante

Il riscontro decisivo è un **nuovo export MainCode** dalla macchina attuale, acquisito col medesimo metodo del 20 ottobre, per confrontare payload 4/5, slot `9A3460`, record 17 e checksum. Senza quei byte non è giustificato né correggere il BIN né ripetere il flash. Il candidato `0bb25fd6…cb324e9` resta invariato, sperimentale, NON_INSTALLARE; il vecchio `52f8714d` resta escluso. Nessun avvio AkeruOS o fotografia; circa 10% funzionale invariato; accesso NAND esteso non raggiunto.
