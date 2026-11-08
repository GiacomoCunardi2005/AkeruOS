# Nuove prove salvate prima dello stop — 19 ottobre 2026

Lavoro sospeso su richiesta dell'utente dopo il salvataggio. Le prove sono statiche sul campione V1.1; nessuna funzione Nikon è stata eseguita e nessun firmware è stato modificato.

## SD Life: scrittura persistente richiesta

La voce SKY con dato0 entra in `0x7D58D8`. A `0x7D5B44` apre un file con modo2 e nome costruito dal formato `%s\Test%d.log` (pool `0x7D5D48 → 0x98CE85`). A `0x7D5B60` chiama la scrittura `0x12DE3C`; a `0x7D5BC8/0x7D5C84` rilegge con `0x12D530`, confronta con `0x32E508` a `0x7D5CAA` e può ripetere dal salto `0x7D5CDE → 0x7D59E8`. Il contatore a `0x899BA4` viene incrementato a `0x7D5CD4`. Classificazione aggiornata: **P, richiesta di scrittura persistente**, con completamento fisico non provato.

La routine usa anche il percorso `A:` e i messaggi `Format card ...` / `Format Err=%X`; chiama `0x21C420` a `0x7D5A12`. Quest'ultima inoltra la richiesta `0x2018` a `0x1F2348`, che chiama indirettamente il campo+0x1C della tabella del dispositivo. L'endpoint runtime di questa richiesta resta da risolvere: la prova di scrittura file non dipende dall'interpretazione del messaggio di formato.

Fonti: [GNU della routine](../S33-sections/analysis_codex/evidence/007d58d8_sd_life_full_code.txt), [coda dopo il pool](../S33-sections/analysis_codex/evidence/007d5d80_sd_life_tail.txt), [JSON con stringhe e chiamate](../S33-sections/analysis_codex/evidence/storage_followup.json).

## Collegamento al livello MMIO

Nel ramo di aggiornamento partizione0: `0x1EE0FA → 0x2606B4 → 0x260624 → 0x25E0A4`. La routine `0x260624` carica byte dal buffer a `0x26063A` e li passa nel delay slot al writer; `0x25E0B0` esegue `sth.di r0,[r1]`, con r1 dal pool `0x25E0AC = 0x0FF05000`.

Il wrapper comandi `0x25CB3C` usa lo stesso porto tramite `0x25E064/0x25E070`; il chiamante prepara0x80 a `0x2606DA` e0x10 a `0x260786`. `0x25DF24/4C` modificano i bit8/9 del controllo `0x0FF04020`. Sono istruzioni statiche e accessi espliciti: sostengono la categoria F, possibile scrittura NAND/flash. Non provano il modello del chip, la temporizzazione o il completamento di erase/program.

Fonti: [caricamento byte e invio](../S33-sections/analysis_codex/evidence/00260624_storage_data_output_loop.txt), [store MMIO riancorato](../S33-sections/analysis_codex/evidence/0025e0b0_data_port_store.txt), [controllo comandi](../S33-sections/analysis_codex/evidence/0025df24_command_enable_bits.txt).

## Stato di attivazione: ricerca nei16payload

Scansione separata dei16payload, comprese le residenze sovrapposte11–15: un solo candidato di chiamata diretta al setter `0x129904`, a `0xC5DE8`, verificato nuovamente con r0=1; unica occorrenza LE32 del pointer `0x366880` nel pool `0x12991C`.

Tre coincidenze del pattern halfword-swapped del setter nel blocco09 non dimostrano chiamate. La scansione lineare produce anche falsi salti da dati; non esclude scrittori indiretti, gp-relative o indirizzi calcolati. Non è una prova che lo stato resti sempre1 dopo il boot.

Fonti: [ricerca riproducibile](../S33-sections/analysis_codex/sweep_activation_references.py), [risultati e limiti](../S33-sections/analysis_codex/evidence/activation_reference_sweep.json), [writer riancorato](../S33-sections/analysis_codex/evidence/000c5ddc_writer_reanchored.txt).

## Callback di ingresso, uscita e navigazione

| Menu / evento | Callback | Classe locale | Prova e limite |
|---|---|---|---|
|4A /4405|0x7D417C|R + U|Store guardia+4 a7D4198 e pointer lista a7D41A0; chiamate12DF54/129888 e cambi modalità. Effetti transitivi non tutti chiusi.|
|4A /4406|0x7D4330|R + U|169FBC(1),143AFC(1C); chiusura non certificata come priva di effetti.|
|4A /440C|0x7D4354|R + U|23D478 e azzeramento flag a7D43EC; renderer non chiuso.|
|4A /0580|0x7D4400|R + U|7D4928, poi byte contesto+8 da1 a2 a7D4424.|
|4A /0480|0x7D442C|R + U|1453E4(20,0) a7D4444; ciclo vita dell'oggetto successivo.|
|4B /4405|0x7D49DC|R + U|Preparazione lista e riscrittura etichette aitem+0C; chiamate e cambi modalità da chiudere.|
|4B /4406|0x7D4C5C|R + U|169FBC(1),143AFC(1C), analoghi a4A.|
|4B /440C|0x7D4C80|R + U|23D478 e azzeramento flag a7D4D18.|
|4B /0580|0x7D4D2C|R + U|7D5240, poi byte contesto+6 da1 a2 a7D4D50.|
|4B /0480|0x7D4D58|R + U|Apre20 sotto guardia provenienza; altrimenti evento4002/dato16.|
|4A/4B default|0x20E814|U|Delega alla tabella comune; effetti transitivi non chiusi.|

R indica modifiche RAM osservate; U conserva gli effetti dei chiamati ancora aperti. L'ingresso nei menu non è certificato come privo di effetti persistenti.

**Correzione della sintesi precedente:** il nome “chiusura file” attribuito a `0x12DF54` non era provato. Il corpo osservato modifica flag del contesto, chiama `0x5FE90C` e programma un evento; è ora descritto come routine di flag runtime, con effetti transitivi aperti. `0x129888` costruisce uno snapshot INFO nel buffer fornito, senza provare un reset della memoria persistente.

## Controlli effettivi e punto di ripresa

Eseguiti `python3 S33-sections/analysis_codex/sweep_activation_references.py` e `python3 S33-sections/analysis_codex/audit_storage_followup.py`:16identità payload e16roundtrip ELF;23finestre e40istruzioni controllate; stringhe, pointer, loop file e store MMIO verificati. [Evidenza del secondo controllo](../S33-sections/analysis_codex/evidence/storage_followup.json). I due hash firmware sono rimasti invariati.

Alla ripresa: risolvere l'endpoint runtime della richiesta2018 e gli effetti dei callback di inizializzazione/chiusura. Se si passa al simulatore, intercettare le richieste storage. Nessuna compilazione dell'emulatore svolta. Nessun processo di analisi resta da attendere.
