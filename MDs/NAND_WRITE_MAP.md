# Mappa delle operazioni persistenti e dei rischi NAND

Verifica documentale locale del 19 ottobre 2026 sul campione Nikon S33 **V1.1** (29.602.084 byte; SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`). Gli indirizzi sono CPU della mappa candidata dei payload, non offset del contenitore. Le istruzioni e i risultati qui citati sono evidenze statiche **pregresse lette in questa sessione**, non una nuova esecuzione del firmware né una verifica hardware. Nessun trasferimento degli indirizzi alla macchina V1.0 è dimostrato.

La classificazione distingue richiesta di persistenza, collegamento statico al porto MMIO e completamento fisico. Non basta l'etichetta della voce. Fonte completa dei 29 casi NAND e dei 17 casi SKY: [FUNCTION_RISK_AUDIT.md](FUNCTION_RISK_AUDIT.md); salti riancorati nei file `evidence/*case_4a_*` e `*case_4b_*`.

## Raggiungibilità

La radice `0x20` apre `0x4A` tramite evento `0x5005`, callback `0x7CC94C`, chiamata `0x7CC964 → 0x1453E4`. Apre `0x4B` tramite `0x5006`, callback `0x7CC96C`, call `0x7CC984`. Queste aperture sono distinte dalle azioni dei dispatcher `0x7D444C` e `0x7D4D94`: occorre una selezione successiva. La main usa eventi `0x5000..0x53FF`, il byte basso come indice e `item+0x14` come dato: indice visibile e dato non coincidono. Fonti: [mappa](HIDDENMENU_MAP.md), [main NAND](../S33-sections/analysis_codex/evidence/007d412c_main_4a.txt), [main SKY](../S33-sections/analysis_codex/evidence/007d498c_main_4b.txt).

L'ingresso automatico nel menu esegue callback con effetti RAM e servizi ancora aperti. Per esempio `0x7D417C` scrive guardia a `0x7D4198` e lista a `0x7D41A0`, chiama `0x12DF54`, `0x129888` e cambia modalità. Non è stata provata una scrittura NAND automatica, ma nemmeno l'assenza transitiva di persistenza. Fonte: [inizializzazione NAND](../S33-sections/analysis_codex/evidence/007d417c_nand_init.txt).

## Aggiornamento, cancellazione e partizioni

| Dato NAND / case | Catena statica e bersaglio | Rischio e limite |
|---|---|---|
| 100 / `0x7D4528` | `12A794 → 12A9FC → 12AD58 → 1EEA4C(6,buffer,0,len)` | MainCode; contenuto eseguibile persistente. |
| 101 / `0x7D4542` | `12A794 → 12AA3C → 12AE00 → 1EEA4C(0,…)` | BootCode; danno al codice necessario all'avvio plausibile. |
| 102 / `0x7D455A`; 103 / `0x7D456A` | `2FFF0C(6)` / marker `CDA24`, poi `2FFF0C(0)` | Riempimento FF seguito da writer. 103 ha case ma non voce iniziale visibile. |
| 104 / `0x7D4584` | `2FFF0C(1)`, poi `(2)` | Calibrazione: lettura preliminare e fill FF parziale; nessun ripristino provato. |
| 105 / `0x7D459E` | `2FFF0C(5)` | Area riservata/risorse; perdita persistente plausibile. |
| 106 / `0x7D45AA` | `1695D0(0,1,buffer,0) → 169564` | Settore iniziale da etichetta e argomenti; sink specifico da chiudere. |
| 118–120 / `0x7D463C..465A` | `3001D0 → 129D08`; `300208 → 3019E8`; `C9D58/1290F8/128F28/1290F0` | Restore calibrazione e restore/reset parametri: persistenza candidata, non tutti i sink espansi. |
| 121 / `0x7D466A` | `3014C0 → 1EEF6C` | Update BootNANDBase; confronto con `1ED5E4`, completamento aperto. |
| 122 / `0x7D4674` | `3016EC → 1EEAEC → 25F338` | Update BFNSetting; backend e semantica del chip incompleti. |
| 123 / `0x7D467E` | Aggiornamenti 100/101, poi `3016EC` e `3014C0` | Operazione composta: nessuna atomicità/rollback provati. |
| 124 / `0x7D46E8` | `3012F0 → 29EFC4` | Cambio partizioni candidato. |
| 125–126 / `0x7D46F6/4716` | Marker e `301E1C(1,0)` / conferma e `(0,1) → 29E8F0/16F200` | Update P1 e possibile ricreazione partizioni; catena non chiusa fisicamente. |
| 128 / `0x7D4746` | `300D0C → 12BA68 → 18AF04 → 21C420/21C698` | “Full Format Internal”: selettore distinto; mappatura fisica volume da dimostrare. |

Queste catene sono documentate con fonti per ogni caso nell'[audit precedente](FUNCTION_RISK_AUDIT.md). [Writer MainCode/BootCode](../S33-sections/analysis_codex/evidence/0012ad58_update_write_backends.txt): `0x12AD9C` è la call con selettore 6; `0x12AE4A` usa 0. [Wrapper partizioni](../S33-sections/analysis_codex/evidence/001eea4c_write_wrapper.txt): allineamento a 512 byte, lock `0x1593AC`, preparazione `0x260FE4`, call `0x1EE730` a `0x1EEAA4`, rilascio `0x1594A4`. Il lock e gli esiti non dimostrano sicurezza da perdita di alimentazione.

Nel ramo partizione 0 è collegato `0x1EE0FA → 0x2606B4 → 0x260624 → 0x25E0A4`. Il loop carica byte in un delay slot a `0x26063A`; `0x25E0B0` esegue `sth.di r0,[r1]` con pool `0x25E0AC = 0x0FF05000`. I comandi preparano `0x80/0x10` a `0x2606DA/0x260786`; `0x25DF24/4C` gestiscono bit 8/9 di `0x0FF04020`. È una prova statica di accesso a porta MMIO nel ramo di scrittura; non identifica da sola protocollo, chip, erase nativo o successo fisico. Fonti: [followup](HIDDENMENU_FOLLOWUP.md), [loop](../S33-sections/analysis_codex/evidence/00260624_storage_data_output_loop.txt), [store](../S33-sections/analysis_codex/evidence/0025e0b0_data_port_store.txt), [controllo](../S33-sections/analysis_codex/evidence/0025df24_command_enable_bits.txt).

## File e test SD

I dump NAND dati 107–117 e SKY dato 16 scrivono file. `0x30017C` apre modo 2 a `0x300194`, scrive tramite `0x12DE3C` a `0x3001B2` e chiude. Non sono operazioni di sola lettura globali. Il dato NAND 127 richiede formattazione della card con la catena del dato 128. Mapping dei volumi e durabilità restano aperti. Fonti: [dump writer](../S33-sections/analysis_codex/evidence/0030017c_dump_file_writer.txt), [audit](FUNCTION_RISK_AUDIT.md).

SKY dato 0 chiama `0x7D58D8`: apertura modo 2 `0x7D5B44`, scrittura `0x12DE3C` a `0x7D5B60`, riletture `0x12D530`, confronto `0x32E508`, ripetizione `0x7D5CDE → 0x7D59E8`. Richiede anche `0x21C420 → 0x1F2348`, codice `0x2018`, callback runtime +0x1C ancora aperta. Il nome “SD Life” non implica innocuità. Fonte: [routine](../S33-sections/analysis_codex/evidence/007d58d8_sd_life_full_code.txt), [risultati precedenti](../S33-sections/analysis_codex/evidence/storage_followup.json).

SKY dati 8 e 10 cancellano prima con `0x2FFF0C(5)`, poi passano a `0x7D52A4/0x7D581C → 0x129460 → 0x1EEA4C(5)`: fallimento dopo la prima fase può lasciare risorse perse. Dato 9 salva P1Res.bin con `0x12BD5C`; dato 15 (`BC62C(0/3/4) → BD348/1296EC`) resta candidato persistente, non provato dalla sola parola Copy. Fonti: [audit](FUNCTION_RISK_AUDIT.md), [commit risorse](../S33-sections/analysis_codex/evidence/00129460_resource_commit.txt).

## Limite e continuazione

Non è stata stabilita una mappa EEPROM separata: calibrazione e parametri sono bersagli logici; chiamarli EEPROM fisica sarebbe prematuro. Restano aperti reset `C9D84`, consumer dei toggle RAM, callback runtime, sottoalberi debug/calibrazione e completamento fisico. Prossimo controllo locale utile: chiudere identità e inizializzazione del backend del comando filesystem `0x2018`; se si emula, sostituire i sink di storage con stub senza host passthrough.

## Riverifica nella consegna complessiva

Il coordinatore ha poi rieseguito `audit_storage_followup.py`: 23 finestre GNU e 40 istruzioni controllate, con hash dei due firmware invariati. [Risultato corrente](evidence/storage_followup.json), [log](../S33-sections/safety_audit_codex/evidence/storage_recheck.log). La scansione globale dei candidati allo stato resta una prova precedente letta; non è stata rieseguita. Nessuna esecuzione storage reale. La sonda della sola istruzione è documentata separatamente in [EMULATION_RESULTS.md](EMULATION_RESULTS.md).

## Seguito: updater pubblico e candidato TBIB

La [nuova verifica R4](SD_UPDATE_RECOVERY_PATH.md) collega la UI pubblica V1.1 ai writer MainCode/BootCode e identifica nel TBIB un caricamento RHIR alternativo precedente al MainCode. Sono prove statiche nuove (48 finestre/145 istruzioni), integrate nel runner e nel manifest. Non certificano preservazione fisica: il pubblico può raggiungere il writer BootCode selettore0, il mapping dipende da metadati runtime e reset/ROM→copia TBIB non è dimostrato. Il candidato non è una procedura pronta di ripristino e non equivale al pacchetto pubblico firmware.bin. NO-GO invariato; nessuna azione hardware.
