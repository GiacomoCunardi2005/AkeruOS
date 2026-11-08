# Indirizzi più alti nell'ASM e limite della stima RAM

20 ottobre 2026. Scansionate **6,125,576 righe**, ricostruiti tutti i 29,602,084 byte e lo SHA-256 del firmware originale. Il massimo numero esadecimale negli operandi è **0xFFFFFFFF**: non equivale alla dimensione della RAM.

[Script](../Python_Trace_Scripts/s33_scan_address_limits.py), [risultati e massimi per categoria](../Ghidra_Results/ghidra_reports/address_limits/verified_evidence.json), [tre finestre GNU](../Ghidra_Results/ghidra_reports/address_limits/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_scan_address_limits.py`. Si analizza il listato canonicoCMP3, non si rigenerano i due ASM. I gruppi numerici sono contenitori di ricerca, non una classificazione fisica della memoria.

## Cosa si può ricavare davvero

- La fine massima dei payload con base CPU candidata è **0x0128D800**, cioè 18.553 MiB dall'indirizzo zero. Questa è geometria dei payload, con overlay e fasi distinte: non è la quantità di RAM installata.
- Il getter reale `0x2696F4`, riancorato con GNU, restituisce quattro basi: `0x0F794000`, `0x0F798000`, `0x0F7A0000`, `0x0F7B0000`. La più alta di queste quattro basi è `0x0F7B0000`: il suo indirizzo non ne stabilisce dimensione o natura fisica.
- Il workspace già ricostruito occupa `[0x0F79B180, 0x0F79F180)`, **16 KiB**. Getter, due casi e literal sono ricontrollati; il raccordo completo precedente è in [origine dei buffer](S33_Origine_Celle_Buffer_e_Area_Condivisa_Stadi.md). Questo dà un intervallo software concreto, non una RAM contigua da zero.
- **Solo ipotizzando** RAM fisica lineare dazero, senza buchi o alias, la fine di quel workspace richiederebbe almeno 259,649,920 byte, circa **247.621 MiB**. Non dimostra 256 MiB installati: le ipotesi non sono verificate e potrebbe trattarsi di una finestra di memoria interna a un motore hardware.

Un indirizzo alto della memoria indica, sotto ipotesi precise, un minimo di copertura necessario. Non stabilisce un massimo della capacità: può esistere RAM non usata, indirizzata tramite calcoli o in altre banche. Viceversa un piccolo blocco fisico può essere mappato a un indirizzo numericamente molto alto. I registri hardware e le maschere numeriche non vanno sommati alla RAM.

## Massimi della scansione da trattare come candidati

| Categoria e intervallo numerico | Provenienza | Valore più alto | Riga ASM |
|---|---|---|---:|
| absolute_di, 01000000_to_0effffff | boot_main_linear | `0x010406AC` | 30976 |
| absolute_di, 01000000_to_0effffff | other_payloads_linear | `0x0C00FE01` | 3747693 |
| absolute_di, 0fe00000_to_0fffffff | boot_main_linear | `0x0FEF0348` | 390860 |
| absolute_di, 10000000_and_above | boot_main_linear | `0xFFE40044` | 390835 |
| absolute_di, 10000000_and_above | other_payloads_linear | `0x8E3C8DFD` | 3938457 |
| absolute_di, below_01000000 | boot_main_linear | `0x00428130` | 735763 |
| absolute_normal, 01000000_to_0effffff | boot_main_linear | `0x01041674` | 16997 |
| absolute_normal, 01000000_to_0effffff | other_payloads_linear | `0x0D9249AD` | 1355893 |
| absolute_normal, 10000000_and_above | other_payloads_linear | `0x66FF92FF` | 3523372 |
| absolute_normal, below_01000000 | boot_main_linear | `0x004225B8` | 1037919 |
| absolute_normal, below_01000000 | other_payloads_linear | `0x00C6A404` | 2430593 |
| pcl_loaded_word_untyped, 01000000_to_0effffff | boot_main_linear | `0x0EE6B280` | 121786 |
| pcl_loaded_word_untyped, 01000000_to_0effffff | other_payloads_linear | `0x0EFEBC2A` | 4173680 |
| pcl_loaded_word_untyped, 0f000000_to_0fdfffff | boot_main_linear | `0x0F812104` | 601696 |
| pcl_loaded_word_untyped, 0f000000_to_0fdfffff | other_payloads_linear | `0x0FDFB500` | 3994356 |
| pcl_loaded_word_untyped, 0fe00000_to_0fffffff | boot_main_linear | `0x0FFFFFFF` | 51910 |
| pcl_loaded_word_untyped, 0fe00000_to_0fffffff | other_payloads_linear | `0x0FFFFC00` | 1786518 |
| pcl_loaded_word_untyped, 10000000_and_above | boot_main_linear | `0xFFFFF77F` | 682661 |
| pcl_loaded_word_untyped, 10000000_and_above | other_payloads_linear | `0xFFFFFFFF` | 1463363 |
| pcl_loaded_word_untyped, below_01000000 | boot_main_linear | `0x00FFFFFF` | 6021 |
| pcl_loaded_word_untyped, below_01000000 | other_payloads_linear | `0x00FFFFFE` | 1458415 |

La tabella è un inventario di dove cercare, non un elenco di accessi RAM verificati. I massimi possono derivare da dati disassemblati come codice. Le parole caricate da pool e gli immediati non hanno un tipo: possono essere puntatori, maschere o numeri. Le formule PC-relative sono applicate soltanto alle tre forme riconosciute; gli altri costruttori e gli indirizzi calcolati non sono risolti.

Prossimo punto utile: ricostruire il controller memoria e le sue impostazioni di base/capienza/banchi, oppure trovare una descrizione hardware pertinente del chip RAM. Non inizializzare nell'emulatore tutta la fascia fino al numero massimo: nasconderebbe anche accessi hardware sconosciuti. Nessun file firmware modificato o accesso alla Nikon; nessuna nuova prova di boot completo o recupero. NO-GO al flash invariato.

## Continuazione: dimensione configurata decodificata — 20 ottobre 2026

Il [consumatore nel BootNAND](S33_BootNAND_DDR_ID_Dimensione_e_Checksum.md) ora chiarisce il significato software dell’ID: byte basso ×8 MiB, quindi256 MiB configurati per0120; bit8 distinto nel controller. Verificati12casi aritmeticiCPU e2checksum originali. Questo supera «ID ancora non decodificato», senza certificare RAM fisica o una banca contigua utilizzabile. Checksum BFN5A97D e test RAM sparso ricostruiti; profilo128MiB del laboratorio non modificato. Prossimo: loader e dati NAND successivi ai primi512byte.

Continuazione 6 novembre 2026: [stima 256 MiB, test PASS e profilo emulatore 256-zero](S33_Stima_RAM_256MiB_e_Profilo_Emulatore_20261106.md).
