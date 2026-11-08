# Nikon S33 — mappa registri CPU, AUX e MMIO

24 ottobre 2026. **Mappa fisica incompleta; obiettivo di censimento completo ancora attivo.**
Nessun accesso hardware. GNU, firmware originali e copie laboratorio invariati.

La [mappa consultabile](../Risultati/Processor_Registers/20261024T161825Z/REGISTER_MAP.md)
consolida 64 posizioni di encoding core, 93 indici AUX con fonti distinte e
153 indirizzi MMIO esaminati. Questi numeri non contano registri fisici provati:
includono slot opzionali/riservati, definizioni di implementazioni di riferimento
e candidati da pool. Dei 153 indirizzi MMIO, 115 restano solo candidati da pool;
38 hanno accessi documentati o richieste a helper osservate nei banchi precedenti.

- [JSON con campi, fonti e limiti](../Risultati/Processor_Registers/20261024T161825Z/register_map.json)
- [CSV](../Risultati/Processor_Registers/20261024T161825Z/register_map.csv)
- [Grafo registri/fonti](../Risultati/Processor_Registers/20261024T161825Z/graph.html)
- [Audit del grafo](../Risultati/Processor_Registers/20261024T161825Z/GRAPH_REPORT.md)

## Prove nuove

Il verificatore AUX esistente passa 24 casi. La suite monitor passa 6 test.
Un nuovo harness esterno prova numeri e ritorni della API libsim. Il verificatore
di provenienza GNU passa 29 casi e ripete due prefissi originali:
Main ha 132 record LR/SR con risultato su 20 indici AUX, TBIB 11 record su 6 indici,
contenuti nello stesso insieme di 20. I segmenti ELF corrispondono ai byte del
firmware originale, SHA256
`1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`.

Tutti i 61 target guest r0–r60 passano probe con valori distinti e due sentinelle
conservate. r32–r59 restano slot opzionali del modello; r61 riservato, r62 limm e
r63 PCL non vengono trattati come normali destinazioni. Il PC debugger reg63 è
distinto dall'encoding core r63/PCL.

Una verifica indipendente ridisassembla **64 siti AUX** a partire dai PC delle
tracce, controlla indici e operazioni e riconfronta i byte ELF con il contenitore
originale. Una seconda verifica controlla **66 istruzioni/pool** delle routine
sensore, riallineando le finestre dopo i pool dati.

Comandi riproducibili, dalla radice:

```bash
python Python_Trace_Scripts/s33_inventory_processor_registers.py
python Python_Trace_Scripts/s33_verify_register_trace_sites.py Risultati/Processor_Registers/20261024T161825Z
python Python_Trace_Scripts/s33_verify_processor_register_sensor_fields.py
python Python_Trace_Scripts/s33_build_register_atlas.py Risultati/Processor_Registers/20261024T161825Z
```

Il primo e il terzo comando creano nuove directory; gli altri rigenerano soltanto
gli artefatti derivati. Le evidenze puntano anche ai verificatori e ai nuovi output
GNU conservati. Nessun simulatore è stato modificato in questo lavoro.

## Correzioni delle descrizioni storiche

Le finestre sensore storiche attraversavano alcuni pool dati senza riallinearsi
al target del salto; le vecchie asserzioni controllavano un sottoinsieme di token.
La nuova verifica dei byte stabilisce:

| Registro | Sequenza corretta nel firmware V1.1 |
|---|---|
| FF98074 | RESET e INIT usano bit 8, 2, 3, 6, 7; RESET imposta e cancella ciascun bit |
| FF98018 | riceve le scritture complete 1, 80, 100, 200, 800, 1000 esadecimali; non attribuirle a FF98000 |
| FF98000 | RESET cancella bit0; INIT imposta 0, 10, 12, 8, 9, 11, 13, 14 |
| FE800F4 | cancella bit4; low4 conserva il campo divisore; non prova frequenza fisica |

La maschera `-25 = 0xFFFFFFE7` spegne soltanto bit3/4, correggendo una frase del
rapporto iride. Il cluster DEVNAND mantiene la correzione di attribuzione storage
del 23 ottobre. I riferimenti USB FE50920/FE50010 nei test cancel sono argomenti
di helper sostituiti da fixture: non provano dereference MMIO o larghezza fisica.

I campi BCR DCCM/ICCM e TLBPD0/1 sono stati verificati sulle figure dei PDF
originali; le definizioni Linux cache/PCT sono fissate al commit riportato nel
catalogo esteso. Le varianti ARCv2 sono conservate separatamente, senza attribuirle
all'ARC700 Nikon.

## Limite nuovo della API registri GNU

La API ARC700 fetch/store delega agli accessor A5 compilati contro cpu5.h.
Nel motore corrente questi differiscono dalle semantiche guest cpu7.h.
Leggere AUX512 tramite API host arresta con `S33_AUX_UNKNOWN` e bad long jump;
il corrispondente probe guest ARC700 passa il reset modellato. Il fallimento
è conservato, non aggirato.

Sono verificati PC reg63, AUX6 reg70, STATUS32 reg61/reg74, AUX94 reg212 e
storage AUX45 reg133/AUX7ff reg2111 dopo scrittura. Il ritorno `-1` può indicare
accettazione della API: store STATUS32 restituisce `-1` ma il readback resta zero.
Non esporre una scansione cieca degli AUX nel monitor web.

## Copertura negativa e lavoro rimanente

Il censimento conserva tutti i 16 payload e TBIB in namespace separati. Nei 16
payload la disassemblazione lineare produce 4.453 candidati LR/SR in 421 gruppi,
887 con indice non risolto. Questi non diventano accessi validi senza CFG o traccia.
Il controllo OOB esistente respinge il listing lineare dell'intero TBIB: il
fallimento è conservato, senza padding o taglio silenzioso del firmware. I siti
TBIB presenti nelle tracce sono invece decodificati singolarmente con PC ancorato.

REA 6.7.0, provata in un processo separato senza cambiare la registrazione corrente,
espone 207 strumenti ma rifiuta ancora l'ELF ARC come architettura non supportata.
Hopper/Ghidra tramite REA e IDA Free non sostituiscono quindi GNU ARC per queste
prove. L'installazione/connessione IDA Free resta non completata e non viene
presentata come strumento disponibile.

Restano da confermare configurazione fisica e BCR Nikon, estensioni custom/DSP,
percorsi firmware non raggiunti, indici AUX dinamici, accessi effettivi ai candidati
MMIO e semantica fisica di FIFO/W1C, DMA/cache, IRQ e temporizzazioni. L'assenza
da una traccia non prova l'assenza di un registro. Le celle MMIO sintetiche e gli
zeri iniziali del modello non sono letture dell'hardware.

Nessun boot completo, fotografia, persistenza o recupero dimostrato. **NON_INSTALLARE**.
