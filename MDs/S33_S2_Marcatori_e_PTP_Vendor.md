# S33 — marcatori S2, CaptureLiveview e registrazione PTP aggiuntiva

Analisi statica del 18 ottobre 2026, firmware V1.1. Il dispositivo dei report hardware è V1.0. L'utente ha autorizzato nuovamente l'accesso alla fotocamera, senza poter interagire fisicamente; questa analisi ha usato soltanto file locali.

## Report PTP ricevuto

Il [report dell'utente](../outputs/S33_USB_Hardware_Evidence/CPU_RAM_USB_Recon/20261018_122849/08_ptp_operations_verified.txt) elenca 23 operazioni, 12 eventi e 7 voci di proprietà. Fra queste ultime compare `0x0000 Unknown`: è una voce riportata, non una proprietà identificata. Le operazioni `0x9801`, `0x9802`, `0x9803`, `0x9805` appartengono alla lista MTP e non vanno contate come proprietà della fotocamera.

Non è dichiarata un'operazione proprietaria non MTP. Questo limita ciò che il dispositivo pubblicizza; non dimostra l'assenza di codice per ulteriori operazioni. Il report non stabilisce una capacità di leggere CPU o RAM.

## Nuovo marcatore: `0xB00106 = S2 event`

Il decoder di nomi a `0x12CCB0` distingue le famiglie diagnostiche. Per la famiglia `0xB001xx`, il codice a `0x12CCE6..0x12CCEA` carica la base attraverso il letterale `0x12CE30 = 0x38EE5C` e indicizza con il byte basso del codice.

| Indice | Voce | Testo |
|---:|---:|---|
| 0 | `0x38EE5C` | S1 event |
| 1 | `0x38EE60` | AE start |
| 2 | `0x38EE64` | AE lock |
| 3 | `0x38EE68` | AF start |
| 4 | `0x38EE6C` | AF lock |
| 5 | `0x38EE70` | S1 display |
| 6 | `0x38EE74` | S2 event |
| 7 | `0x38EE78` | Expo start |

La voce 6 punta alla stringa `0x38F250`. Non è il vecchio marcatore `0xB80021 = S2 ISR CallBack`: sono identificatori distinti. Le parole contigue precedenti appartengono ad altre sottotabelle; numerare tutta la zona come un'unica lista avrebbe attribuito a S2 l'indice errato 20.

Nei 16 blocchi sono presenti sei letterali allineati `0x00B00106`. Tutti e sei sono caricati in `r0` nello slot di ritardo di una chiamata `bl.d 0x12CAD4`:

| Blocco | Chiamata al logger | Caricamento | Letterale |
|---:|---:|---:|---:|
| 00 | `0x1DCA6E` | `0x1DCA72` | `0x1DCCE8` |
| 00 | `0x1DD366` | `0x1DD36A` | `0x1DD5F8` |
| 02 | `0x654E9C` | `0x654EA0` | `0x654FE4` |
| 02 | `0x65B346` | `0x65B34A` | `0x65B3A4` |
| 04 | `0x7F7F5A` | `0x7F7F5E` | `0x7F7F74` |
| 04 | `0x7FA4F6` | `0x7FA4FA` | `0x7FA544` |

Il logger `0x12CAD4` accetta questa famiglia e conserva il codice nel proprio record diagnostico, visibile a `0x12CB18`. Non si tratta di sei interrupt fisici dimostrati. La ricerca non comprende valori costruiti a runtime o ingressi indiretti.

## Ingresso interno di CaptureLiveview

Continuazione: il [rapporto MMIO e coda eventi](S33_S2_MMIO_e_Coda_Eventi.md) ricostruisce il tasto logico 2 fino a `0x100/0x101` e verifica la registrazione della tabella oggetti. Con l'inizializzazione originale attiva, l'indice 4 usato nel ramo finale dell'handler `0x654CD4` seleziona CaptureImage. Il valore di stato passato rimane da risolvere.

Il descrittore `0x7833CC` contiene callback `0x6524F4` a +12 e nome `CaptureLiveview` a +20. La callback passa la tabella `0x7833EC` al lookup già ricostruito `0x169F60`, chiamato a `0x65272A`.

La riga a `0x78346C` associa **evento interno `0x100 → 0x654CD4`**. Questo handler contiene il ramo `0x654E96..0x654EAA`, che emette il marcatore S2 a `0x654E9C`, dopo controlli di stato. Non basta ricevere l'evento per dimostrare l'esecuzione di quel ramo. Il puntatore al descrittore compare inoltre nell'array a `0x3F5904`; l'effettiva selezione a runtime rimane aperta.

Gli altri due siti del blocco 04 chiamano `0x1453E4(0x82,0)` dopo il marcatore. Questo wrapper risolve un oggetto per indice con `0x14507C` e passa a `0x145180`: è un collegamento al gestore oggetti, non una prova che l'indice `0x82` selezioni CaptureImage.

## Collegamento alla catena immagini e registrazione `0x9081`

Il sito `0x1DCA6E` appartiene alla funzione che inizia a `0x1DC8B4`. Proseguendo nello stesso tratto si incontrano:

```text
0x1DCA94 → 0x1B8F24
0x1DCAAE → 0x1B9F6C
0x1DCAB8 → 0x191EA4
0x1DCACA → 0x126D48, r1 = 0
```

Sono gli stessi quattro ingressi presenti nel percorso PTP `0x100E → 0x183950`. In particolare `0x126D48` pubblica il lavoro immagini `0x0C` con callback `0x1E4C34`, già ricostruito nel [rapporto PTP/JPEG](S33_PTP_Acquisizione_e_JPEG.md). Questo dimostra la condivisione di routine nel codice V1.1, senza stabilire parametri o comportamento identici fra tutti i chiamanti.

Il puntatore a `0x1DC8B4` è caricato dall'inizializzatore `0x1DBD98`. A `0x1DBDB6` il codice invoca **`0x81E7E8(r0=0x9081, r1=0x1DC8B4, r2=1, r3=1)`**. Il registrar aggiunge una voce da 12 byte alla tabella RAM `0x519960`, scrivendo opcode a +0, callback a +4 e attributi a +8/+9, con controllo di capacità 100. È distinto dal registrar della tabella ordinaria `0x81E7B8`.

Il dispatcher seleziona questa tabella per gli opcode con bit 15 impostato: lookup a `0x81F1CA..0x81F1EE`, poi callback a `0x81EF5A..0x81EF6E`. I letterali di lookup e invocazione puntano rispettivamente a `0x519960` e `0x519964`, coerentemente con il campo callback +4.

**Limite:** esiste codice V1.1 per registrare l'operazione `0x9081`; non è stato provato che l'inizializzatore venga eseguito nella configurazione ordinaria, che l'operazione sia utilizzabile via USB, o che sia presente nella V1.0. Non è stata inviata alla fotocamera. Questo risultato non attribuisce a `0x9081` una funzione di lettura memoria.

## Riproducibilità e prossimo confine

Lo [script esistente](../Python_Trace_Scripts/s33_trace_recorder_dispatch.py) verifica hash e dimensioni dei 16 blocchi, tabelle, stringhe, sei letterali e relative istruzioni di caricamento; ricrea ELF con roundtrip identico e conserva 81 finestre. Controlla anche che i sei siti siano chiamate differite al logger. Il [JSON](../Ghidra_Results/ghidra_reports/s33_recorder_dispatch.json) conserva i campi `s2_marker` e `retained_ptp_recon`, inclusi gli hash delle fonti; il [disassemblaggio](../Ghidra_Results/ghidra_reports/s33_recorder_dispatch_disassembly.txt) conserva le istruzioni. Nessun firmware viene eseguito da questi controlli.

Il prossimo confine utile è la provenienza dell'evento interno `0x100` verso CaptureLiveview, insieme ai filtri della callback e alla registrazione del gestore fisico. Il marcatore S2 è presente anche in un percorso di registrazione PTP aggiuntiva: il suo nome, da solo, non identifica l'origine fisica. `0xB00106`, `0x100`, PTP `0x100E` e Recorder `0x4405` restano quattro codici distinti. Avanzamento complessivo invariato: circa 10%.
