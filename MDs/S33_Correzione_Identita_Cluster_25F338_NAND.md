# Correzione: il cluster 25F338 appartiene ai percorsi NAND verificati

23 ottobre 2026 — analisi offline V1.1. **L'attribuzione del cluster `0x25CBxx..0x260Dxx` e della porta `0x0FF05000` a un «protocollo MCU dell'obiettivo» non è sostenuta dalle prove.** Gli stessi corpi sono raggiunti dal driver originale **DEVNAND**, dai lettori delle partizioni e dall'updater del firmware. La loro interpretazione operativa deve ripartire dal sottosistema storage/NAND. Non usare i byte00/10/30/50/60/70/80/D0/FF come comandi ottici o i metadati P1IDSTR come posizioni/tempi dell'obiettivo.

Questo corregge l'attribuzione semantica, senza cancellare i byte, i call site e i risultati aritmetici verificati nei rapporti storici. Non stabilisce il wiring elettrico del chip né esclude in assoluto usi alternativi della periferica. **Non invalida le prove indipendenti sull'iride GPIO, sugli eventi MCUCTRL e sui dispatcher service-request**, che hanno percorsi differenti.

## Nuova verifica riproducibile

```bash
python3 Python_Trace_Scripts/s33_verify_nand_cluster_identity.py
```

- [Script](../Python_Trace_Scripts/s33_verify_nand_cluster_identity.py).
- [Manifest](../Risultati/Storage/NAND_Cluster_Identity/20261022T231229Z/verified_evidence.json), [10 finestre GNU](../Risultati/Storage/NAND_Cluster_Identity/20261022T231229Z/gnu_verified.txt).
- [Ricostruzione logica precedente](S33_NAND_Mappa_Logica_e_Ricostruzione_Integrale_Export.md), [manifest storico](../Risultati/Dump_fotocamera/Partizioni_Logiche/20261020T155718Z/verified_evidence.json).

Il controllo corrente verifica16payload, identità raw del recordDEVNAND, nove call site, tre campioni NAND/export da2048byte e hash degli input. Non esegue CPU o controller, non riscrive GNU e non rilegge la fotocamera. Il manifest storico della ricostruzione integrale viene verificato e citato, **non dichiarato rieseguito**.

## Collegamento dal nome originale DEVNAND

La tabella volume Main contiene il record a **0x376168**, stringa inline **DEVNAND:** a+8 e callback **0x168F24** a+0x34, word0x37619C. Non è una ricerca del solo nome di un file o una vicinanza nel listato: la callback è letta dal record originale e i successivi rami/call site sono controllati nelle finestre GNU allineate.

Il percorso condizionale verificato comprende:

```
record DEVNAND 0x376168
  callback +0x34 = 0x168F24
    0x168F76 → 0x168EAC
      0x168F18 → 0x168CEC
        0x168D3A → 0x168BBC
          0x168C1E → 0x25F338
```

Le funzioni contengono gate, gestione errori e percorsi alternativi: il grafo prova un percorso software, non che ogni avvio o ogni lettura percorra tutti questi siti. Lo stesso `0x25F338` è chiamato anche dal lettore logico **0x1ECB0C**, a **0x1ECB52**. Quel lettore usa descrittore corrente, sentinelFFFF e quantità di unità512byte per pagina; il comportamentoFF è già stato eseguito nel laboratorio NAND precedente.

## Raccordo con l'aggiornamento del Main

La routine **0x12AD58**, già verificata come updater Main, a **0x12AD94** imposta il selettore6 e a **0x12AD9C** richiama **0x1EEA4C**. Il wrapper a **0x1EEAA4** chiama **0x1EE730**; il ramo per selettore nonzero a **0x1EE990** chiama **0x1EDED8**. Il medesimo updater rilegge tramite **0x1ECD6C** a0x12ADBC e confronta il contenuto tramite0x32E508.

Queste routine erano state descritte anche come «switch comandi obiettivo», con campiP1IDSTR detti cumulativi o parametri MCU. Il raccordo al contenuto del firmware, alle partizioni e al driverDEVNAND rende **non giustificata quell'interpretazione ottica**. I numeri dei campi e le formule restano byte verificati; il loro significato va ricondotto al layout storage prima di progettare nuove chiamate.

Il dizionario di comandi e le fasi512+16/2048+64 erano inoltre già presenti nelle prove del [lettore raw](S33_NAND_ECC_Integrita_e_Limite_Errori_Export_Raw.md). Qui non viene attribuito un nome elettrico ai singoli strobe sulla base di uno standard esterno: la correzione poggia prima sui chiamanti originali e sui contenuti dei dump.

## Tre riscontri diretti sui dump attuali

Sono stati ricontrollati gli hash di NANDP1 e dei tre export contro la mappa precedente. Per ciascuno si usa il primo gruppo fisico indicato dalla mappa e si confrontano i primi2048byte dati del record2112byte:

| Export | ID logico iniziale | Gruppo fisico esportato | Confronto nuovo |
|---|---:|---:|---|
|BootCode|1|1|2048byte identici|
|MainCode|165|146|2048byte identici|
|NANDReserved|16|285|2048byte identici|

Sono **campioni nuovi limitati**, non una nuova certificazione dei40.501.248byte della ricostruzione storica. Mostrano comunque che la numerazione logica e i record/spare discussi in quel cluster hanno un riscontro storage concreto; non sono telemetria dello zoom dedotta dal nomeMCU.

## Correzioni da applicare alla lettura dei rapporti precedenti

- «Porta MCU obiettivo0FF05000» diventa **porta usata dai percorsi NAND verificati; wiring fisico ancora da attribuire**.
- «Comando/risposta MCU, posizione, tempi, budget ottico» non è un significato provato per i campi dei descrittori0x36B254/0x50F420/0x50F52C. Usare nomi neutri o quelli storage sostenuti dai rispettivi consumatori.
- La ricerca di un wrapper iris fra i chiamanti25F338 era basata sull'attribuzione errata. Le prove successive che individuano l'iride in GPIO0FF04024 bit3/4 sono separate e non richiedono quella pista.
- Le cartelle e i nomi `Lens_MCU_Interface`/`s33_verify_lens_*` sono conservati per la provenienza: **il loro nome non costituisce evidenza del sottosistema**. I manifest storici non vengono riscritti per fingere una nuova certificazione.

Per proseguire offline sul dumper: mantenere il [contratto SD appena verificato](S33_Dumper_RAM_SD_Handle_Errori_e_Chiusura.md), chiudere la stabilità dei backend/creazione esclusiva e la mappa RAM. Per l'ottica: ripartire dai percorsi GPIO/eventi realmente raccordati, senza reintrodurre il cluster NAND come protocollo lente. Nessun hardware o nuovo firmware installabile; circa10% funzionale invariato.
