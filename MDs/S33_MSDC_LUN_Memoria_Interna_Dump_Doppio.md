# MSDC: il LUN da 22 MiB è la memoria interna — dump doppio e assenza dai dump NAND

21 ottobre 2026 — R0/R3/R4. Prima acquisizione integrale via USB del LUN MSDC attivo: **45.056 settori letti due volte, identici**, SHA-256 `06a12253308fd80376bd7006c332e85425eb1fa4baac70cdbbcc0e057c5e224f`. Il LUN contiene la **memoria interna della fotocamera** (FAT12 con DCIM/101-102NIKON, NCFL), una regione NAND **non coperta da alcun dump disponibile** (NANDP1, NANDReserved, MainCode, BootCode: nessun riscontro dei suoi byte). Nessun gestore originale legge oltre questo LUN: il "resto della NAND" via usbdev resta possibile solo con l'handler RAW del candidato, la cui presenza in flash è ancora da confermare con un nuovo export MainCode.

## Prove e riproduzione

- Enumerazione: [osservazione 10/10 MSDC](../Risultati/Hardware/MSDC_Default/20261021T154955Z/observation.json), collettore `Python_Trace_Scripts/s33_observe_msdc_usb_enumeration.py`.
- Dump: [script](../Python_Trace_Scripts/s33_dump_msdc_lun.py), [diario](../Risultati/Hardware/MSDC_Default/LUN_interno_20261021T155624Z/journal.json), cartella `read1.img/read2.img/journal.json`.

```bash
sudo python3 Python_Trace_Scripts/s33_dump_msdc_lun.py
```

Lo script apre il disco solo in `O_RDONLY`, esegue due letture complete con hash per MiB e non scrive mai sul device. Autotest offline su file regolare superato prima dell'uso hardware. Comando eseguito dall'utente con sudo.

## Identità e struttura

- USB `04b0:035d`, prodotto `NIKON DSC COOLPIX S33-MSDC`, seriale `0000000000000000VNA851EA41007153`, model `4MP-CARD`; interfaccia 08/06/50 in 10 campioni su 10.
- Disco 45.056 settori/512 byte = 23.068.672 byte; MBR con unica partizione a LBA 55 da 45.001 settori, FAT12 (32 settori/cluster, 2 FAT da 12 settori, 256 voci root, media 0xF8).
- Contenuto confermato dai file montati: `DCIM/101NIKON/DSCN0144.JPG` (5.501.197 B, `c1bdeff7…`), `DSCN0148.JPG` (6.052.103 B, `bc510026…`), `DCIM/102NIKON/DSCN0865.JPG` (5.776.073 B, `875f73b7…`), `NCFL/NCMRKLST.LST` (825 B, `fd377c13…`), `DCIM/100NIKON` e `MISC` vuote. Foto datate 2015–2017: memoria interna, non SD.
- Nel dump 0144 e 0865 compaiono contigui; 0148 è frammentato (testa contigua, corpo su cluster non contigui), coerente con lettura completa da mount e dump integrale.

## La regione non è nei dump NAND esistenti

Ricerca dei byte distintivi del LUN (VBR a LBA 55; blocco interno di DSCN0144) in `DUMPS/NANDP1.dmp`, `NANDReserved.dmp`, `MainCode.dmp`, `BootCode.dmp`: **nessun riscontro**. Quindi il LUN copre una regione NAND (memoria interna utente) che il metodo di export non raggiunge: via USB si è così ottenuto il primo blocco esteso di NAND reale mai coperto dai dump. La posizione fisica di questa regione non è determinabile dai dati disponibili.

## Nessun gestore originale legge oltre il LUN

Sweep dei 18 gestori della tabella `9A33D4` (finestre chiave verificate GNU, resto su listato lineare come supporto): TUR, REQUEST SENSE, FORMAT UNIT, INQUIRY, MODE SENSE(6/10), START/STOP, noop 0x1E, READ FORMAT CAPACITIES, READ CAPACITY(10/16), READ(6/10/12), WRITE(10/12), VERIFY, e `0xFF` = noop `820B2C` nell'immagine attuale. READ(10) passa per la validazione `81FA90` e il callback LUN `[89AB7C+0x28]`/default `168F24`; le capacità derivano dai provider geometria. Nessun percorso tocca NAND grezza o indirizzi fuori LUN. Il gestore RAW `0xFF` del candidato (slot `9A3460→35BD40`) resta l'unica via, e richiede che l'immagine candidata sia effettivamente avviata.

## Limiti e prossimo passo

- Doppia lettura identica: integrità di trasporto confermata per questo LUN, non per altre regioni.
- Nessun accesso raw oltre i 45.056 settori; nessuna scrittura eseguita o proposta.
- Il passo decisivo del ramo NAND/PC resta il **nuovo export MainCode** (metodo HiddenMenu Dump2File del 20 ottobre) per stabilire se il candidato `0bb25fd6…cb324e9` è nella flash: senza di esso nessun comando RAW funzionerà e il problema è l'installazione, non la sintassi.
- Candidato invariato NON_INSTALLARE; nessun avvio AkeruOS o fotografia; circa 10% invariato; goal "accesso al resto NAND dal PC" ancora aperto.
