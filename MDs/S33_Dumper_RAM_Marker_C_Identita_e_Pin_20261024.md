# Dumper RAM — identità del marker e pin FAT controllati dal C compilato

24 ottobre 2026. Implementato `akeru_nikon_v11_sd_marker_check` in
`AkeruOS/nikon_v11_sd_marker.c/.h`: **14 scenari CPU PASS** con controllo C
compilato ARC, apertura in lettura e close superiori Nikon originali.
Nessun accesso alla fotocamera, nessun BIN pronto. **NON_INSTALLARE**.

È il controllo di identità necessario alla sessione SD, non ancora la callback
`armed` completa né l'adapter che crea e scrive il dump. Il chiamante deve avere
aperto `B:\AKERUDMP.ON` con `12CE8C(path,0x11,&file)`, possedere il wrapper e
mantenerlo vivo durante controllo e sessione. Il port write/close già verificato
conserva il puntatore nativo per il cleanup successivo.

## Contratto controllato

Il controllo rifiuta il puntatore nullo o l'errore wrapper+0xC, verifica callback
del dispositivo `1F43AC/1F48A4`, etichetta `B:`, contesto e backend FAT noto
1/6/12. **Backend7 è rifiutato prima di interpretarne il privato come FAT.**
FAT16/32 sono ammessi dal predicato software ma non eseguiti nei nuovi scenari,
che usano backend1/FAT12. L'etichetta B: non prova da sola l'identità fisica
di una SD inserita; il raccordo al dispositivo sottostante resta necessario.

Il C controlla il marcatore del semaforo `6C77736D`, esegue wait originale
`23ECA4` su contesto+388 e, sotto quella sincronizzazione, verifica:

- backend invariato tra quelli ammessi, ready1 e wrapper volume collegato
  allo stesso dispositivo, con almeno un oggetto file elencato;
- oggetto privato con magic `4D465356`, modo r0 e directory padre/root0;
- record FAT copiato a privato+12 con nome breve esatto `AKERUDMPON `,
  senza attributi directory o volume e senza errore sul wrapper.

Rilascia con `23EE48` e ricontrolla il marcatore del semaforo. Restituisce1
per identità valida,0 per rifiuto,-1 per errore di sincronizzazione. Non apre,
crea, scrive o chiude file. Il controllo identifica la copia del record
restituita dal filesystem; non promette di rilevare la successiva rimozione
del marker senza un nuovo lookup e non certifica persistenza fisica.

Compilazione: **688byte text/rodata, data/BSS0**, nessuna rilocazione SDA.
Gli indirizzi di caricamento del laboratorio non sono una collocazione
proposta sulla fotocamera.

## Prove che cambiano il prossimo passo

| Scenario | Evidenza |
|---|---|
| Marker normale e readonly | C restituisce1; il file r vivo blocca reconfigure225A60 e close volume1F46C4 con01A00010 |
| Marker assente | Open superiore originale01A00002, nessun wrapper pubblicato |
| Directory al posto del marker | Open originale01A0000E |
| Allocazione parser257 nulla, scratch iniziale0 | Open superiore originale0 con wrapper vivo, record vuoto e task-error01A00006; **C restituisce0** |
| Nome, root, modo o magic diversi | C rifiuta ciascun caso; campi ripristinati soltanto nel laboratorio prima del cleanup |
| Backend7 | Privato reso deliberatamente non leggibile nel modello: C rifiuta senza dereferenziarlo |
| Ready0 / file-error | C rifiuta; campi ripristinati per il close del laboratorio |
| Magic semaforo alterata all'ingresso wait | Wait originale fallisce dopo aver consumato il token: count0; C restituisce-1 senza close |
| Magic alterata all'ingresso post | Post originale restituisce0 e count1, ma magic resta invalida; C restituisce-1 tramite controllo indipendente |

I due ultimi casi sono guasti sintetici dello stato del laboratorio, non guasti
osservati sulla Nikon. Dopo l'errore il test verifica che il file resti posseduto,
poi ripara **esplicitamente il solo modello** per consentire cleanup e controlli
di bilanciamento. Il C applicativo non esegue quella riparazione.

**Su -1 il futuro task deve conservare file e stato e interrompere la sessione.**
Non chiudere o ritentare alla cieca: un wait fallito non prova che il token sia
rimasto disponibile e il successivo close potrebbe attendere lo stesso semaforo.
Questa proprietà deve arrivare fino alla durata del contesto del task.

Ogni scenario verifica zero create `2AC2B4`, zero write superiore, zero emissioni
PIO/DMA e tutti110settori del modello invariati, oltre a ownership heap/wrapper/
oggetti, semafori e nesting critico dopo cleanup. Il lookup, scanner e copia
del record sono originali: non è una fixture che restituisce direttamente
un record valido per il nome richiesto.

## Riproduzione e limiti

```bash
make -C AkeruOS ram-dump-sd-marker-verify
make -C AkeruOS ram-dump-sd-io-verify
make -C AkeruOS build/nikon_v11_sd_marker.o
```

Runner condiviso `Python_Trace_Scripts/s33_verify_ram_dump_sd_io_port.py`, ingresso
`s33_verify_ram_dump_sd_marker.py`, probe `ProbeDumpSDMarker.java` nella directory
`S33-sections/analysis_ghidra/scripts`. Manifest, snapshot, hash16payload e sorgenti,
log/link/listati e traccia: `Risultati/Runtime_Kernel/RAM_Dumper_SD_Marker/latest.json`.
La regressione separata del port conserva i propri7scenari.

Come nel lifecycle precedente: kernel/contesti/registro montati predisposti,
heap/pool/clock/cache e dispositivo SD/MMIO/DMA/DSP dichiarati dal modello.
Wait/post, apertura/lookup, lista file e close eseguono il firmware originale;
il checker esegue il nuovo C compilato. Padding16byte del decoder dopo il
modulo appartiene alla memoria del laboratorio. Nessun byte Nikon modificato.

Tentativi precedenti conservati: corretta l'invocazione del close-volume nel
probe usando il suo wrapper volume; corretta l'aspettativa sul post con magic
invalida, che restituisce0. Solo il PASS finale viene pubblicato come latest.

Restano da completare: sessione `armed/open_new` con lookup ripetuto coerente,
guardia backend/contesto/PMSD e creazione esclusiva, durata dei file trattenuti
sugli errori; mappa fisica completa RAM e integrazione/residenza task/launcher.
Il pin è verificato sulle due rotte originali citate, non su ogni possibile
scrittore concorrente. Nessun update completo per tutta la RAM ancora verificato.
