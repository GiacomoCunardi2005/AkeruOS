# Nikon COOLPIX S33 — diagnostica USB di sola lettura, 24 ottobre 2026

**Esito: Nikon presente e stabile in MSDC, con un LUN Linux da 22 MiB. Nessuna nuova prova di firmware installato, accesso NAND esteso, lettura RAM o funzionamento del dumper.** Controlli autorizzati dall'utente in questa chat; la precedente regola di lavoro solo offline è superata esclusivamente per questa diagnostica non invasiva. NON_INSTALLARE resta applicabile ai candidati.

Le osservazioni nuove sono quelle del 24 ottobre: dieci campioni dalle 09:43:29 UTC, cioè 11:43:29 Europe/Rome, e raccolta complementare successiva. I riferimenti al 20–23 ottobre sono evidenze storiche, non prove rieseguite oggi. La sequenza di accensione/collegamento, la presenza fisica della SD e lo stato del display non sono stati osservati dall'agente.

## Evidenze e metodo

- [Osservazione, 10 campioni](../Risultati/Hardware/MSDC_Default/20261024T094329Z/observation.json), [collettore riusato](../Python_Trace_Scripts/s33_observe_msdc_usb_enumeration.py), relativo snapshot nella cartella dell'osservazione.
- [Diagnostica complementare](../Risultati/Hardware/Diagnostica_USB_Sola_Lettura/20261024T094549Z/diagnostic.json), con comandi, timestamp, exit code, sysfs, confronti e hash; [snapshot del collettore](../Risultati/Hardware/Diagnostica_USB_Sola_Lettura/20261024T094549Z/collector_snapshot.py), [SHA-256 degli artefatti](../Risultati/Hardware/Diagnostica_USB_Sola_Lettura/20261024T094549Z/sha256.json).
- [Descrittori USB](../Risultati/Hardware/Diagnostica_USB_Sola_Lettura/20261024T094549Z/lsusb_nikon_verbose.stdout.txt), [limite di accesso usbfs](../Risultati/Hardware/Diagnostica_USB_Sola_Lettura/20261024T094549Z/lsusb_nikon_verbose.stderr.txt), [kernel](../Risultati/Hardware/Diagnostica_USB_Sola_Lettura/20261024T094549Z/kernel_last100.stdout.txt), [mount](../Risultati/Hardware/Diagnostica_USB_Sola_Lettura/20261024T094549Z/nikon_mount.stdout.txt), [udev](../Risultati/Hardware/Diagnostica_USB_Sola_Lettura/20261024T094549Z/nikon_udev.stdout.txt).

Eseguiti inizialmente `lsusb`, `lsusb -t`, `sudo -n journalctl -k -n 100 --no-pager`, `lsblk -o NAME,SIZE,MODEL,TRAN,FSTYPE,MOUNTPOINTS`. Sudo ha restituito `sudo: a password is required`, senza chiedere password. `journalctl -k` senza sudo ha funzionato. Non sono stati cambiati permessi, driver o impostazioni del sistema.

`lsusb -v` ha segnalato `Couldn't open device, some information will be missing`: i descrittori di configurazione sono disponibili nella cache sysfs, ma non è stata effettuata una lettura diretta completa via usbfs. Nessun reset o tentativo privilegiato alternativo. Il collettore storico legge solo cache/sysfs e metadati OS; non apre una sessione PTP né il disco. Il suo campo `local_candidate` identifica il file MSDC locale storico, non la build installata.

Riproduzione della sola osservazione passiva, dalla radice del progetto:

```bash
python3 Python_Trace_Scripts/s33_observe_msdc_usb_enumeration.py --connection-sequence unknown
```

Lo snapshot complementare registra anche il confronto con questa osservazione specifica; i nomi `sda`, bus e indirizzo sono quelli di questa sessione. Prima di riusarlo su un altro collegamento occorre identificarli nuovamente. Tutti gli output vengono scritti sul filesystem del PC, fuori da mount Nikon e alberi GNU.

## Identità, interfacce e driver osservati

| Campo | Risultato hardware/OS |
|---|---|
| VID:PID | `04b0:035d` |
| Produttore/prodotto | `NIKON` / `NIKON DSC COOLPIX S33-MSDC` |
| Seriale | `0000000000000000VNA851EA41007153`, uguale alle acquisizioni storiche |
| Bus / indirizzo | `003 / 016`; sysfs `3-1.3.1` |
| Topologia | Controller `xhci_hcd`, attraverso gli hub Lenovo `3-1` e `3-1.3` |
| Velocità | High Speed, `480` Mbit/s negoziati; non è una misura di throughput |
| USB / EP0 | USB `2.00`, pacchetto controllo massimo 64 byte |
| Configurazione | Una, attiva `1`; lunghezza 32 byte, una interfaccia, alternate 0 |
| Classe interfaccia | `08/06/50`: Mass Storage / SCSI transparent / Bulk-Only |
| Endpoint dati | `0x81` bulk IN, `0x02` bulk OUT; entrambi massimo 512 byte |
| Alimentazione dichiarata | Bus powered, massimo richiesto 500 mA; consumo non misurato |
| Driver | `usb-storage` sull'interfaccia, `sd` sul disco SCSI; non UAS |
| Dispositivo SCSI registrato | `0:0:0:0`, modello `4MP-CARD`, revisione `1.00` |
| Stabilità | Dieci campioni con stessa identità, interfaccia e discendenti block; nessun errore del collettore |

I dispositivi Bison `5986:2169` e Sunplus `1bcf:2701` sono altre webcam del PC; gli hub Lenovo, Bluetooth Intel, volante Logitech, tastiera, mouse e audio hanno identità differenti. L'associazione Nikon→sda non dipende dal nome del disco: è verificata tramite la discendenza sysfs e le proprietà udev.

Non compare un'interfaccia Still Imaging/PTP `06/01/01`, né un'interfaccia vendor, seriale, rete o debug nella configurazione acquisita. Linux registra un solo LUN; non è stato inviato GET_MAX_LUN per cercarne altri. Non si può escludere una modalità dormiente o un servizio interno dai soli descrittori.

**Versione Nikon corrente non acquisita.** `bcdDevice=1.00` e revisione SCSI `1.00` non identificano MAIN/BOOT o l'hash del firmware. La documentazione conserva log PTP V1.0 e fotografie successive con MAIN1.1100/BOOT0.1380: sono osservazioni di sessioni precedenti. Non è stata aperta una sessione PTP, assente nell'interfaccia attiva, né cambiata modalità per ottenere GetDeviceInfo.

## LUN, mount e limiti della sola lettura

| Oggetto | Metadati nuovi |
|---|---|
| `/dev/sda` | 45.056 settori da 512 byte = 23.068.672 byte = 22 MiB; rimovibile, `ro=0` |
| `/dev/sda1` | Inizio LBA55, 45.001 settori = 23.040.512 byte; filesystem segnalato `vfat` |
| Mount già presente alla prima ispezione | `/run/media/jack/disk`, opzioni comprendenti `rw,relatime,flush` |
| Permessi disco/partizione | `root:disk`, `brw-rw----`; non leggibili dall'utente corrente |

Il kernel registra la connessione alle 11:37:52 locali, il disco alle 11:37:53 e, alle 11:37:54, `Volume was not properly unmounted. Some data may be corrupt. Please run fsck.` È un avviso di chiusura precedente non corretta: non una diagnosi completa di corruzione. **Nessun fsck, riparazione o lettura dei file montati è stato eseguito.**

Il log segnala anche `Asking for cache data failed` e assume write-through: non è stato interpretato come guasto NAND o errore del dumper. La registrazione del driver UAS nel kernel riguarda la disponibilità del modulo; l'interfaccia Nikon usa `usb-storage`.

Non sono stati effettuati mount, remount, unmount, eject, sync, modifiche di partizione o accessi al contenuto di `/dev/sda`. Anche un normale accesso a file su un mount `rw,relatime` potrebbe aggiornare metadati: è stato evitato. Il mount preesistente è rimasto tale. Nei contatori block acquisiti risultano zero scritture completate e zero settori scritti per sda/sda1; ciò non certifica l'assenza assoluta di modifiche autonome del firmware o di altri processi.

## Confronto con il reverse engineering

1. **MSDC/PTP.** Il descrittore d'interfaccia corrisponde esattamente a quello del template V1.1 a CPU candidata `0x3901B0`, nel payload1 verificato contro il manifest. La configurazione completa differisce in quattro byte: i due `wMaxPacketSize` sono 64 nel template statico e 512 nella configurazione High Speed osservata. La corrispondenza della classe e la differenza dei pacchetti sono misure separate; il punto runtime che adatta i descrittori non è stato dimostrato qui. Il template PTP separato è a `0x3900F0`. Fonte: [candidato MSDC](S33_USB_MSDC_Predefinito_Candidato_Offline.md).
2. **Continuità hardware.** I 50 byte cached del device+configurazione hanno SHA-256 `08081ba5216c46c427b752c0f86d7d7e5c3339e0481e28cc29a4690d419ec6b6`, identico alle osservazioni `20261020T212724Z` e `20261021T154955Z`. Coincidono seriale, capacità e geometria partizione. Bus/indirizzo e percorso fisico possono cambiare.
3. **Supporto esposto.** È coerente con il LUN allora identificato come memoria interna FAT12 tramite [doppia lettura hardware del 21 ottobre](S33_MSDC_LUN_Memoria_Interna_Dump_Doppio.md) e [inventario offline dei byte acquisiti](S33_MSDC_LUN_Inventario_FAT12_Indipendente.md). Oggi non è stato riletto il suo contenuto: non si afferma che sia identico né che una SD sia presente/assente. `4MP-CARD` da solo non identifica la SD. La [catena SCSI](S33_USB_SCSI_Callback_Dispatcher_e_Capacita_Storage.md) spiega come un profilo NAND possa produrre proprio 45.056 settori; non rende osservati i suoi parametri runtime.
4. **Service Mode.** [HiddenMenu/diagnostica USB](S33_HiddenMenu_GUI_e_Diagnostica_USB.md) e [attivazione](S33_Attivazione_Diagnostica.md) distinguono selettore MSDC `0x366B9D`, flag diagnostico `0x366B9F` e stato HiddenMenu `0x366880`. Non è dimostrato che aprire un menu abiliti nuovi endpoint o accesso RAM. Nessuna sequenza di tasti, voce diagnostica o cambio modalità è stata tentata.
5. **Candidato NAND/PC v2.** Verificati oggi soltanto dimensione e hash del [firmware.bin locale del 23 ottobre](../Risultati/USB_SCSI/Accesso_NAND_PC/container_v2_20261023T191711Z/firmware.bin): 29.602.084 byte, SHA-256 `39bdefdf9a00948463f528fc11aec36da17b5599f16340be45eacec8c369b6e4`. Il [v2](S33_NAND_PC_Candidato_V2_16_Record.md) usa 16 record e patch in place in payload9, con handler `0xE99F40`, guardia `0xE9AE00`, buffer `0xE9A2A4`. Integrità/rollback e test BOT/dispatch precedenti sono prove offline. Canarie runtime, validazione completa v2 di loader/updater e recupero restano limiti documentati. L'enumerazione odierna è compatibile anche col candidato MSDC semplice e **non identifica il v2 installato o assente**. Nessuna sonda `0xFF`, SCSI RAW o comando NAND eseguito.
6. **Dumper RAM su SD.** Il [motore cooperante](S33_Dumper_RAM_Completa_SD_Prototipo.md) ha prove host con 128 MiB sintetici, non un dump fisico. Il [lifecycle integrato](S33_Dumper_RAM_SD_Registro_Apertura_Close_e_Ownership_Integrati.md) e i [modi FAT](S33_Dumper_RAM_SD_Modi_Apertura_FAT_e_Gate_Backend7.md) avanzano l'esecuzione CPU offline, con SD/DMA e servizi modellati dichiarati. Backend7 attivo, adapter C concreto, proprietà/close, task e hook compatibile restano aperti. La diagnostica USB di oggi non modifica il valore hardware0 della tappa specifica dumper.

## Informazioni mancanti e prossimo esperimento minimo

| Informazione | Recuperabile adesso senza modificare il dispositivo? |
|---|---|
| Identità USB, endpoint, driver, capacità pubblicata e mount | Sì: cache/sysfs, udev e kernel; acquisiti |
| Stabilità e differenze rispetto ai vecchi collegamenti | Sì: campioni e confronto dei log; acquisiti |
| Versione MAIN/BOOT e build realmente avviata | Non dai metadati MSDC disponibili; `1.00` non basta |
| SD presente, geometria e contenuti attuali | Non stabiliti da questo LUN; nessun inventario SD corrente |
| RAM fisica, banchi/alias/MMIO, heap/stack e memoria propria | Non esposti da queste letture standard; restano aperti |
| NAND fisica, ID, ECC, traduzioni e salute globale | Non dimostrati da capacità SCSI o vecchi dump |
| Binding dumper, coerenza cache/DMA, completamento e close fisici | Richiedono altre evidenze e integrazione; nessuna prova oggi |
| Recupero indipendente dal firmware modificato | Non verificato; nessuna nuova garanzia |

**Prossima prova hardware consigliata: acquisizione standard, limitata al LUN già esposto, senza firmware nuovo.** Preparare prima il PC affinché quel supporto non venga montato automaticamente in scrittura; ottenere una situazione non montata e stabile senza forzare reset o scollegamenti. Il mount `rw` attuale non è stato modificato durante questa fase, anche per evitare flush impliciti non valutati.

Con identità nuovamente verificata tramite parent USB, accesso al nodo esclusivamente in lettura e privilegi disponibili, si può riusare `Python_Trace_Scripts/s33_dump_msdc_lun.py` per due passate limitate alla capacità pubblicata, confrontando copie/hash e poi analizzando FAT soltanto sulle copie del PC. Lo script è stato letto, **non eseguito oggi**. Usa un default `/dev/sda` e non applica da solo tutti i controlli di identità/mount/limite: non lanciarlo alla cieca su un altro collegamento. Le due passate passano dalla cache kernel; un hash coincidente non prova da solo due trasferimenti fisici indipendenti.

Questa prova riguarda il volume logico ordinario, non NAND RAW o regioni ulteriori; nessun comando vendor, CDB sperimentale o cambio modalità serve allo scopo. In questa sessione il nodo è inaccessibile senza privilegi e il mount è già `rw`: nessun tentativo di aggirare i due limiti. L'identità del contenuto e l'eventuale drift rispetto al 21 ottobre sarebbero il risultato verificabile successivo.

Per **i dati della SD**, un lettore separato con accesso di sola lettura verificato evita di dipendere dalla selezione LUN della Nikon; richiede però un intervento fisico e non è stato eseguito. I vecchi export BFN/MainCode possono intanto essere studiati offline per restringere mappa e versioni, senza considerarli misure dello stato attuale.

R0: nuove evidenze hardware attribuibili e riproducibili. R3/R4: nessuna chiusura di avvio, residenza o recupero; stima funzionale AkeruOS invariata. Firmware, C del dumper, alberi GNU, flash e SD non modificati dall'agente. Restano fuori dalla fase corrente installazione, esecuzione dumper, opcode diagnostici e accesso NAND esteso.
