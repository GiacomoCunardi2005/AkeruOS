# Default MSDC: confronto hardware PTP, MSDC e rimozione della SD

**Continuazione corrente21ottobre:** [S33_NAND_PC_Parser_Buffer_Privato_e_Contenitore_Offline.md](S33_NAND_PC_Parser_Buffer_Privato_e_Contenitore_Offline.md). Parser e bufferprivato integrati, contenitoreoffline NON INSTALLARE; Nikondevice033 nuovamenteMSDC22MiB alle08:55UTC. Le condizioni di assenza e i limiti del prototipo descritti sotto sono checkpoint precedenti.

**21ottobre08:20UTC:** [nuova verifica](S33_USB_BulkOnly_Transazione_RAW_e_Adattatore_Offline.md) con10campioni senzaNikon rilevata. È distinta dalla precedente confermaMSDCdevice30/22MiB; il funzionamentoMSDC osservato non viene revocato. `latest.json` segue l’ultima raccolta, non implica la stessa condizione delle raccolte storiche.

20 ottobre 2026 — R0/R3/R4. Nuova osservazione hardware fornita dall’utente e rilevata sul computer, successiva alla preparazione del [candidato MSDC](S33_USB_MSDC_Predefinito_Candidato_Offline.md). Non sostituisce le prove statiche o certifica il recupero.

## Aggiornamento: MSDC osservato dopo il secondo aggiornamento

L’utente riferisce una seconda installazione e identifica il file come quello appena verificato per SHA-256 sulla SD: candidato **af65ab0e…3544**. La sequenza acceso/spento prima di collegare questa volta non è specificata; non trasferire automaticamente quella della prima prova. Neppure il messaggio di completamento della seconda installazione è stato confermato separatamente. [Dichiarazioni dell’utente](../Risultati/Hardware/MSDC_Default/20261020T212010Z_second_update_user_report.json).

**Questa volta la Nikon espone realmente un’interfaccia Mass Storage.** Non è soltanto il nome del prodotto:

| Controllo | Risultato dopo la seconda installazione riferita |
|---|---|
| VID:PID e percorso |04b0:035d,3-9,bus003/device028 |
| Prodotto |NIKON DSC COOLPIX S33-MSDC |
| Classe/sottoclasse/protocollo |**08/06/50**, coerenti fra sysfs e descrittori cached |
| Driver interfaccia |**usb-storage** |
| Disco discendente dalla Nikon |sda, modello4MP-CARD; parentela sysfs verificata |
| Prima lettura lsblk, con SD |119,1GiB, sda1 exFAT montata in/run/media/jack/disk |
| Dopo rimozione SD riferita dall’utente |sda0B, nessuna sda1; stessa interfaccia MSDC |

La [prima raccolta MSDC](../Risultati/Hardware/MSDC_Default/20261020T211922Z/observation.json) comprende10campioni sempre08/06/50. I primi **cinque** contengono sda e sda1, gli ultimi cinque soltanto sda: la rimozione avviene durante la raccolta. Il `lsblk` finale di quella stessa raccolta mostra già0B; non va presentato come conferma di capacità nonzero per tutti i10campioni. La capacità iniziale e il mount provengono dal comando immediatamente precedente, conservato come [trascrizione dell’output di sessione](../Risultati/Hardware/MSDC_Default/20261020T211922Z_initial_command_context.json), con provenienza esplicita.

Una [seconda raccolta dopo la rimozione](../Risultati/Hardware/MSDC_Default/20261020T212009Z/observation.json) conferma10campioni MSDC, sempre stesso dispositivo e driver, soltanto sda e **capacità0** letta per campione da sysfs. L’[indice hardware corrente](../Risultati/Hardware/MSDC_Default/latest.json) punta a questa condizione senza scheda. La rimozione non ha causato una ri-enumerazione PTP durante la finestra osservata.

Il collettore ora distingue MSDC/PTP e registra capacità e parentela dei nodi block. Nome del file installato e schermata completamento sono parametri espliciti: non vengono più dedotti automaticamente dalla presenza del candidato locale. Il modo di collegamento resta `unknown` in queste due raccolte.

```bash
python3 Python_Trace_Scripts/s33_observe_msdc_usb_enumeration.py --reported-installed-file S33_USB_MSDC_DEFAULT_OFFLINE_NON_INSTALLARE.bin
```

Comando eseguito due volte, exit0, nessun errore;13artefatti per raccolta con hash. Soltanto enumerazione, descrittori cached e metadati Linux: nessuna sessione PTP, lettura di settori o scrittura intenzionale dell’agente sulla SD. **Non sono stati letti file attraverso MSDC prima della rimozione**, quindi integrità delle letture/scritture di contenuti, espulsione, riconnessione, comportamento di tutti gli avvii e recupero fisico restano da verificare. Non trasformare questo successo di enumerazione in certificazione completa del firmware.

I vecchi risultati PTP sotto rimangono osservazioni della prima installazione riferita e di una sequenza diversa/non confrontabile: la causa del cambio non è isolata. L’hash corretto del file SD non è un readback flash né prova dell’esecuzione del byte modificato. Il candidato locale e i suoi backend restano invariati; circa10% funzionale AkeruOS invariato.

## Prima installazione riferita: osservazione PTP storica

L’utente riferisce di avere installato **`S33_USB_MSDC_DEFAULT_OFFLINE_NON_INSTALLARE.bin`**, con messaggio di aggiornamento completato. Riferisce inoltre di avere **acceso la fotocamera prima di collegare il cavo USB**.

La rilevazione Linux trova la Nikon in **PTP**, senza dispositivo di archiviazione associato:

| Campo | Valore osservato |
|---|---|
| VID:PID | `04b0:035d` |
| Prodotto | `NIKON DSC COOLPIX S33-PTP` |
| Percorso USB | `3-9`, bus003/device026 durante il campionamento |
| Interfaccia | **classe06 / sottoclasse01 / protocollo01** |
| Velocità dichiarata da sysfs | 480 |
| Campioni | 10, distanziati di circa1secondo |
| Dispositivi block discendenti dalla Nikon | Nessuno |
| Errori del collettore | Nessuno |

Il risultato si fonda sulla classe dell’interfaccia e sui descrittori binari memorizzati dal kernel, non soltanto sul nome del prodotto. Questi descrittori coincidono con i campi dell’interfaccia in sysfs in tutti i campioni. Non è stata osservata un’interfaccia MSC08/06/50 né un disco Nikon.

Un controllo separato `fuser -v /dev/bus/usb/003/026` ha indicato il processo utente `gvfsd-gphoto2` con il dispositivo aperto. Non è stato arrestato o modificato. Non viene attribuita a quel processo la causa della classe PTP: questa osservazione non dimostra una selezione della modalità da parte del client.

## Spie riferite dall’utente e confronto col manuale

L’utente aggiunge: spia superiore accesa fissa, spia chiamata «del flash» verde e probabilmente lenta, schermo spento. Sono osservazioni riferite, non misure ottiche o fotografia del dispositivo. [Registrazione separata](../Risultati/Hardware/MSDC_Default/20261020T210756Z_led_user_report.json).

Il [manuale Nikon ufficiale](https://download.nikonimglib.com/archive2/BaNzv00IB5UX02SDox925rKD0D79/S33RM_%28En%2905.pdf), già conservato localmente, distingue i contesti: in ricarica il verde lento segnala batteria in carica; verde rapido segnala impossibilità di ricarica. Nel contesto fotografico il lampeggio della spia flash può invece indicare carica del flash (pagine stampate9/23/87). Il verde probabilmente lento durante USB è compatibile con la prima spiegazione, ma non è una diagnosi certa né dimostra MSDC. Schermo spento e spia superiore fissa non bastano per attribuire un blocco del firmware.

È stata ripetuta la raccolta con la sequenza di collegamento specificata nel comando: anche il secondo gruppo di10campioni resta PTP. L’indice corrente punta al secondo gruppo; il primo `20261020T210615Z` è conservato.

## Identità e limiti dell’installazione

Il candidato locale conserva dimensione29.602.084byte e SHA-256 **`af65ab0e66781c1a1036ab2349700e9d2110c6618738b02208da8b83c8813544`**. L’utente identifica questo nome come file installato. **Non sono stati riletti i byte della flash o del codice runtime**: il messaggio riferito e l’enumerazione non dimostrano da soli che l’istruzione modificata sia stata applicata ed eseguita.

Alla prima raccolta era dimostrata una connessione PTP della Nikon dopo l’installazione dichiarata, in quella sequenza di avvio. Allora non era ancora stata osservata la modalità MSDC; la seconda installazione riferita ha successivamente prodotto l’osservazione MSDC documentata in apertura. Restano possibili, senza attribuire ancora una causa, mancata applicazione effettiva, percorso che non passa dall’inizializzatore studiato, override successivo o altro ordine di lettura dei descrittori.

I test precedenti mantengono il loro valore per i rispettivi modelli e finestre; non vanno presentati come una prova del risultato hardware desiderato. La disponibilità dei backend originali e un avvio riuscito non dimostrano il percorso di recupero in caso di interruzione o firmware non avviabile.

## Controlli eseguiti

```bash
python3 Python_Trace_Scripts/s33_observe_msdc_usb_enumeration.py --connection-sequence powered-on-before-usb
lsusb -d 04b0:
lsblk -o NAME,TYPE,SIZE,TRAN,VENDOR,MODEL,FSTYPE,LABEL,MOUNTPOINTS
fuser -v /dev/bus/usb/003/026
```

[Collettore](../Python_Trace_Scripts/s33_observe_msdc_usb_enumeration.py), [indice](../Risultati/Hardware/MSDC_Default/latest.json), [osservazione e hash](../Risultati/Hardware/MSDC_Default/20261020T210756Z/observation.json), [descrittori cached iniziali](../Risultati/Hardware/MSDC_Default/20261020T210756Z/sample_00_3-9_cached_descriptors.bin), [lsusb Nikon](../Risultati/Hardware/MSDC_Default/20261020T210756Z/nikon_lsusb.txt), [metadati block del collettore](../Risultati/Hardware/MSDC_Default/20261020T210756Z/block_metadata.txt).

Il collettore legge soltanto sysfs/descriptors già disponibili nel kernel e metadati di enumerazione Linux. Non apre una sessione PTP, non invia opcode Nikon, non legge settori grezzi della SD e non scrive sulla fotocamera. Il primo `lsusb/lsblk` e il controllo `fuser` sono osservazioni aggiuntive della sessione, distinte dai file generati dal collettore. Nessun codice GNU modificato.

## Confronto proposto dopo la prima prova e continuazione

La proposta formulata dopo la prima rilevazione era confrontare con un collegamento **da fotocamera spenta**, senza accensione manuale o tasti tenuti premuti: spegnere normalmente, scollegare USB, poi ricollegare USB e rileggere l’enumerazione. La sequenza della successiva connessione MSDC non è stata specificata: non considerare eseguito questo confronto controllato. Non avviare altri aggiornamenti, reset o formattazioni per questo confronto.

Se anche quella condizione rimane PTP, servono identificazione del firmware effettivamente in esecuzione e prove sui suoi override/letture iniziali; non estendere automaticamente la patch invertendo tutti i rami. La [nuova prova locale del manager freddo](S33_USB_Manager_UI57_Argomento_Timer_e_Dispatch.md) verifica ora richiesta57, store4401→oggetto+18 e dispatch originale dopo pop; il collegamento con i chiamanti di avvio e il runtime resta aperto. Recupero fisico ed esposizione SD restano non dimostrati; circa10% funzionale AkeruOS invariato.

## Verifica del file MSDC sulla SD — 20 ottobre 2026

Su richiesta dell’utente, letto in sola lettura `/run/media/jack/disk/firmware/firmware.bin`: **29.602.084 byte**, SHA-256 **`af65ab0e66781c1a1036ab2349700e9d2110c6618738b02208da8b83c8813544`**. Coincide con il candidato locale MSDC; nessun file della scheda modificato. Prima confronto mediante `sha256sum`, poi verifica riprodotta con [script](../Python_Trace_Scripts/s33_verify_msdc_sd_hash.py), comando `python3 Python_Trace_Scripts/s33_verify_msdc_sd_hash.py`, esito `MATCH`, exit 0. [Evidenza](../Risultati/Hardware/MSDC_Default/Verifica_SD/20261020T211409Z_sha256.json). Copertura: file integrale su SD e candidato locale, controlli di stabilità dimensione/mtime durante lettura.

La scheda è montata da `/dev/sdb1`, exFAT, in un dispositivo USB Generic MassStorageClass: non è prova di enumerazione MSC della Nikon. L’identità del file sulla SD non è un readback della flash né prova dell’esecuzione della patch. Prossimo punto: confronto di enumerazione da fotocamera spenta e identificazione del firmware effettivamente in esecuzione; nessun nuovo aggiornamento eseguito.

## Controllo finale delle prove

[Audit locale](../Risultati/Hardware/MSDC_Default/20261020T212009Z_final_cpu_and_hardware_audit.json): hash di tutti i903+828artefatti CPU e dei13+13artefatti delle due raccolte hardware, input dei verificatori, conteggi/classi/driver/partizioni e26collegamenti locali controllati. Rilettura dei10campioni PTP storici conferma06/01/01 senza disco; non è una nuova connessione PTP.

Il [confronto binario dei descrittori](../Risultati/Hardware/MSDC_Default/20261020T212009Z_descriptor_template_comparison.json) evita un’identità troppo forte: la configurazione cached di32byte ha gli stessi campi del templateMSC a3901B0, eccetto le due word delle dimensioni pacchetto endpoint,64nel template e512osservati (offset22/29). Verificato su tutti i20campioni MSDC. Il servizio che produce questa differenza non è stato seguito; non dichiarare una copia byte-identica del template o dedurne l’esecuzione della patch.

## Continuazione — raccolta storica da22MiB, analizzata il21ottobre2026

Il [rapporto SCSI](S33_USB_SCSI_Callback_Dispatcher_e_Capacita_Storage.md) raccorda la raccolta già presente [20261020T212724Z](../Risultati/Hardware/MSDC_Default/20261020T212724Z/observation.json): device29, MSDC08/06/50,45056settori512,22MiB e nome4MP-CARD. È successiva e distinta dalle raccolte device28 con rimozioneSD e capacità0 sopra. Nessuna nuova osservazione hardware. L’handoff riferisce assenzaSD e FAT; i metadati di questa raccolta non certificano questi due aspetti. Il firmware contiene un percorsoNAND che restituisce la medesima capacità con profiloF0/classe8 eD.E4=324; ID e selezione runtime restano da provare. Il nome4MP-CARD da solo non dimostra SD, perché dipende dall’indice passato aINQUIRY. Candidati eNO-GO invariati.

## Nuova verifica richiesta dall’utente —21ottobre2026

Confermato nuovamente **MSDC operativo**: Nikon04b0:035d, productS33-MSDC, device30,08/06/50 eusb-storage per10campioni; sda45056settori512,22MiB. [Osservazione](../Risultati/Hardware/MSDC_Default/20261020T225849Z/observation.json), [verifica del mountvfat](../Risultati/Hardware/MSDC_Default/20261020T225849Z/mounted_volume_verification.json). L’utente conferma aggiornamentoMSDC già installato; non è stato riletto l’hash in flash. Nessuna operazione dell’agente su settori, impostazioni o memoria del dispositivo. Il [nuovo checkpoint](S33_Accesso_NAND_PC_Inizializzazione_Buffer_e_Nucleo_Sola_Lettura.md) prosegue verso le altre regioni NAND; il disco22MiB non dimostra quell’accesso.
