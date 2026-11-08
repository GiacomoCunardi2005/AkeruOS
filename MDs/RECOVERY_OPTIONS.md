# Opzioni di recupero — Nikon COOLPIX S33

Data: 19 ottobre 2026. Ambito: ricerca documentale e lettura locale; nessuna operazione sulla fotocamera. Tappa R4 ancora aperta.

## Risultato

È documentato l'aggiornamento Nikon ordinario **V1.0 → V1.1**. Nelle fonti effettivamente consultate non è identificata una procedura dimostrata per ripristinare una S33 che non avvia più il menu. Non è una prova dell'assenza globale di procedure di assistenza o boot ROM.

La [pagina Nikon italiana del firmware](https://downloadcenter.nikonimglib.com/it/download/fw/193.html) indica V1.0 come versione di partenza, `firmware/firmware.bin` sulla scheda e avvio dal menu Versione firmware. Segnala anche la possibilità di rivolgersi a un centro autorizzato per l'aggiornamento. Il [catalogo ufficiale S33](https://downloadcenter.nikonimglib.com/en/products/208/COOLPIX_S33.html) data V1.1 al 14 luglio 2016. Questi elementi non documentano un recupero dopo mancato avvio, né un downgrade o la reinstallazione della stessa versione.

## Cosa è disponibile e cosa manca

| Percorso | Evidenza disponibile | Limite per il recupero |
|---|---|---|
| Aggiornamento Nikon da SD e menu | Procedura ufficiale sopra citata | Richiede che la macchina si accenda e raggiunga il menu; non è dimostrata la raggiungibilità dopo un avvio modificato fallito. |
| Centro assistenza | Nikon lo menziona per gli aggiornamenti | Nessuna promessa verificata di riparazione di firmware modificato, disponibilità del servizio, costo o conservazione delle calibrazioni. |
| Copia locale del pacchetto originale | Campione V1.1 identificato nel rapporto versioni locale | Il file distribuito per aggiornamento non è qui provato equivalente a un backup integrale della memoria installata, incluse configurazioni e calibrazioni. Conservarlo non dimostra di poterlo riscrivere a macchina non avviabile. |
| Bootloader di emergenza o combinazione tasti | Nessuna procedura S33 verificata nelle fonti consultate | Servirebbero ingresso raggiungibile indipendentemente dall'applicazione, supporto di trasporto e controlli di accettazione ricostruiti. Nessuna combinazione va inventata. |
| USB/PTP | I log storici del progetto riguardano macchina V1.0 funzionante | Non provano un trasporto di ripristino dopo brick; nessuna operazione diagnostica o di scrittura è stata eseguita per questa ricerca. |
| UART, JTAG o programmazione diretta | Ipotesi di canali da identificare | Non sono identificati qui pinout, tensioni, accessibilità, stato dei blocchi debug, protocollo o possibilità di riscrittura. Non costituiscono opzioni pronte all'uso. |

## Distinzioni da mantenere

- Il campione studiato è V1.1; i log fisici citati dal progetto dichiarano V1.0. Una correzione applicabile al campione non prova la compatibilità con quella macchina.
- La verifica matematica di RHIR/KHIR e del checksum TBIB non dimostra l'accettazione da parte dell'updater né la capacità di recupero. L'[audit precedente](../S33-sections/analysis_codex/audit_patch.py) esprime già questo limite; il relativo JSON è stato soltanto letto in questa ricerca, non rigenerato.
- Il file storico `outputs/S33_USB_Hardware_Evidence/S2_Physical_Test/recovery_20261018_122059/recovery_summary.txt` elenca due JPEG scaricati. Il nome della cartella non è evidenza di recupero firmware o sblocco della fotocamera.
- Una stringa seriale nel firmware o l'architettura ARC non dimostrerebbero da sole una porta UART/JTAG utilizzabile sulla scheda.

## Verifiche svolte e continuazione

Lette le due pagine ufficiali sopra collegate, il rapporto locale `S33_Firmware_Versioni.md`, la sezione R4 della roadmap, lo script/JSON dell'audit precedente e il riepilogo del recupero JPEG. Ricercate le parole `uart`, `jtag`, `brick`, `recovery` nelle fonti locali mirate. Il PDF italiano di aggiornamento collegato da Nikon non è stato acquisito: il browser di ricerca ha restituito errore al redirect. Le ricerche web sul recupero hanno prodotto anche omonimi estranei alla COOLPIX S33, esclusi dalle conclusioni.

Prossimo punto utile: ricostruire staticamente il percorso updater/bootloader e quali regioni effettivamente scrive, prima di presentare il pacchetto originale come ripristino. Occorre poi dimostrare un canale disponibile quando il normale menu non parte, con preservazione delle calibrazioni; questa ricerca documentale non chiude quel requisito.

Evidenza di ricerca: [recovery_research.json](../S33-sections/safety_audit_codex/evidence/recovery_research.json).

Non verificati su hardware: aggiornamento, boot di emergenza, UART/JTAG e ripristino. Rischio concreto: una modifica che impedisce il menu può eliminare anche l'accesso all'unico percorso pubblico qui documentato.

## Seguito: updater pubblico e candidato TBIB

La [nuova verifica R4](SD_UPDATE_RECOVERY_PATH.md) collega la UI pubblica V1.1 ai writer MainCode/BootCode e identifica nel TBIB un caricamento RHIR alternativo precedente al MainCode. Sono prove statiche nuove (48 finestre/145 istruzioni), integrate nel runner e nel manifest. Non certificano preservazione fisica: il pubblico può raggiungere il writer BootCode selettore0, il mapping dipende da metadati runtime e reset/ROM→copia TBIB non è dimostrato. Il candidato non è una procedura pronta di ripristino e non equivale al pacchetto pubblico firmware.bin. NO-GO invariato; nessuna azione hardware.

## Verifica successiva richiesta sulla variante CMP3

Il [nuovo controllo boot/ripristino CMP3](CMP3_BOOT_RESTORE.md) usa il campione con confronto3, verificato dai byte.25scenari P-code registrano21confini corretti e4limiti del modello; una prova isolata conferma un difetto `ld.ab` con alias nel decoder, riscontrato con GNU ARC700/QEMU. Nessuna conclusione di mancato boot va ricavata dal PC0 emulato. Nuove14finestre/71istruzioni dei backend BootCode restringono origine dei metadati e aggiornamento della mappa, ma non provano una copia recuperabile dopo interruzione. Il linguaggio non è stato modificato; firmware e hardware invariati. NO-GO flash confermato.
