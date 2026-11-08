# NAND dal PC: prima prova hardware, FF senza dati e dispatch del candidato

21 ottobre2026 — nuova osservazione hardware dopo l'installazione dell'ultimoBIN riferita dall'utente, confermata da lui come completata e seguita da riavvio. **MSDC eINQUIRY funzionano; il comando RAW non restituisce dati.** Il comportamento osservato è compatibile col gestoreFF originale vuoto e differisce dal nuovo handler nei casiCPU verificati. Non attribuiamo ancora la causa a un aggiornamento fallito o a uno specifico scrittoreRAM.

## Evidenze hardware e provenienza

- [Enumerazione e permessi](../Risultati/Hardware/NAND_PC/20261021T143459Z/observation.json), [prima lettura riferita](../Risultati/Hardware/NAND_PC/20261021T143459Z/reported_first_raw_read.json).
- [Risultato diagnostico originale](../Risultati/Hardware/NAND_PC/20261021T143459Z/probe/probe.json), [confronto strutturato](../Risultati/Hardware/NAND_PC/20261021T143459Z/comparison.json).
- [Client diagnostico](../Python_Trace_Scripts/s33_nand_pc_probe.py), [lettore pagina](../Python_Trace_Scripts/s33_nand_pc_read.py).

Dopo un primo controllo senza Nikon, il nuovo controllo mostra USB04b0:035d, prodottoS33-MSDC, bus3/device55, interfaccia08/06/50 e driverusb-storage. Il discoNikon èsda:45.056settori,23.068.672byte/22MiB; partizioneFAT montata. Non inferiamoSDpresente/assente da questa capacità o dal nomeCARD.

L'agente non può aprire il disco:O_RDONLY fallisce conEACCES e sudo non interattivo richiede autenticazione. Il successivo tentativo dell'agente resta nella faseautenticazione e termina senza comandi aldispositivo. L'utente esegue nel proprio terminale il lettorepagina con privilegi amministrativi; il traceback riferisce **residuo2112 di2112**. Il client rifiuta il risultato e non conserva un filepagina valido. L'identità viene verificata sul descrittore effettivamente aperto.

La diagnostica successiva, anch'essa eseguita dall'utente, salva ilJSON locale letto e confrontato dall'agente. Effettua soloINQUIRY eFF con magicAKRN volutamente errato, direzioneIN. Questa seconda richiesta non richiede una paginaNAND: nel candidato, prima del controllo magic può essere interrogata la geometria software sotto mutex, ma il nucleo non arriva alla lettura della pagina. Nessun comando di scrittura/flash o reset è stato emesso dai programmi.

|Richiesta|CDB|StatusSCSI/host/driver|Residuo|Byte ricevuti|
|---|---|---|---:|---:|
|INQUIRY|120000002400|0/0/0|0|36|
|FF con magicerrato|ff584b524e0100000000000000000000|0/0/0|2112|0|

La rispostaINQUIRY contiene prodotto4MP-CARD e revisione1.00; non è un'identificazione della patch. Nessunsense viene restituito dalFF. Lo statusbuono non prova il trasferimento: qui il residuo dimostra che non sono arrivati datiRAW. La precedente affermazione«nessuncomando hardware» resta valida per i checkpointoffline, ma **non** per questa nuova sessione, nella quale l'utente ha eseguito le richieste indicate.

## Controprova con la tabella presa dal BIN reale

- [Verificatore](../Python_Trace_Scripts/s33_verify_usb_bot_readonly.py), [manifest31casi](../Risultati/USB_SCSI/Accesso_NAND_PC/bot_candidate_dispatch_20261021T144136Z/verified_evidence.json), [risultati](../Risultati/USB_SCSI/Accesso_NAND_PC/bot_candidate_dispatch_20261021T144136Z/cases.json).

```bash
python3 Python_Trace_Scripts/s33_verify_usb_bot_readonly.py --main-extension --candidate-dispatch
```

L'opzione nuova usa il payload5 estratto dal candidato corrente e verifica che il recordFF a9A3460 contenga35BD40. Il test **non scrive quel puntatore fra una transazione e l'altra**. Controlla inoltre che il codicehandler ricompilato coincida col prefisso del record17 e che ilhookparser corrisponda alBIN. Le altre sostituzioni diUSB/controller/mutex restano fixture dichiarate; gli oggettiLUN e la geometria sono input espliciti di laboratorio, nonRAM letta dalla macchina.

31casi superati con parser/BOT/dispatcher originali, più256lunghezze delparser già previste dal verificatore. Sono inclusi un profiloLUN tipo2 e due scenariCARD/tipo1 con flagpronti forniti daltest. Il testCARD valido invia2112byte; magicerrato eNANDnonpronta produconoCSWstatus1 e residuo2112. Il contestoCARD, da solo, non riproduce la rispostabuona senza dati quando la tabella contiene il puntatore candidato.

Il baseline storico `original_ff_in` ha inveceCSWstatus0 e residuo2112. La routineoriginale820B2C è `j_s.d [blink]` con `mov_s r0,0` nel delay slot, senza invio dati. La somiglianza col risultato fisico è quindi sostenuta sia dai byte originali sia da una provaCPU. **Compatibilità comportamentale non equivale a readback del puntatore.**

I log precedenti delverificatore non vengono riscritti. Il nuovo run ha un indice distinto`bot_candidate_dispatch_latest.json`, senza sostituire il riferimento30casi usato dalbuilder.

## Cosa è stabilito e cosa rimane aperto

Confermato: macchina nuovamenteMSDC, trasportoINQUIRY funzionante, FF ricevuto come comandoSCSI completato senza dati, nessuna paginaRAW acquisita. Confermatooffline: la tabella presente nelBIN conduce al nuovo handler e rifiuta ilmagicerrato nei contesti provati.

Non dimostrato: quali byte delBIN siano ora inNAND/RAM, che il puntatore9A3460 runtime sia35BD40, che ilMainCode avviato provenga dalla sorgente aggiornata o che una copia successiva abbia ripristinato dati precedenti. Non trasformare la conferma umana«completato e riavviata» in un hashflash verificato, né l'assenza di dati in una diagnosi di NAND guasta.

Il prossimo riscontro discriminante è il contenutoMainCode attuale o il recordcallbackruntime. Il progetto ha già ricevuto in passatoMainCode.dmp dall'utente: un nuovo export acquisito con lo stesso metodo consentirebbe di confrontare payload4/5, record17 e relativi checksum, ma non viene qui prescritta una nuova sequenzaHiddenMenu o effettuata un'altra installazione. Senza questi byte non è giustificato correggere ilBIN scegliendo una delle cause ipotizzate.

IlBIN SHA256`0bb25fd6603488e30d41ac6ad96f4fe4e8fe5e838deda7cfc7e9c6ab7cb324e9` resta invariato e sperimentale. Nessun avvioAkeruOS o fotografia dalla nuova applicazione; circa10% funzionale invariato. AccessoNANDesteso non raggiunto; la nuova prova hardware è negativa rispetto al funzionamento atteso delcomando.
