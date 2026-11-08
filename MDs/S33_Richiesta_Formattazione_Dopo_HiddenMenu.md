# Richiesta di formattazione nella schermata normale

20 ottobre 2026 — ramo R0/R1/R4, diagnosi locale; circa 10% funzionale AkeruOS invariato.

## Osservazione dell’utente

Premendo alcuni pulsanti, incluso quello di scatto, compare la normale richiesta della fotocamera di formattare la SD. Rifiutandola, la macchina permette lo spegnimento. L’utente conferma di avere **soltanto fotografato**, senza selezionarla, la voce IQ DEBUG «Switch Require formating».

La schermata e il suo testo esatto non sono ancora acquisiti. Non attribuire quindi automaticamente l’osservazione al particolare oggetto UI descritto sotto, né dichiarare la SD guasta o la patch responsabile. Non confondere questa richiesta con ResetCameraConfirmMenu84 dell’uscita HiddenMenu.

## Risultato utile immediato

**Non confermare la formattazione e non usare «Switch Require formating» per eliminare l’avviso.** La prima può cancellare i file. La seconda richiama il backend iniziale di scrittura NAND: non è dimostrata come semplice opzione in RAM e non è una procedura di riparazione SD verificata.

MSDC ON era stato osservato sul display, ma non conosciamo il suo valore durante questo nuovo problema o un’eventuale esclusione reciproca USB/filesystem. Mancano anche una verifica della leggibilità della SD al PC e il confronto del problema con USB scollegata. Nessuna di queste cause è accertata.

## Collegamento statico della voce IQ

La voce numero13 di IQDEBUG35 ha testo9871AB e record986EB0. Il record evento9870A0 contiene500D e callback7CF828. A7CF836 viene riservato un buffer locale da512 byte; a7CF862 viene chiamata:

`1695D0(0, 1, fp-512, 0)`

Il callback non inizializza quel buffer prima della chiamata. Non è lecito sostituire il contenuto sconosciuto con zeri o FF e dedurne una cancellazione deterministica.

Il puntatore iniziale `DEVNAND:` a376168+38 è1695D0; `DEVSD:` a376018+38 è invece1684B4. Il servizio1695D0 chiama260FE4 con selettore7, quindi può passare a169564. Questa corrispondenza, già coerente col rapporto [backend SD](S33_Dispositivo_SD_e_Completamento.md), classifica la voce come **richiesta verso il percorso di scrittura NAND**, non prova di un erase fisico completato. La destinazione fisica, gli effetti transitivi e il risultato hardware non sono stati eseguiti qui.

L’utente non l’ha selezionata: non abbiamo evidenza che questa azione abbia prodotto il suo avviso. Il controllo serve a evitare di suggerirla come soluzione.

## Percorso normale candidato

L’oggetto4D, catalogato MSG_NoImageToDisp, contiene anche controlli sul supporto. Nell’ingresso7FEDA0,135A84 legge il byte366AEB e7FEDBE ne conserva una copia a89A480+8. Il risultato di137774(0) viene conservato a+9. Nell’evento2180, callback7FF350, guardie ulteriori e i controlli su+9/bit3 di+8 possono portare alla richiesta dell’oggetto7B, Setup_FormatMenuConfirm, tramite1453E4.

Nella conferma7B, il callback2180/8069B4 può richiedere l’oggetto4E, Formatting, con parametro30 o31 secondo il ramo. Questo è un collegamento eseguibile statico fra stato del supporto e conferma di formattazione; **non identifica ancora il messaggio dell’utente**, il tasto fisico che lo provoca o i valori RAM reali. Non abbiamo seguito in questa prova tutti gli scrittori di366AEB.

## Verifiche e ripresa

Comando effettivamente eseguito:

```bash
python3 Python_Trace_Scripts/s33_verify_format_prompt.py
```

Esito: `PASS_BOUNDED_FORMAT_PROMPT_CHECKS`, **6 finestre GNU ARC700 little-endian e23 controlli di istruzioni**; record eventi, pool e nomi dei backend controllati. I byte selezionati coincidono con MainCode.dmp fornito;16 payload originali verificati dagli helper. Firmware, dump e strumenti GNU ricontrollati invariati. Nessuna nuova esecuzione CPU, operazione USB o scrittura su macchina/SD.

[Script](../Python_Trace_Scripts/s33_verify_format_prompt.py), [ultima prova](../Risultati/HiddenMenu_Formattazione/latest.json), [GNU e hash](../Risultati/HiddenMenu_Formattazione/20261020T174819Z/verified_evidence.json).

**Prossimo:** acquisire il testo esatto o una foto dell’avviso; distinguere SD e memoria interna, poi controllare gli scrittori di366AEB e il contesto di ritorno a Liveview. Un confronto pratico con USB scollegata e una lettura della scheda tramite lettore separato, senza accettare formattazioni, permetterebbero di separare lo stato della fotocamera dai dati della SD. Prima di qualsiasi riparazione va preservato il contenuto leggibile. Recupero, salute SD e persistenza delle opzioni restano non dimostrati.
