# S33 — comandi SD, risposte e controllo originali nella catena di lettura

23 ottobre 2026, R0/R1/R4. Continuazione della [lettura PIO e dei motori originali](S33_Dumper_RAM_SD_Lettura_PIO_Motori_e_Completamento_Originali.md). La catena r/open → directory → FAT → PMSD/DEVSD → motori SD → copia CPU → close esegue ora anche il dispatcher 2E52F4, il decoder delle risposte e il controllo 25AA8C. Il test fornisce campioni ai load MMIO originali; non sostituisce più questi servizi con un risultato preconfezionato. Nessun dispositivo fisico coinvolto.

## Prove riproducibili

| Gruppo | Copertura | Evidenza |
|---|---|---|
| Dispatcher e controllo isolati | 28 comandi + 12 controlli, tutti ritornati; 15 finestre GNU, 9 istruzioni chiave | [40 casi](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Command/20261023T094241Z/verified_evidence.json) |
| Catena completa con comandi/MMIO | 16 scenari: 15 ritorni e 1 ciclo FAT interrotto; 68 finestre GNU, 21 istruzioni chiave | [16 scenari](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Command_Chain/20261023T095145Z/verified_evidence.json) |
| Regressione con esiti comando sostituiti | 13 scenari: 12 ritorni + 1 ciclo interrotto | [PIO precedente](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_PIO_Chain/20261023T095200Z/verified_evidence.json) |
| Regressioni ai tre confini superiori | 13+13+13, ciascuno 12 ritorni + 1 ciclo interrotto | [adattatore SD](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_SD_Chain/20261023T095200Z/verified_evidence.json), [callback dispositivo](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Chain/20261023T095200Z/verified_evidence.json), [lookup diretto](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Chain/20261023T095200Z/verified_evidence.json) |

Sono matrici ripetute a confini diversi, non 108 comportamenti indipendenti conclusi. I cicli interrotti non sono prove di cleanup normale. Il gruppo isolato è stato eseguito prima del raccordo; i cinque gruppi di catena sono stati eseguiti sui sorgenti condivisi finali. Snapshot, hash dei sorgenti e dei 16 payload, comando, log, traccia e finestre GNU sono conservati nelle rispettive directory.

```sh
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_command.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_command_chain.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_pio_chain.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_sd_chain.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_chain.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_chain.py
```

## Emissione e conteggi

Il costruttore 2E509C prepara il descrittore. Il dispatcher 2E52F4 seleziona il formato e chiama 25A278. Gli store halfword originali pubblicano, in ordine, comando, metà alta e bassa dell'argomento, configurazione: registri 0FF01824/828/82C/80C meno il selettore. Verificati argomento FFFFFFFF, conteggi 0/1/2/10001 e selettori 0/800.

Per 11/12 il percorso dati imposta anche dimensione meno uno, parte bassa del conteggio ed eventualmente parte alta tramite 25A39C. La geometria ordinaria del test è 512 byte: store 511 a 0FF0181C meno selettore.

Un dettaglio da non generalizzare: **lo zero iniziale a 2E5464 usa l'indirizzo assoluto 0FF01854**, caricato dal pool 2E5460, senza sottrarre il selettore. Gli store successivi di 25A39C usano invece il selettore. Con selettore 800 e celle iniziali global=AAAA/selected=BBBB, conteggio 2 produce global=0 ma selected resta BBBB; conteggio 10001 produce global=0 e selected=1. Il primo tentativo di verifica assumeva tutti gli indirizzi selezionati e ha fallito; la traccia e i byte originali hanno corretto l'assunzione. Non è una diagnosi di guasto: la relazione fisica fra i due registri non è provata. La catena DEVSD integrata usa selettore 0.

Configurazioni osservate: 11/12 tipo1 con flag1 → 61, flag0 → 21; 0D tipo1/flag1 → 41; 07/0C tipo2/flag1 → 51; comando0 tipo0/flag0 → 04. Non sono una specifica completa di ogni tipo o famiglia di comandi.

## Polling comando e tipo senza risposta

25A5F8 legge entrambi gli stati a ogni iterazione: 0FF01800/804 meno selettore. Priorità originale: primo stato bit0 → 00E00100; altrimenti bit1 → 00E00101; altrimenti bit2 → 0; altrimenti nibble basso del secondo stato nonzero → 00E00208; altrimenti ripete. Il limite **8000 è stato esaurito nel P-code** e restituisce 00E00100. Non è un tempo in millisecondi.

Il bit2 pronto prevale anche quando il secondo stato segnala errore nel nibble basso. Il writeback 25A098 rilegge il primo stato e scrive `(stato & ~maschera) | maschera`: con stato7 e priorità bit0 riscrive7. Questo non prova una semantica elettrica W1C.

**Il descrittore tipo0 può ritornare zero anche dopo errore o timeout del polling.** Il ramo 2E548E raggiunge 2E556C prima del controllo dell'errore per i tipi con risposta. Tre casi con comando0 verificano pronto, bit0 e 8000 iterazioni esaurite: risultato finale0 in tutti e tre; nel secondo e terzo caso il polling aveva restituito 00E00100. Stato precedente AABBCCDD e buffer risposta A5 rimangono invariati, senza letture della porta risposta. Zero non è quindi una garanzia generale di completamento del comando. La catena read integrata usa tipi1/2, che propagano gli errori provati.

## Porta risposta e decoder

25A3E0 esegue il load halfword a 25A3FE da **0FF01830 meno selettore**, scambia i due byte e li salva nel buffer del descrittore a +32. Nei tipi1/2 provati vengono letti due campioni. Campioni raw 0000/0600 producono byte `00 00 06 00`, quindi stato3; 0000/0800 producono stato4.

2E5234 estrae `(byte2 & 1E) >> 1` e lo pubblica nel campo stato del descrittore prima della verifica degli errori. Perciò stato3 e risultato nonzero possono coesistere. La scansione dei bit è prioritaria: byte0 bit7..0 → 00E00200..207; byte1 bit7..0 → 208..20F; byte2 bit7/6/5 → 210/211/212. Le associazioni complete provengono dai byte/pool GNU; le prove dinamiche selezionano 80/C0 nel primo byte,40 nel secondo,26 nel terzo e stati3/4. Non sono state provate dinamicamente tutte le combinazioni di bit.

## Controllo 25AA8C e bit3

L'abilitazione chiama 25A158 e imposta bit3 di 0FF01808 meno selettore, poi attende bit7 del primo stato spento. La disabilitazione lo spegne e attende bit7 acceso. Entrambi i limiti di **2000 iterazioni** sono stati eseguiti; verificati anche due campioni d'attesa seguiti dal terzo pronto.

La disabilitazione opera soltanto sui selettori0/800 e può essere saltata dai byte globali **36B242/36B243**. Il test con flag1 non modifica il registro e non interroga lo stato; l'abilitazione continua invece a operare. Il selettore400 in disabilitazione salta entrambe le azioni. Questi byte non sono il flag49 della tabella volume DEVSD.

Il ritorno osservato conserva valori grezzi: timeout enable80, timeout disable0, disable protetto1, selettore non gestito400. Non viene introdotto un contratto “0=controllo riuscito” per questa funzione. I motori originali read conservano il proprio risultato attraverso queste chiamate.

## Raccordo con r/open, FAT e chiusura

Restano i settori sintetici root100/101, data102, FAT20/21, due settori per cluster e offset PMSD2048. La preparazione riceve stato3 dalla porta risposta e lo decodifica davvero; il test non lo scrive direttamente nel descrittore. Anche comandi, risposta, polling e gate vengono eseguiti senza sostituire i relativi ritorni. I buffer dati/FAT ricevono byte soltanto dagli store PIO originali alimentati dalla porta dati.

Ogni store effettivo del comando è confrontato con la sequenza prevista: lettura single `0D,07,11`; multi `0D,07,12,0C`; errore PIO aggiunge recupero0D; errore del comando12 evita dati e stop0C e passa direttamente al recupero0D. Insieme alle sequenze si verificano numero di letture risposta, accoppiamento enable/disable, store bit3 e registro finale.

| Scenario | Comandi emessi | Halfword risposta | Campioni dati | Esito finale |
|---|---:|---:|---:|---|
| secondo settore root | 6 | 12 | 512 | record root indice17 |
| due salti FAT | 22 | 44 | 2048 | record cluster4/indice0 |
| FAT0 corrotta | 16 | 32 | 1536 | file root omonimo accettato, stato0 |
| errore polling sul comando FAT | 21 | 36 | 768 precedenti | advance00E00100, lookup01A00002 |
| errore polling sul comando dati | 18 | 30 | 512 precedenti | r/open00E00100 |
| errore nei byte risposta dati | 18 | 36 | 512 precedenti | r/open00E00200 |

Le tre nuove iniezioni verificano tre tentativi nel driver SD e l'assenza di modifica del buffer nelle operazioni fallite prima dei dati. Nei 15 ritorni normali rimangono quattro buffer liberati una sola volta e semafori FS/PM bilanciati. Nei successi l'oggetto file conserva il record corretto e blocca volume close finché vivo; con FAT corrotta conserva invece il record root errato già identificato nei rapporti precedenti.

Il ciclo FAT viene interrotto prima del dodicesimo ingresso nel motore: 34 comandi già eseguiti,68 halfword risposta,11 coppie gate complete,3072 campioni dati. Rimane un bracket PM aperto (lock12/post11), nessun ritorno o cleanup normale. Gate bilanciato dei precedenti11 motori non significa che tutta l'operazione interrotta sia stata rilasciata.

## Confine restante

Restano simulati: campioni MMIO e risposte, geometria/contesti predisposti, recupero25B63C riuscito, delay2E500C, heap/pool/clock/dirty/close ioctl3 già dichiarati. 3342A8 resta prodotto modulo2^32 modellato per MULUDW non supportato. Non sono provati FIFO, W1C fisico, cache/DMA, interrupt, scheduler o mount completo. I tipi speciali del dispatcher non attraversati dai test restano fuori copertura.

Prossimo passo offline: **lettore asincrono allineato25A83C**, oggetto2801F0, callback/attesa e proprietà del buffer; separatamente produttore del flag49 che salta il backend. Per il dumper restano mappa RAM completa, creazione esclusiva SD, wait RTOS e task/stack/hook con memoria propria. Firmware originali,dump,GNU,C AkeruOS e BIN invariati in questa decodifica. Il BIN NAND/PC è stato rigenerato separatamente su richiesta utente con contenuto invariato. Circa10% funzionale invariato, **NON_INSTALLARE**, goal aperto.

## Continuazione — chiamante read asincrono

[S33_Dumper_RAM_SD_Lettore_Asincrono_Attese_e_Uscite_Parziali.md](S33_Dumper_RAM_SD_Lettore_Asincrono_Attese_e_Uscite_Parziali.md):21scenari del corpo25A83C,servizi inferiori/eventi fixture. Verificati30controlli consecutivi senza progresso,uscite parziali dopo acquisizione e precedenza degli errori cleanup. Non trasferisce dati e non amplia il profilo filesystem integrato. Prossimo2801F0/27FCD4,28080C/281158,ownership ecallback/eventi originali. NON_INSTALLARE,nessunhardware.

## Continuazione — oggetti di ricezione originali

[S33_Dumper_RAM_SD_Oggetti_Ricezione_Acquisizione_e_Rilascio.md](S33_Dumper_RAM_SD_Oggetti_Ricezione_Acquisizione_e_Rilascio.md):18casi2801F0/27FCD4/281158/281064 e21caller25A83C collegati all'oggetto512CC8,regressione21PASS. Tre oggetti receive512CC8/512CEC/512D10 distinti dai precedenti oggetti write512C5C/512C80/512CA4;release consumaid+4 ehandle anche con errorepost. Le releasefixture precedenti non descrivono questo contratto reale. Earlycallback-error lasciarecord nonripulito,senza prova di leakglobale o avviofisico. Avvio28080C/progress266E9C,semafori/eventi e hookstop restano daeseguire. NON_INSTALLARE,nessunhardware.
