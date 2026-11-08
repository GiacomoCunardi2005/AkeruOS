# S33 — lettore di settori, cache e trasferimento originale

23 ottobre 2026, R0/R1/R4. Continuazione del [lookup integrato](S33_Dumper_RAM_SD_Lookup_Integrato_e_Falso_Successo_Parser.md) e delle analisi statiche di [metadati differiti](S33_Metadati_Differiti_e_Scrittura_Inferiore.md) e [backend SD](S33_Dispositivo_SD_e_Completamento.md).

## Risultato e copertura

Il confine simulato è stato spostato dal lettore di settori fino alla callback del dispositivo. La catena ora eseguita insieme nel P-code originale è:

```text
2A3360 coordinatore → parser → 2A318C directory → 2A2D88 scanner
→ 2A1178 lettore/cache → 2A0C60 trasferimento
→ 226204 posizione → 1F3524 dispatch lettura → callback sintetica
```

La moltiplicazione `0x3342A8` resta un confine dichiarato: l'emulatore rifiuta `MULUDW` a `0x3342B4`. Il probe sostituisce il solo helper con il prodotto modulo 2^32. Le formule che lo usano sono quindi **condizionali a quel modello**, non una nuova prova della semantica DSP Nikon. Gli altri corpi sopra indicati sono eseguiti, con contesto, heap e driver di laboratorio espliciti.

| Gruppo | Casi | Evidenza |
|---|---:|---|
| Lettore/cache e consumatore del pendente | 28 | [prova](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Sector_Reader/20261023T082425Z/verified_evidence.json) |
| Trasferimento inferiore e dispatch generici | 25 | [prova](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Transfer/20261023T082950Z/verified_evidence.json) |
| Lookup fino al lettore, trasferimento sostituito | 20 | [prova intermedia](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lookup_Sectors/20261023T083018Z/verified_evidence.json) |
| Lookup fino alla callback dispositivo | 20 | [prova integrata](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lookup_Device/20261023T082950Z/verified_evidence.json) |
| Regressione lookup col precedente confine | 20 | [regressione](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lookup_Tree/20261023T083018Z/verified_evidence.json) |
| Regressione r/open e close file/volume | 7 | [regressione](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Tree/20261023T083018Z/verified_evidence.json) |

Sono matrici in parte ripetute con confini differenti, non 120 comportamenti indipendenti. I gruppi includono rispettivamente 5/8/17/22/13/18 finestre GNU verificate. I test conservano stack e guardie, verificano l'identità dei 32 byte del record restituito e non modificano i settori sorgenti sintetici. Non sono state modificate immagini firmware, dump canonici, GNU o la fotocamera.

## Lettore 0x2A1178

Firma ricostruita: `(ctx, cluster, indiceSettore, &stato, bufferUtente, numeroSettori)`.

| Condizione | Percorso locale verificato |
|---|---|
| cluster=0 | posizione=`[ctx+0x5C]+indice`; deve essere strettamente minore di `[ctx+0x60]` |
| cluster diverso da zero | posizione=`(cluster−2)*byte[ctx+0x12]+[ctx+0x60]+indice`, con helper di prodotto simulato |
| posizione oltre word `[ctx+0x28]` | rifiuto; il confronto ammette l'uguaglianza al limite |
| bufferUtente nonnullo e numeroSettori>1 unsigned | inoltra selettore5, posizione, conteggio e buffer; successo ritorna bufferUtente |
| altri casi | sceglie il buffer interno secondo word `[ctx+708]` |

La geometria del test isolato è root100/data104/quattro settori per cluster; il limite è scelto dal caso. Non è la geometria fisica della Nikon.

Il ramo bulk controlla qui **solo la posizione iniziale**: nel caso limite iniziale104 e conteggio3 il trasferimento inferiore riceve `(104,3)`. Questo non prova un accesso fisico oltre capacità: il backend reale può imporre ulteriori limiti. Con conteggio1 il buffer utente viene ignorato e si usa il buffer interno. Nel caso modo3 esplicito il corpo restituisce il valore preimpostato di r7 senza scrivere lo stato; non è dimostrato che un chiamante reale usi un modo fuori0/1/2.

| Modo | Buffer | Posizione memorizzata | Comportamento |
|---|---|---|---|
| 0 | word ctx+712 | word ctx+752 | legge un settore; aggiorna posizione solo dopo successo |
| 1 | word ctx+436 | word ctx+432 | hit se stessa posizione e ctx+0x34 diverso da1; altrimenti flush del pendente, poi lettura |
| 2 | word ctx+716 | word ctx+748 | legge un settore; aggiorna posizione solo dopo successo |

Un hit modo1 può restituire il buffer con flag pendente ancora1, senza provare la scrittura. Il valore1 di ctx+0x34 forza il reload; il valore2 del caso non lo forza. Un errore di flush nel miss interrompe la lettura e conserva il pendente; se il flush riesce ma la lettura fallisce, il pendente è già zero e la posizione precedente resta invariata.

Gli offset `.as` sono scalati: `107/108/109` corrispondono a `428/432/436`, non alla lista file a ctx+100/count halfword+108. Questa distinzione evita di sovrapporre strutture differenti.

## Consumatore del pendente 0x2A10F4

Se word ctx+428 è nonzero, il corpo passa a `2A0C60` selettore10, posizione ctx+432, conteggio1 e buffer ctx+436. Azzera il flag soltanto su risultato zero.

Dopo questo tratto, anche quando la scrittura fallisce, confronta ctx+752 e ctx+748 con ctx+432. Per ogni uguaglianza copia **halfword[ctx+0x10] byte** dal buffer436 al rispettivo buffer712/716 tramite `225618 → AD920`. Nei test sono512 byte, con contenuti e guardie verificati. Le due copie avvengono anche a pendente inizialmente0: non sono subordinate a una nuova scrittura riuscita.

Un indirizzo rifiutato dal lettore attraversa comunque questo consumatore. Il lettore memorizza prima l'esito del flush, poi lo **sovrascrive con `0x01A0000D`**. Due casi provano flush riuscito e flush fallito, con flag finale rispettivamente0 e1 e copie interne in entrambi. Non si può quindi dedurre «nessuna scrittura tentata» dal solo errore di indirizzo del lettore.

## Trasferimento 0x2A0C60 e conteggio residuo

La nuova prova esegue anche `2A0C14` per la scrittura, `1FA090` e `1F3524` per i dispatch generici, `226204` per la posizione e `1F2348` per i controlli. Le callback del dispositivo, ai soli indirizzi di laboratorio0F000200/300, restituiscono valori scelti; non trasferiscono dati sulla SD.

Con ctx+0x44 nonzero, posizione e conteggio sono inoltrati nelle unità del dispositivo. Con campo zero, la posizione usa halfword[ctx+0x10] e il conteggio viene shiftato di halfword[ctx+0x48]; il test512/shift9 riceve posizione3584 per indice7 e conteggio1024 per due unità. Anche questa moltiplicazione usa il confine DSP esplicito.

Entrambi i rami tentano la callback dati al massimo una volta nel corpo esaminato. È verificato il residuo al punto originale comune `2A0CFE`, oltre a conteggio, buffer, posizione e numero di chiamate:

| Esito callback sintetica, richiesta2 | Errore handle | Esito wrapper |
|---|---:|---:|
| 2 trasferiti | nonzero preesistente | 0 |
| 1 trasferito | 0 | 0, residuo1 |
| 0 trasferiti | 0 | 0, residuo2 |
| −1 | 0 | 0, residuo2 |
| 1 trasferito oppure−1 | 01A00021 | 01A00021 |
| 3 trasferiti | nonzero | 0, residuo−1 |
| callback mancante | scritto dal dispatcher:102C | 102C |

Queste combinazioni sono **prove del contratto locale**, non la dimostrazione che il driver SD reale produca una risposta parziale senza errore. Confermano però che stato0 di questo wrapper, preso da solo, non certifica un trasferimento completo. La vecchia conclusione statica sul residuo è ora riprodotta nel P-code originale.

Il posizionamento originale scrive handle+0x10 e pulisce bit3 di handle+8. Il risultato della callback controllo7 viene scartato prima del ritorno0. Con ctx+848=0 il wrapper esegue i controlli2015 e2016 nell'ordine `2015 → 7 → 2016`; i loro errori non interrompono il trasferimento nei casi eseguiti. Con count0 la preparazione e i controlli restano eseguiti, ma non viene chiamata la callback dati. Verificata anche la traduzione errori1A02→01A0000F,1A03→01A0000E;1A04 resta invariato.

## Lookup integrato e buffer riutilizzati

L'albero sintetico mantiene root/DIR/sub. La nuova geometria è root100/data101/un settore per cluster: cluster2→101 e3→102. Il current-directory0x123 viene tradotto in390 e mappato esplicitamente sulla root, solo nel laboratorio. Il dispositivo è configurato in unità blocco; ctx+848=1 disabilita2015/16 in questa matrice, mentre il controllo7 è eseguito dal dispatcher originale.

Percorsi osservati alla callback inferiore:

| Ricerca | Posizioni e modi |
|---|---|
| root, scratch0 | 100@2 |
| root, scratchA5 | 100@0 |
| DIR/file | 100@0 →101@1 |
| DIR/sub/file | 100@0 →101@1 →102@1 |
| relativa, scratch0 | 390@2 |

Il record finale risiede ora nei buffer del contesto, riutilizzati fra letture. Il probe verifica puntatore, metadati cluster/indice e identità byte del record contro il settore sorgente, oltre alle guardie di tutti e tre i buffer. Il passaggio tra directory non distrugge il risultato prima del suo consumo nei percorsi provati.

Resta riproducibile il falso successo OOM257: parser fallito con scratch517 azzerato → nome vuoto → record libero index2 → stato0. Ora il percorso attraversa anche lettore, wrapper, posizione e dispatch originale. L'accettazione successiva dar/creazione dell'oggetto resta provata dalla regressione separata con lettore sostituito; **non è ancora una singola esecuzione r/open→driver→close**.

## Limiti e passo successivo

Cache esterne21B2CC/21A454 e fastpath2A29B4 restano disabilitate; heap/pool e terminazione2ABC68 sugli errori sono fixture. Nessuna catena FAT multisettore, long-name o ottimizzazione DCIM è coperta. Le identità dei buffer provano solo la durata interna ai percorsi eseguiti, non concorrenza, DMA o ownership di un nuovo task.

Prossimo: eseguire l'avanzamento originale2ABC68 e la catena FAT1F25D8 su più settori, poi eliminare l'ultimo confine simulato tra r/open, driver e close; confrontare il contratto di conteggio/errori delle callback PM/DEVSD prima di usare stato0 come garanzia del dumper. Restano mappa fisica completa, creazione esclusiva, stack/hook/task e recupero. Nessun cambiamento al BIN o al C AkeruOS: circa10% funzionale invariato, **NON_INSTALLARE**.

Riproduzione:

```sh
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_sector_reader.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_transfer.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_lookup_device.py
```

Le evidenze contengono snapshot dei sorgenti, hash dei16 payload, log headless, tracce e finestre GNU. Il primo tentativo del probe settori in082342Z si arrestò sul MULUDW non implementato;082425Z è il risultato con confine di prodotto dichiarato. Le rigenerazioni successive dei gruppi condivisi incorporano le nuove verifiche di identità e i profili opzionali; i risultati storici restano conservati.

## Continuazione — FAT multisettore e r/driver/close

[S33_Dumper_RAM_SD_Catena_FAT_Multisettore_e_Identita_File.md](S33_Dumper_RAM_SD_Catena_FAT_Multisettore_e_Identita_File.md):34casi avanzamento/decoder,13catena multisettore e7r/driver/close. Il precedente limite del lettore sostituito nella sequenza r è superato per l’albero con un settore per directory; la FAT multisettore è provata separatamente. Nuovi casi errore FAT perso, voce0 che riporta alla root, ciclo limitato e root esaurita. Close libera tre buffer ma non ne azzera le celle. Driver/DSP/pool dichiarati; nessun hardware o BIN.
