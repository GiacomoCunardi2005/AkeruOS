# Dumper SD: registro, apertura superiore e proprietà degli handle

23 ottobre 2026 — R0/R1/R4. **17 scenari CPU ritornati**: i13 casi file/FAT/controller precedenti ora attraversano il registro dispositivi, l'apertura superiore e il close superiore originali; quattro nuovi casi verificano proprietà e rilascio sugli errori. La prova resta offline, **NON_INSTALLARE**.

- [Evidenza principale](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Lifecycle/20261023T192759Z/verified_evidence.json), [trace](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Lifecycle/20261023T192759Z/trace.txt), [GNU verificato](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Lifecycle/20261023T192759Z/gnu_verified.txt):31finestre,29istruzioni asserite,10sorgenti con snapshot/hash.
- [Probe](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDFileLifecycle.java), [runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_file_lifecycle.py).
- [Regressione13 casi callback](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Write/20261023T192829Z/verified_evidence.json):PASS dopo l'estrazione del setup/scenari condivisi. Nessuna modifica al dumper C o a GNU.

Riproduzione dalla radice:

```bash
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_file_lifecycle.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_file_write.py
```

## Catena eseguita

Il banco conserva la [scheda FAT sintetica](S33_Dumper_RAM_SD_File_FAT_Creazione_Scrittura_Close_e_Riapertura.md), con110settori,512byte/settore,2settori/cluster e partizione PMSD a offset2048. Aggiunge questi corpi originali:

1. `2A3C5C(name,open,close,read,write,control,delete,privateCtx)` registra il dispositivo B: sotto il semaforo kernel+334. L'allocatore è fixture; `268EE4`, inizializzazione dei44byte, callback, lista e contatore sono originali.
2. `12DBFC(path,3,&file)` seleziona n; `12CE8C(path,0x11,&file)` seleziona r e altro selettore r+. Resolver B:, semaforo volume, controllo di stato, ricerca nei60slot e pubblicazione del risultato sono originali.
3. `1F21F8(path,mode)` trova il dispositivo nel registro, rilascia il mutex, alloca il wrapper32byte e invoca il callback `1F43AC`. Creazione, collisione e lookup continuano nei corpi FAT originali.
4. `12DE3C → 1FA090 → 1F4958 → 21A4B8 → 2A0D70/2A0C14 → PMSD/DEVSD → motori SD`, con gli stessi errori,PIO e DMA modellata del gruppo precedente.
5. `12D604(&file)` esegue i controlli3038/3015 tramite `1F2348/1F56B4`, poi `1F22C0 → 1F48A4/21AD30`, libera il wrapper e azzera slot/cella quando raggiunge quel ramo.
6. Il primo contesto viene distrutto; un nuovo contesto/registro riapre soltanto la scheda salvata nel modello. `1F3524` rilegge contenuto e dimensioni; segue close superiore.

Il controllo3038 ha un risultato ignorato dal chiamante superiore; non trasformarlo in una garanzia di sincronizzazione. La fixture ioctl3 resta distinta dai controlli3038/3015 eseguiti.

## Identità e ABI

| Elemento | Stato nel banco e corpo originale |
|---|---|
| Registro dispositivi | head=kernel+328, count halfword=kernel+330, mutex=kernel+334 |
| Record44byte | +8 nome conservato come puntatore; +C open,+10 close,+14 read,+18 write,+1C control,+20 delete,+24 contesto |
| Wrapper file |32byte, indirizzo di laboratorio0200F000; allocazione/liberazione controllate con guardie |
| Oggetto privato FAT |0200E000; lista contesto+100 e count+108, pool originale chiamato tramite fixture |
| Cella del chiamante |0200F600; appartiene al banco, non una regione proposta per il firmware |
| Slot volume | primo a376078,60celle da4byte; riga B:376018 |
| Handle volume | riga+58=376070 |
| Semaforo volume B: | id1A0000D, record374108, token+28; constructor/wait/post originali |

Le chiamate del banco verificano ritorno,SP e registri callee-saved ARC700. Le callback del registro sono quelle originali. Questo non misura un frame CPU d'interrupt né ricostruisce il boot/mount completo.

## Quattro nuovi errori di proprietà

| Caso | Risultato verificato |
|---|---|
|60slot già occupati |12DBFC→1A00032 prima dell'allocazione wrapper; cella0, tabella invariata, nessun oggetto privato |
|Allocazione scratch517byte nulla |12DBFC→1A00006; wrapper allocato/liberato1/1, nessuna pubblicazione di handle/slot, nessun oggetto privato |
|Handle volume assente prima di3015 |1F2348(NULL,3015) originale→FFFFFFFF; wrapper,oggetto privato,slot e cella restano vivi. Ripristinato l'handle volume, un secondo close libera ciascun oggetto una volta |
|Contesto non pronto al close |ready+40=0→1A0000C: wrapper,slot,cella consumati ma oggetto privato FAT ancora nella lista,count1,pool1/0 |

Il terzo caso inietta esplicitamente lo stato allaCPU12D692, dopo il resolver e prima del load riga+58. Non sostituisce un ritorno del controllo e non sostiene che questa condizione sia stata osservata sulla Nikon. Gli assert controllano la proprietà **prima** del retry, non soltanto il risultato finale. Nel quarto caso ready=0 è un secondo fault esplicito di stato: il ritorno è regolare, ma l’oggetto privato trattenuto resta un esito negativo, non cleanup riuscito. Tutti e quattro i casi preservano i110settori byte per byte, non emettono storePIO/DMA e ripristinano i token dei mutex e il livello critico. Solo il quarto conserva deliberatamente un oggetto privato: tale proprietà viene asserita e non nascosta dalla distruzione del banco.

**Correzione per l’adapter:** cella azzerata e wrapper liberato non bastano a provare che il filesystem abbia rilasciato ogni risorsa. Nel caso ready0 non è lecito ritentare sul vecchio wrapper già liberato; occorre conservare il contesto e fermare nuove catture. Non viene eseguito un cleanup diagnostico extra per far apparire bilanciato il risultato.

Il close con erroreE00100 del callback, già presente nei13casi, raggiunge invece il ramo che consuma wrapper,slot,cella e oggetto privato. **Il solo codice d'errore del close non indica se l'handle sia ancora posseduto.**

## Correzione del risultato FAT dopo errori write

Il close superiore aggiunge il flush3015 che mancava al gruppo callback. Dopo sei errori con conteggio0 — PIO bit2/bit3,comando,completamento finale,timeout asincrono,status4 — la FAT salvata contiene **FAT[2]=FF7**. La directory dichiara ancora2048byte, ma la catena percorribile dal parser indipendente contiene soltanto1024byte. Il frammentato corto conserva il suo caso precedente FAT[4]=FF7.

Il parser host esamina tutte13immagini, ricava geometria/entry/catena dai byte e confronta i byte disponibili con il pattern atteso. Non inventa la seconda metà del file quando la catena termina male. `fsck.fat -n`:

- 4 positivi: existing-rplus,new-exclusive,new-tail513,new-async→exit0;
- 7 negativi strutturali attesi: i sei sopra più fragmented-short→exit1/bad cluster;
- nessuna immagine modificata dal verificatore.

Una rilettura Nikon di1024byte può riuscire nonostante il resto della catena sia invalido: non presentarla come verifica dell'intero file dichiarato. Stato write0/count0/fileError0 e count pieno/fileError1A00006 restano riprodotti. Il timeout conserva81risvegli e8100tick originali su9tentativi motore.

## Implicazioni per l'adapter

`ram_dump.h` richiede che il suo close consumi l'handle esterno anche su errore. Non è lecito equipararlo a una singola `12D604`: il fallimento prima di3015 può lasciare una proprietà Nikon viva. Servono stato privato dell'adapter e quarantena dell'handle trattenuto, senza cancellarlo, ritentare una nuova cattura o liberarne il contesto mentre è ancora posseduto dal filesystem. Un retry deve usare lo stesso handle conservato e distinguere proprietà consumata/non consumata; con wrapper consumato ma oggetto privato trattenuto deve invece fermarsi, senza dereferenziare memoria già liberata.

L'open esclusivo richiede inoltre backend e guardia del volume verificati: il n/backend1 qui provato non diventa esclusivo per backend7. Il successo write richiede conteggio ed errore del file, non il solo stato0. Questi vincoli precedono l'associazione ad AkeruOS; non è stato aggiunto un binding hardware.

## Confini e tappe

Restano predisposti geometria/mount e contesto kernel. Heap/pool,clock,cache17FAA4,delay2E500C,recovery25B63C/query25BF3C e ioctl3 sono fixture. I datiPIO seguono gli storeCPU originali; le copieDMA sono modelli hardware governati da puntatori/conteggi programmati dal codice originale. Eventi,callback,deadline e rilascio sono originali, ma B2D50/frameCPU e consegna IRQ sono astratti. Nessuna persistenza o RAM fisica provata.

Stime per tappe offline di peso uguale, non sicurezza o percentuale di firmware funzionante:

| Area | Tappe | Limite aperto |
|---|---:|---|
|Filesystem |88% (7/8)|aggiunta sync/close superiore e proprietà; insieme completo errori/modi/backend resta parziale |
|Write SD |75% (6/8)|cache,recovery/query originali e hardwareDMA aperti |
|Interrupt/eventi |63% (5/8)|frameCPU,vettore fisico,interleaving/concorrenza aperti |
|Adapter AkeruOS |20% (1/5)|contratto generico verificato; implementazione con proprietà e controllo backend mancante |
|Hardware |0% (0/5)|mappaRAM,memoria/task,residenza/compatibilità,recupero,acquisizione reale mancanti |

L'obiettivo42b56cc8 resta attivo. Il raccordo registro/open/close è ora eseguito nel gruppo end-to-end; I [modi di apertura e il gate backend7](S33_Dumper_RAM_SD_Modi_Apertura_FAT_e_Gate_Backend7.md) hanno un gruppo separato. Proseguire con backend7 attivo e adapter compatibile con questi stati di errore. Non produrre un firmware dumper da queste sole prove.
