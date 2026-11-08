# BootNAND: DDR_SIZE_ID, dimensione configurata e checksum BFN

20 ottobre 2026 — R0/R3/R4. Il valore `DDR_SIZE_ID=0x120` è ora decodificato nel codice del boot fornito dalla fotocamera: **byte basso32 × 8 MiB = 256 MiB come limite configurato del test memoria**. Il bit8 vale1 e alimenta un ramo di configurazione del controller. Questa prova supera il precedente «ID non interpretato»; non certifica256 MiB di RAM fisica interamente utilizzabile.

## Prove e riproduzione

- [Script riproducibile](../Python_Trace_Scripts/s33_verify_bootnand_ddr_id.py).
- [Indice corrente](../Risultati/Dump_fotocamera/BootNAND_ID/latest.json).
- [Evidenze](../Risultati/Dump_fotocamera/BootNAND_ID/20261020T153622Z/verified_evidence.json), [sette finestre GNU](../Risultati/Dump_fotocamera/BootNAND_ID/20261020T153622Z/gnu_verified.txt), [12 casi aritmetici](../Risultati/Dump_fotocamera/BootNAND_ID/20261020T153622Z/arithmetic_cases.json), [punti del test memoria ricostruiti staticamente](../Risultati/Dump_fotocamera/BootNAND_ID/20261020T153622Z/memory_test_static_sites.json).
- [Caller di laboratorio](../Risultati/Dump_fotocamera/BootNAND_ID/20261020T153622Z/ddr_id_and_checksum.s), [traccia CPU](../Risultati/Dump_fotocamera/BootNAND_ID/20261020T153622Z/ddr_id_and_checksum.trace), [log CPU](../Risultati/Dump_fotocamera/BootNAND_ID/20261020T153622Z/ddr_id_and_checksum.log).

Comando eseguito dalla radice:

```bash
python3 Python_Trace_Scripts/s33_verify_bootnand_ddr_id.py
```

Esito `PASS_BOOTNAND_ID_ARITHMETIC_AND_CHECKSUM`:12casi aritmetici e2calcoli del checksum originale nello stesso programma di laboratorio;1317istruzioni del profiler, exit0, nessun fault e nessuna istruzioneMMIO eseguita. GNU originale fissato per hash, senza varianti DSP. Lo script ricontrolla i14dump, il firmwareV1.1 e i16payload tramite gli helper esistenti. DUMPS, toolchain, sorgenti e installazioni GNU rimangono intatti.

Il probe contiene **sei istruzioni originali rilocate**, tre per il limite e tre per il bit8, con inizializzazione e controlli sintetici. Non esegue tutta la routine DDR. L’helper checksum originale viene invece chiamato nel suo corpo completo. Nessun risultato qui è un nuovo boot della Nikon o una prova di RAM fisica.

## Identità e base del codice BootNAND

`DUMPS/BootNANDBase.dmp`:8192byte, SHA-256 `44c849a4ab69d9e9e010602887293eda1fb19dfcfa22d1f7f4bcfba7a166bd65`. Confermata la ricostruzione dai primi16segmenti512/528 di NANDP1 già documentata nella [classificazione](S33_Classificazione_Dump_Fotocamera.md).

La base candidata è `0x0F800000`: il programma contiene riferimenti assoluti coerenti a codice proprio, ad esempio routine`0x0F80037C` e indirizzi di inizio/fine di loop. All’offset`0x20` imposta`gp=0x0F801E3C`; a`0x1FE0` compare la stringa `BootFromNAND`. L’ELF di analisi usa questa base e viene ricopiato a BIN per verificare identità integrale. Non è una misura della mappa al reset o la prova che questo intervallo sia RAM libera.

Distinzione necessaria: il puntatore runtime alla configurazione viene letto da **AUX`0x18`** all’offset`0x15E8`. Non è stato osservato il valore restituito dall’hardware. Il rapporto non lo sostituisce con`0x0F802000` o con una regione aggiunta al simulatore.

I PC indicati sotto sono base candidata più offset file. La catena statica utile è `0x0F8015DC` → lettura configurazione`0x0F800478` → configurazione clock → selettore → inizializzazione DDR`0x0F80109C`. Il medesimo puntatore letto daAUX18 arriva alle routine nel delay slot delle chiamate. Il selettore locale`0x0F801D20` restituisce1 nel delay slot del ritorno; non è un input hardware inventato dal modello.

## Decodifica di DDR_SIZE_ID

Nella routine`0x0F80109C`:

| PC candidato | Istruzione | Effetto |
|---|---|---|
|`0x0F8010A4`|`ld r13,[r0,196]`|Legge il campo configurazione+`0xC4`|
|`0x0F8010EA`|`extb_s r13,r13`|Conserva il byte basso unsigned|
|`0x0F8010F2`|`asl_s r13,r13,0x17`|Moltiplica per`2^23`, cioè8 MiB|
|`0x0F801100`|`bl.d …0x0F801018`|Chiama il test memoria|
|`0x0F801104`|`mov_s r0,r13`|Passa il limite nel delay slot|

Per il valore del dump:

```text
0x120 & 0xFF = 0x20 = 32
32 << 23 = 0x10000000 = 268435456 byte = 256 MiB
```

I12casi CPU includono0,1,`0x10`,`0x20`,`0x80`,`0xFF`,`0x100`,`0x110`,`0x120`,`0x180`,`0x1FF`,`0xFFFFFFFF`. Servono anche a verificare l’estensione unsigned del byte, il troncamento a32bit e la separazione dai bit superiori; non sono12boot o12misure della memoria.

Nella routine DDR`0x0F800A54`, il campo+`0xC4` viene letto di nuovo, mascherato con256 e spostato di8bit: `(ID >> 8) & 1`. Questo bit viene conservato in`r17`, guida un ramo e viene scritto come halfword al registro`0x0FE20110`. Per questo campione vale1. Non gli viene assegnato il nome di uno standard DDR o una larghezza di bus senza documentazione o ulteriori consumatori.

## Il test del boot è sparso

La routine`0x0F801018` parte dall’indirizzo0 e avanza di`0x100000`, cioè1 MiB. Per ogni punto scrive due word, con pattern alternati`0x5555AAAA` e`0xAAAA5555`, poi le rilegge e le confronta. Salta il punto`0x08000000`. Dopo aver controllato il punto`0x0F700000` esce anche se il limite configurato sarebbe maggiore.

Con il limite`0x10000000`, la proiezione statica produce **247punti, due word per punto,1976byte**. Il punto più alto è`0x0F700000` con seconda word a`0x0F700004`; non viene verificato ogni byte dell’intervallo e non viene raggiunta tutta la parte superiore prima del limite. I punti sono elencati nel JSON; questa enumerazione è un calcolo del flusso di controllo, non l’esecuzione di quelle scritture.

Non è ricostruita la ragione hardware del salto a128 MiB o dell’arresto a247 MiB. Non dedurre da queste eccezioni né una lacuna fisica precisa né memoria assegnabile al nuovo task. L’avvio HiddenMenu osservato resta evidenza separata: non è stata raccolta una traccia che mostri questo test superato sulla macchina.

## Il checksum protegge anche DDR e clock

Il reader`0x0F800478` legge256halfword dal registro`0x0FFCA010` nel buffer runtime. Legge il checksum dalla word+`0x4C`, poi chiama l’helper`0x0F800350` con puntatore buffer+`0x50` e lunghezza432byte. Il ramo confronta il risultato con la word memorizzata.

L’helper somma108word little endian modulo`2^32`. Nei quattro record BFN individuati in precedenza, la somma dei byte`[0x50,0x200)` è`0x0005A97D`, uguale alla word+`0x4C`. L’intervallo comprende DDR, ID, clock e le due versioni. Il ruolo del checksum è quindi raccordato sia ai byte reali sia al codice che lo consuma.

Due prove CPU eseguono l’helper originale: configurazione integra→`0x5A97D`; incremento controllato di1 nella word+`0xA0` della **copia di laboratorio**→`0x5A97E`. GNU usa file mappati condivisi: le scritture guest aggiornano`configuration_mmap.bin` nei risultati. `configuration_input.bin` conserva il contenuto iniziale; lo script verifica l’esatta differenza prevista e ricontrolla gli hash di tutti gli originali. Nessun dump utente viene passato al simulatore come mappa scrivibile.

## Implicazioni per AkeruOS e continuazione

R3 ora dispone di una configurazione della macchina che indica256 MiB nel boot e di un parametro separato del controller. Il precedente profilo128 MiB resta un profilo di laboratorio storico; non viene ingrandito automaticamente. Prima di costruire una mappa per AkeruOS rimangono residenza, alias, MMIO, finestre alte, proprietà e durata delle aree usate da Nikon.

R4 acquisisce il formato del checksum della configurazione iniziale, distinto daTBIB/TBM. Questo aiuta a capire quali dati preservare, ma non autorizza ricostruzione, scrittura NAND o una garanzia di recupero. Le quattro copie raw identiche non sono ancora quattro percorsi indipendenti di avvio dimostrati.

Prossimo: interpretare i dati successivi ai primi512byte dei record e raccordarli al loader e alla geometria NAND; seguire poi il caricamento e l’handoff alTBIB. Per la RAM, cercare un riscontro indipendente della capacità e delle finestre senza coprire i registriMMIO con una banca generica. Nessuna nuova fotografia AkeruOS o percentuale funzionale acquisita.

## Continuazione: P1IDSTR e handoff TBIB — 20 ottobre 2026

Il [nuovo rapporto loader](S33_NAND_P1IDSTR_Blocchi_Boot_e_Handoff_TBIB.md) identifica24copie identiche della tabella244byte, raccorda tutti i393216byte BootCode ai blocchi1/2/3 e verifica inCPU originale checksum e salto alTBIB da un contesto post-trasferimento dichiarato. Il TBIB raggiunge la prima scrittura stack non fornita nel laboratorio; non è boot completo né prova del controllerNAND. Prossimo: campi partizioni/managerNAND e divergenze delle proiezioni MainCode/Reserved.
