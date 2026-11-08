# S33 — percorsi interrupt alternativi e scrittori dei vettori

Analisi statica V1.1, 19 ottobre 2026. Continuazione dei [vettori runtime](S33_Vettori_Interrupt_e_Tabella_Runtime.md). Nessuna esecuzione hardware.

## Risultato

I target alternativi **`0x2646A0`** e **`0x2655D4`** costruiscono ciascuno un frame interrupt e consultano tabelle proprie da quattro callback. Non attraversano, nel tratto ricostruito, la selezione della tabella runtime usata da `0xB3054`.

Risolti inoltre due tipi distinti di scrittori: uno modifica il target rispetto alla base CPU corrente; altri accessor scrivono interi salti a indirizzi fissi **`0x420`** e **`0x1428`**. Le loro condizioni d'uso restano da attribuire. Non si può assumere che tutte queste operazioni avvengano nello stesso stadio o con la stessa base vettori. Circa 10% funzionale invariato.

## 1. Due ingressi con frame proprio

Entrambi i target riservano **164 byte**, salvano r0/r1/r12 e trattano `aux_irq_lv12`, `status32_l1`, `status32_l2` e i collegamenti interrupt. Proseguono con il salvataggio del contesto e una scansione di callback condizionata da due letture halfword MMIO.

| Ingresso | Tabella | Puntatori MMIO nell'intestazione | Record |
|---|---|---|---|
| `0x2646A0` | `0x427C00` | `0x0FEF0050`, `0x0FEF007C` | 4 |
| `0x2655D4` | `0x427F8C` | `0x0FEF0328`, `0x0FEF0314` | 4 |

Le tabelle seguono la struttura con intestazione di 12 byte e record da 8. I selettori halfword dei record, nell'ordine iniziale, sono rispettivamente **8, 0, 1, 6** e **2, 3, 4, 5**. I puntatori callback sono zero nel payload iniziale. Il significato dei selettori non viene equiparato automaticamente agli ID logici `0x0402/0x0904` dei percorsi precedenti.

## 2. Chiamata condizionata e writeback successivo

Il primo corpo controlla i bit indicati dai record e invoca il campo funzione con **`jl [r0]` a `0x2647B8`**. Il secondo fa lo stesso a **`0x2656EC`**.

Dopo il ritorno della callback, ciascuno costruisce una maschera con il bit del record e scrive una halfword al primo indirizzo MMIO della tabella, poi aggiorna la copia locale dei bit ancora da trattare. Gli store sono **`0x2647DC`** e **`0x265710`**. Il codice stabilisce l'ordine callback → writeback; il significato fisico del writeback non è dedotto dal solo store.

Le due tabelle sono distinte da `0x424A00/0x424C30`, usate dai dispatcher runtime già verificati. Per attribuire una notifica SD a questi ingressi servono i loro scrittori delle callback e le condizioni di selezione. Non è provata l'equivalenza dei due percorsi rispetto al salvataggio fotografico.

## 3. Scrittori a indirizzo fisso

L'helper **`0x16D3D8(indirizzo, target)`** scrive una voce di salto assoluto ARC: prima la parola istruzione dal pool **`0x16D508 = 0x0F802020`**, poi il target con le halfword scambiate.

Gli accessor verificati sono:

| Ingresso accessor | Destinazione | Target |
|---|---|---|
| `0x16DA28` | `0x420` | Costante `0x265214`, caricata nel delay slot |
| `0x16DA2E` | `0x420` | Costante `0x2646A0`, caricata nel delay slot |
| `0x16DA48` | `0x1428` | Costante `0x265F60`, caricata nel delay slot |
| `0x16DA4E` | `0x1428` | Costante `0x2655D4`, caricata nel delay slot |

Questi indirizzi sono letterali verificati nei pool. Non vanno sostituiti con `0x800+offset`: l'impostazione iniziale della base a `0x800` è un'altra operazione, e la relazione temporale fra gli accessor e il bootstrap deve ancora essere ricostruita.

I chiamanti reali dei setter entrano a **`0x16DA38`** e **`0x16DA58`**, dopo i caricamenti di literal a `0x16DA36/56`. Conservano rispettivamente r0 a contesto+0/+4 e r1 a contesto+8/+12. Il valore r1 deriva quindi dal chiamante, non necessariamente dal target IRQ caricato due byte prima dell'ingresso.

Questa è una correzione della prima interpretazione degli accessor: senza seguire i delay slot e gli indirizzi esatti di ingresso, i target apparivano assegnati al ramo sbagliato. La verifica ampliata controlla esplicitamente i quattro `b.d`, i relativi caricamenti nei delay slot e i due siti di chiamata ai setter.

## 4. Modifica relativa alla base corrente

I tratti già individuati **`0x265244`** e **`0x265F90`** leggono invece `int_vector_base`, aggiungono rispettivamente **`0x20`** e **`0x28`**, poi scrivono soltanto la parola del target a +4 della voce. Usano `0x2646A0` e `0x2655D4`, seguiti da operazioni sui registri ausiliari di cache.

Sono quindi diverse sia la destinazione sia la quantità scritta rispetto agli accessor della sezione 3. I target `0x265214/0x265F60` conducono ai tratti che includono queste modifiche relative. Le nuove prove della sezione 5 attribuiscono due installazioni, senza risolvere l’intero ordine globale o tutti i successivi ripristini.

Questa separazione conserva un limite concreto della ricostruzione: **la catena iniziale stub → tabella runtime non può essere dichiarata universale dopo una sostituzione del vettore**. Il percorso con slot 9 rimane verificato nella configurazione iniziale; le nuove prove non stabiliscono tutte le modalità successive.

## 5. Due chiamanti e passaggio di esecuzione

Il primo tratto, dentro **`0x159A1C`**, prepara un puntatore nella cella `0x423900`, poi a **`0x159AC0`** chiama `0x16DA38` con **r0=`0x337218`** e **r1=parola letta da `0x423900` nel delay slot**. Questi valori diventano contesto+0 e +8. Imposta stato **`0x424200 = 1`** e chiama **`0x16DA28`**, che installa il target fisso `0x265214` a `0x420`. Dopo altre preparazioni attende ripetutamente che `0x424200` valga 2.

Il secondo, dentro **`0x159CE0`**, chiama **`0x16DA58`** con **r0=`0x23FB10`** e r1 letto dalla cella `0x423A00`. Imposta stato **`0x424400 = 1`**, chiama **`0x16DA48`**, che installa `0x265F60` a `0x1428`, e attende che il proprio stato valga 2.

I target installati leggono rispettivamente **`0x423B08`** e **`0x423B0C`**, passando a quel valore come nuovo stack se non nullo, prima del tratto già ricostruito che modifica il target relativo alla base CPU. Più avanti caricano i campi +0/+4 del contesto nel collegamento interrupt. Questo attribuisce ai valori conservati un ruolo concreto di **punto d'ingresso e puntatore per lo stack** in questi chiamanti, senza estenderlo a ogni uso della struttura.

Le entrate **`0x337218`** e **`0x23FB10`**, quando trovano il rispettivo stato a 1, scrivono **2** e proseguono con configurazioni di cache, livello interrupt e timer CPU. Sono verificati i due store, collegati alle attese dei chiamanti. Non si presume che stato 2 significhi già completamento di tutte le configurazioni successive: la scrittura lo precede.

Nel tratto locale dei due cicli che aspettano 2 non compaiono contatori o timeout. I servizi chiamati al loro interno, le condizioni che attivano il passaggio e l'intero ciclo di vita restano da ricostruire. Non viene ancora assegnata una modalità utente, di alimentazione o di salvataggio a questa sequenza.

## Evidenze e continuazione

[Script](../Python_Trace_Scripts/s33_trace_alternate_irq_paths.py), [JSON](../Ghidra_Results/ghidra_reports/alternate_irq_paths/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/alternate_irq_paths/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_alternate_irq_paths.py`.

Verificati **16 SHA-256**, roundtrip ELF del blocco 00, **14 finestre, 10 collegamenti diretti e 50 istruzioni chiave**, più le due intestazioni e otto record callback. Nessuna osservazione della RAM o degli interrupt del dispositivo.

Prossimo: origine delle due richieste di passaggio, ripristini successivi e scrittori delle tabelle alternative; ordine rispetto ai cambi di base e confronto delle notifiche instradate nei diversi percorsi.

## Continuazione sui cicli delle entrate

Il [rapporto cicli/mailbox](S33_Cicli_Alternativi_e_Mailbox.md) collega il chiamante comune e segue le entrate fino ai cicli persistenti con callback, `sleep 0` e mailbox direzionali. La liberazione della mailbox precede la callback e non ne prova il completamento.
