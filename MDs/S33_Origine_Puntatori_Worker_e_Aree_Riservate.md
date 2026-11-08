# S33 — origine dei puntatori worker e aree riservate

Analisi statica V1.1, 19 ottobre 2026. Continuazione della [griglia e dei tre buffer](S33_Griglia_Tre_Buffer_e_Copia_Finale.md). Nessuna esecuzione hardware.

## Risultato

I puntatori del buffer di lavoro e della destinazione finale provengono da **tabelle di indirizzi selezionate per stato e indice**, a base `0x3920B8`. La sorgente arriva invece dal **valore restituito dalla callback configurazione+0x40**.

Per il descrittore concreto del secondo percorso, questa callback è **`0x25283C`**, che seleziona una chiamata al dispatcher `0x253570`. L'indirizzo sorgente finale restituito dal dispatcher resta da risolvere.

Nell'inizializzatore sono stati individuati due schemi di preparazione delle tabelle: quattro indici con **quattro aree da `0x8C28` byte** per indice in un ramo, oppure **due aree da `0x40C08` byte** per indice nell'altro, usando arrotondamenti a otto byte. È aritmetica di suddivisione di una regione: non prova ancora l'allocazione o la capienza della regione completa. Circa 10% funzionale invariato.

## 1. Strutture intermedie e selezione delle tabelle

Il task `0x15C4E8` usa:

| Indirizzo | Uso |
|---|---|
| `0x3920B8` | base delle tabelle di puntatori e stato |
| `0x392144 = base+0x8C` | indice letto come byte |
| `0x392148 = base+0x90` | stato letto come parola |
| `0x39214C` | struttura intermedia: sorgente, geometria e parametri |
| `0x392328` | descrittore copiato nel payload del worker |

Il tratto `0x15C5DA..604` calcola **base+4*indice**, poi legge due puntatori:

| Stato letto | Offset del buffer di lavoro | Offset della destinazione finale |
|---|---|---|
| 0 | +`0x20` | +`0x40` |
| 1 | +`0x30` | +`0x50` |
| altro | +0 | +`0x10` |

Il builder conserva il primo in r16 e il secondo in r18. A `0x15C614/640` li scrive a descrittore+0/+4. `0x247398` li copia a richiesta+64/+68, cioè **payload+0/+4**.

Il selettore viene letto come byte e usato direttamente nell'offset scalato. **Questo tratto non controlla indice<4**; l'inizializzazione di quattro elementi non dimostra da sola l'invariante del produttore dell'indice. Anche lo stato diverso da 0/1 passa a una tabella di default, senza un rifiuto locale universale.

## 2. Sorgente dal ritorno di una callback

Il tratto `0x15C586..590` legge configurazione **`0x367490+0x40`**, verifica se nonzero e, in tal caso, la chiama senza preparare argomenti espliciti nel tratto mostrato. Il valore r0 restituito viene scritto a **`0x39214C+0`**.

Il builder lo legge a `0x15C612` e lo scrive a descrittore+`0x10` a `0x15C618`. La copia in `0x2473B4..3B6` lo porta a richiesta+80, cioè **payload+0x10**. I backend lo usano poi come sorgente attraverso la cella `0x369604` già verificata.

Se la callback non è presente, questo tratto salta la chiamata e lo store: **non inizializza qui incondizionatamente il campo a zero**. Le guardie successive richiedono un valore nonzero per procedere nel percorso studiato, ma non dimostrano da sole validità, freschezza o proprietà dell'indirizzo.

La geometria halfword di descrittore+`0x14/16` proviene dalle halfword a intermedio+4/+6. In questa continuazione non vengono ancora attribuite dimensioni effettive ai tre buffer sulla base di quei due valori.

## 3. Identità concreta del getter sorgente

Nel secondo descrittore `0x445A6C`, la routine di preparazione `0x252694` scrive il quinto campo (+16) con il valore del pool **`0x2526C8 = 0x25283C`**. L'inizializzatore copia quel quinto campo in configurazione+`0x40`, come verificato a `0x15E58A/592`.

La callback **`0x25283C`** legge un valore halfword a **`0x8996E0+0x18 = 0x8996F8`**, quindi chiama indirettamente **`0x253570`**, risolto dal pool `0x2528BC`.

Il caricamento iniziale è `ld.as r0,[pcl,-107]`: la posizione effettiva del pool è **`align4(0x25283E)-107*4 = 0x252690`**, che contiene `0x8996E0`. L'annotazione GNU non scalata accanto all'istruzione non va usata come indirizzo effettivo.

Fra i rami verificati:

| Halfword selettore | Argomenti r0/r1 al dispatcher |
|---|---|
| 1920 oppure 2016 | 0, 1 |
| 1280, 1344 oppure 1392 | 1, 1 |
| uguale al campo base+`0x20`, oppure a quel campo+48 | 2, 1 |
| 672 | 3, 1 |
| 640 | 3, 0 |
| 352 | 4, 1 |
| altro | 0, 0 |

Il getter ritorna dopo la chiamata, mantenendo r0. Non si presume che il selettore sia una larghezza immagine solo perché alcuni numeri ricordano risoluzioni. Corpo completo del dispatcher, origine delle aree restituite e dominio reale restano aperti.

## 4. Preparazione delle aree per quattro indici

L'inizializzatore carica r14 con `0x3920B8` e azzera la struttura da `0x94` byte. Nel tratto `0x15E614..684`, dopo altre guardie, imposta **quattro iterazioni** e seleziona uno dei due schemi in base a un temporaneo stack+164.

| Ramo | Store per indice i | Incremento fra inizi delle aree |
|---|---|---|
| temporaneo=1 | base+`0x20+4i`, +`0x30+4i`, +`0x40+4i`, +`0x50+4i` | `0x8C28` = 35.880 byte, con allineamento8 |
| altro | base+`4i`, +`0x10+4i` | `0x40C08` = 265.224 byte, con allineamento8 |

Il cursore viene aggiornato con somme e arrotondamenti verso l'alto a otto byte; l'indirizzo di fine viene poi conservato in un temporaneo. Con cursore iniziale allineato e senza overflow, il primo schema avanza complessivamente di **16×35.880 = 574.080 byte**, il secondo di **8×265.224 = 2.121.792 byte**.

Questi numeri descrivono il passo della suddivisione locale. Non sono una misura di RAM libera, né una prova che il chiamante abbia fornito una regione abbastanza grande. L'origine del cursore, i controlli successivi sulla regione e l'associazione delle modalità utente ai due schemi devono ancora essere seguiti.

## Evidenze e prossimo passo

[Script](../Python_Trace_Scripts/s33_trace_worker_buffer_origins.py), [JSON](../Ghidra_Results/ghidra_reports/worker_buffer_origins/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/worker_buffer_origins/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_worker_buffer_origins.py`.

Verificati **16 SHA-256, roundtrip ELF del blocco 00, 10 finestre, 2 collegamenti diretti, 46 istruzioni chiave e 8 valori di pool**. Le conclusioni distinguono la selezione statica dall'allocazione fisica e dal comportamento runtime.

Prossimo: origine e capienza della regione suddivisa, produttore e limiti dell'indice, origine dell'area sorgente restituita dal dispatcher `0x253570` e consumatore della destinazione dopo il worker. Sincronizzazione, freschezza della sorgente e rilascio restano aperti.


## Continuazione: sorgenti concrete del selettore0

Il [rapporto sulle sorgenti numeriche](S33_Sorgenti_Numeriche_Statiche_Interpolatore.md) risolve otto indirizzi del blocco05 nel ramo selettore0, ne estrae i dati e verifica la disposizione130×70. Altri selettori, soglie di stato, stride effettivo e significato delle componenti restano aperti.


## Continuazione: flag e aggiornamento degli indici

Il [rapporto sul ciclo slot](S33_Ciclo_Slot_Worker_Flag_e_Indici.md) risolve pubblicazione/lettura/azzeramento dei flag e alcuni aggiornamenti modulo4. Questo restringe il problema degli indici senza provare l’invariante globale o il completamento fisico dei consumatori.
