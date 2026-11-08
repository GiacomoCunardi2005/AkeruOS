# S33 — HiddenMenu: flag RAW e dimensione massima del percorso individuato

27 ottobre 2026. Analisi **offline del firmware originale V1.1**, SHA256
`1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`.
Nessuna patch firmware, operazione sulla fotocamera o scrittura su SD.

## Risultato utile

La voce più promettente per il RAW dello scatto è **IQDEBUG MENU →
Take12BitCCDRawImage**, con stato logico On. Il codice della voce abilita un
byte e imposta un selettore a **3**. Il percorso di esportazione trovato usa
**4208 × 3152** e richiede **26.527.232 byte** in modalità 3, circa **26,53 MB**
decimali / **25,30 MiB**, rispetto a 13.263.616 byte del ramo ordinario.

È la massima lunghezza fra i due rami di questo percorso verificato, non una
dimostrazione del massimo assoluto di ogni modalità sensore. La risoluzione
del JPEG 4160 × 3120 non è la dimensione usata da questi due getter RAW.
Il contenuto delle righe/colonne aggiuntive, il packing e i bit effettivamente
significativi devono ancora essere verificati su un file reale.

## Quali valori cambiano

Gli indirizzi sotto sono **indirizzi CPU di stato RAM**, non offset del file
firmware. I setter sovrascrivono byte o parole: non sono maschere di bit da
applicare arbitrariamente al BIN.

| Voce o stato | RAM | Valore del percorso individuato | Evidenza |
| --- | --- | --- | --- |
| SaveCCDRawOnTake | byte `0x36C26E` | `1` abilita il flag | setter `0x28D498`, getter `0x28D48C` |
| Take12BitCCDRawImage | stesso byte `0x36C26E` | On → `1`, Off → `0` | callback `0x7CF7C0`, evento `0x500C` |
| Selettore associato alla voce 12 bit | parola `0x366F90` | On → `3`, Off → `0` | setter `0x14A2B8`, getter `0x14A2D8` |
| SaveCFARawOnIRP | byte `0x366C20` | On → `1`, Off → `0` | setter `0x13AF20`, getter `0x13AF18` |
| FullFormat | parola `0x366C18` | `1`=420, `2`=422, `255`=None | getter `0x13AEF4`, setter `0x13AEFC`, testo UI |

Il menu è ID `0x35`, descrittore `0x987000`, tabella eventi `0x987020`.
Le etichette risorsa sono `SaveCCDRawOnTake` (indice 3), `SaveCFARawOnIRP`
(indice 4) e `Take12BitCCDRawImage` (indice 12).
Il testo dinamico dell'indice 3 è invece `SaveCFAonTake:On/Off`.

**I due interruttori degli indici 3 e 12 condividono il flag:** la callback
dell'indice 3 cambia `0x36C26E` ma non aggiorna `0x366F90`; quella dell'indice
12 aggiorna entrambi. Non sono due abilitazioni indipendenti da selezionare
entrambe alla cieca: una seconda selezione può spegnere il medesimo flag.
La combinazione da studiare per il ramo più grande è `0x36C26E = 1` e
`0x366F90 = 3`, ottenuta dal callback della voce 12 bit quando passa a On.

`FullFormat:422` riguarda il formato YUV dell'immagine sviluppata; non seleziona
12/14/16 bit del sensore né aumenta le dimensioni RAW. Le voci SaveFullYRGB e
SaveFullJPEG non sostituiscono il RAW del sensore.

## Catena verificata: menu → stato → lunghezza di esportazione

1. Il record `0x987098` contiene evento `0x500C` e callback `0x7CF7C0`.
2. A `0x7CF7F0` il callback legge il flag; a `0x7CF7FA` ne scrive il valore
   invertito normalizzato 0/1 tramite `0x28D498`.
3. A `0x7CF810` rilegge il flag; se nonzero prepara `r0 = 3` a `0x7CF818`,
   altrimenti `r0 = 0` a `0x7CF81C`. A `0x7CF81E` chiama `0x14A2B8`.
4. `0x14A2B8` è un **setter RAM**: scrive la parola `0x366F90` e torna.
   Questo callback non dimostra di per sé uno scatto immediato. Il nome
   Take12BitCCDRawImage non va interpretato come esecuzione hardware osservata.
5. Nel percorso acquisizione `0x1B8F24`, dopo una richiesta CapMgr,
   `0x1B9292` legge il flag. Se è nonzero e il puntatore del descrittore+4
   esiste, a `0x1B92A2` legge il selettore e lo confronta con 3.
6. Il ramo non-3 legge i getter `0x12BE64` e `0x12BE6C`, moltiplica i due
   valori e prepara la lunghezza semplice. Il ramo 3 a `0x1B9310` rilegge
   gli stessi getter e a `0x1B9328` prepara `r3 = prodotto + prodotto`.
7. Il codice prende il buffer da descrittore+4, passa lunghezza in `r3` e
   raggiunge `0x28D4D4` a `0x1B9336`. In questo wrapper `r3` diventa `r17`,
   quindi `r2` della scrittura `0x12BCC4` a `0x28D58C`.

I getter sono costanti nel codice originale esaminato:

```text
0x12BE64: r0 = 0x70; imposta bit 12 → 0x1070 = 4208
0x12BE6C: r0 = 0xC5; shift sinistro 4 → 0xC50 = 3152

N = 4208 × 3152 = 13.263.616
modo diverso da 3: lunghezza richiesta = N byte
modo 3:             lunghezza richiesta = 2N = 26.527.232 byte
```

Il bit 12 della prima istruzione costruisce il numero 4208: **non è un bit
di abilitazione RAW da cambiare**. Allungare questa costante senza conoscere
il buffer potrebbe provocare letture fuori buffer; non è una strada validata
per aumentare risoluzione o precisione.

Il nome del menu suggerisce dati a 12 bit salvati con spazio maggiore rispetto
al ramo ordinario. L'esatta rappresentazione dei 2N byte non è stata accertata:
non equivale a provare 16 bit utili del sensore.

## Percorso CFA all'IRP

`SaveCFARawOnIRP` è indipendente dal flag precedente. Per esempio il consumer
`0x1E6A54` legge `0x13AF18`, allinea a 16 le dimensioni prese dal descrittore
e calcola una lunghezza di due byte per posizione se il campo formato vale 2;
il ramo alternativo calcola `(3 × prodotto) >> 1`, quindi **1,5 byte per posizione**.
Il percorso raggiunge il dispatcher `0x28D66C`.

Questo è un ulteriore candidato di dump CFA, ma non dimostra che quel contenuto
sia identico al segnale appena letto dal sensore. Dimensioni e formato sono
dinamici: non assegnargli automaticamente i 4208 × 3152 dell'altro percorso.
Non è necessario abilitarlo per far scegliere 2N al ramo sopra.

## Limiti che contano per un RAW fotografico

- Lunghezza richiesta dalla funzione, conteggio realmente scritto e persistenza
  su SD sono risultati distinti. Il wrapper individuato non rende questa analisi
  una prova del file ottenuto; il percorso di errore dopo write resta da chiudere.
- Prima del dump, un tratto dello stesso percorso, con flag esattamente 1,
  chiama `0x28D5BC` con selettore 2. Il corpo di questa funzione contiene store
  dei bit meno significativi di byte del buffer usando una tabella di 32 valori
  0/1 a `0x35231C`. Non trattare quindi il dump come sicuramente intatto:
  posizione e significato di queste modifiche richiedono una verifica dedicata.
- CFA, precisione ADC effettiva, allineamento dei campioni, endian dei campioni,
  eventuali margini e black level non sono stati identificati da un frame reale.
- Nessuna persistenza dopo spegnimento, uscita completa dall'HiddenMenu o
  possibilità di fotografare con questa configurazione è stata provata qui.
- Non è stato individuato un controllo verificato per un RAW fotografico
  a 14 o 16 bit utili. La stringa diagnostica `LV_test_14b` trovata altrove
  non dimostra una modalità a piena risoluzione collegata a questo menu.

## Prove e riproduzione

[Verificatore](../Python_Trace_Scripts/s33_verify_hiddenmenu_raw.py):

```bash
python3 Python_Trace_Scripts/s33_verify_hiddenmenu_raw.py
```

Esito: **PASS**, 14 finestre originali confrontate con MainCode, 17 controlli
di istruzioni, record eventi, pool e associazione numerica 420/422/None.
Esecuzione delle routine originali nel simulatore GNU ARC700 invariato:
**238 istruzioni, nessun fault, 20 osservazioni verificate**, stack conservato.
Provati getter dimensioni, setter/getter flag con 0/1/2/255, selettore 0/3,
formati validi e rifiuto del formato 3 senza alterare quello precedente.

Solo i getter/setter sono stati eseguiti nella CPU; menu, rami di cattura e
scrittura sono analisi statica. RAM, chiamante e stack sono di laboratorio.
La prima esecuzione del banco si è fermata per RAM del blocco 1 non mappata;
la prova PASS successiva la mappa esplicitamente. Non è stato modificato il
firmware per correggere il banco.

- [JSON della prova PASS](../Risultati/HiddenMenu_RAW/20261027T105610Z/verified_evidence.json)
- [Disassemblaggio verificato](../Risultati/HiddenMenu_RAW/20261027T105610Z/gnu_verified.txt)
- [Traccia CPU](../Risultati/HiddenMenu_RAW/20261027T105610Z/raw_accessors.trace)
- [Candidati di chiamata della ricerca esplorativa](../Risultati/HiddenMenu_RAW/20261027_static/branch_candidates.json)
- [Corpo del modificatore di bit del buffer](../Risultati/HiddenMenu_RAW/20261027_static/raw_buffer_marker.txt)
- [Ingresso acquisizione](S33_Ingresso_Acquisizione.md)
- [Memoria e persistenza HiddenMenu](S33_HiddenMenu_Persistenza_MSDC_e_Inizializzazione_USB.md)
- [Proposta Mono RAW Luminance](S33_Mono_RAW_Luminance.md)

La ricerca esplorativa di chiamate dirette è limitata al disassemblaggio lineare
dei blocchi 0–10; le occorrenze di puntatori sono state cercate nei 16 payload
verificati. I candidati non riancorati non sono flusso di esecuzione dimostrato.
GNU, firmware originali e dump di origine sono rimasti invariati. Nessun BIN
installabile prodotto; **NON_INSTALLARE** resta lo stato dei candidati.
