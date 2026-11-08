# S33 — chiamata indiretta originale dal dispatcher padre al callback FED38

26 ottobre 2026. Firmware V1.1, CPU GNU ARC700 con contesto e MMIO espliciti.
Nessun accesso hardware o modifica a GNU/originali; NON_INSTALLARE.

## Risultato

Provata la catena originale `1014998 → JL [r0] a 1014A06 → 1014D6C`, dopo
che l'API originale ha installato 1014D6C nello slot 1040628 del selettore
610. Il harness chiama ora il dispatcher padre completo 1014998; non chiama
direttamente il callback figlio. Non è però un'iniezione IRQ, un ingresso
tramite vettore o una consegna di interrupt della CPU o della fotocamera.

Atlante `Risultati/Processor_Registers/20261026T114224Z/`: **1266 voci**
(64 posizioni core / 200 AUX / 1002 MMIO), nessun nuovo indirizzo e sei voci
arricchite: FEF0028, FEF0074, FED3814, FED3818, FED3830, FED3834.
Ledger di 356 file verificato; conservate chiavi e geometrie dei 50 atlanti
PASS precedenti. Restano 26 indici AUX con record guest; le ancore run-PC
passano da 213 a 231. Invariate 50 finestre e due famiglie calcolate.

## Accessi e flusso originale

Il dispatcher legge dal descrittore 1040618 l'indirizzo FEF0028 e ne carica
una sola volta la maschera in r5. Poi legge una sola volta FEF0074 in r3.
I nomi maschera/stato qui descrivono l'uso software, non una semantica fisica
di controller verificata. Se maschera e stato sono non nulli, scorre i 16
record originali, controlla i rispettivi bit e consulta lo slot callback.

La prima voce, 610, usa bit15 in entrambe le parole. Con i due bit attivi e
lo slot installato a 1014D6C, le istruzioni originali salvano r1..r6 sullo
stack ed eseguono `JL [r0]`. Al ritorno ripristinano i registri, scrivono
8000 a FEF0074 e cancellano il bit15 nella sola copia r3, senza rileggere
FEF0074. Gli altri slot della tabella restano zero: se un loro bit risulta
attivo, il codice salta la chiamata e lo store associato al callback.

Il callback 1014D6C, a sua volta, rilegge per ciascun record le parole MMIO
FED3814/FED3818 e FED3830/FED3834. È una differenza fra due livelli di
scansione: il padre usa copie conservate nei registri, il figlio carica
nuovamente i valori durante il ciclo. Le due letture iniziali del padre
sono operazioni distinte; non provano uno snapshot atomico hardware.

## Coppie di prove e ambito preciso

Per ciascun seed MMIO 0000, FFFF e A55A sono eseguiti due casi. Cambia
soltanto il bit15 della fixture FEF0074. Le sezioni allocate del harness
(codice e dati file-backed, indirizzi e dimensioni delle sezioni NOBITS),
la profondità di contesto e tutti gli altri byte delle fixture sono identici
all'interno di ogni coppia. L'audit verifica esplicitamente queste identità.

| Seed | Stato con bit15=0 | Callback | Stato con bit15=1 | Callback |
|---|---|---:|---|---:|
| 0000 | 401D | 0 | C01D | 1 |
| FFFF | 3FE2 | 0 | BFE2 | 1 |
| A55A | 6547 | 0 | E547 | 1 |

Senza bit15 il padre non chiama 1014D6C, non scrive FEF0074 e non accede ai
quattro registri FED38 attraverso quel callback. Gli accessi FED38 degli
altri chiamanti della sequenza restano presenti e distinti nell'audit.
Con bit15 il padre chiama esattamente una volta il callback originale e
scrive 8000 a FEF0074. Il registro r3 viene aggiornato rispettivamente a
401D, 3FE2, 6547: è la modifica della copia software, non una rilettura MMIO.

Il backing MMIO è memoria ordinaria: lo store 8000 sostituisce l'intera
parola. Anche gli store del figlio a FED3834 mantengono gli effetti del
modello precedente (4E0D→8, B1F2→80, EB57→40). Nessuna attribuzione W1C,
acknowledge, perdita eventi, latch, concorrenza o IRQ alla periferica reale.
Queste coppie non autorizzano equivalenze su altri bit, slot, input o stati.

## Verifiche ed evidenze

Sei scenari, dodici esecuzioni con/senza osservatore, sei coppie di tracce
identiche. In totale: 180 chiamanti esterni originali, sei dispatcher padre,
tre callback raggiunti tramite il loro JL originale, sei pulizie tramite
API originale e 378 coppie di servizi annidati. Verificati 579 eventi MMIO
(294 letture / 285 scritture), 464 istruzioni ridisassemblate e 24 letture
IDENTITY modellate. Ogni caso negativo ha 80 MMIO nell'intera sequenza;
ogni positivo 113. Il delta è il callback figlio e lo store del padre.

IDENTITY rimane zero nel modello GNU. Le 24 nuove letture dei tre PC
1004A8A/10049E2/1004A3A portano a 36 i record di IDENTITY nell'atlante:
nessuna misura dell'ID Nikon, dei BCR o del reset fisico.

Il gate RAM 10411E4 è impostato temporaneamente a 1; l'API 1004A78 registra
il callback e lo cancella al termine con `(610,0)`. Il contesto `.data` ha
gate +24=1 e profondità 1/2/7 abbinate ai seed. Tutti gli incrementi e
decrementi annidati, i ritorni, stack/r13..r19, slot callback finale zero,
byte di guardia e begin/result MMIO sono controllati. Il globale 104126C e
il gate 10411E4 sono ripristinati; il TBIB runtime finale coincide
integralmente con l'originale. Nessun FLAG/SR, DSP provvisorio o fault.

CPU: `outputs/gnu_arc700/20261026T113832Z_2373313c/verified_evidence.json`.
Audit: `tbib_parent_dispatch_audit.json` nella stessa directory; copie e
script sotto `evidence/` nell'atlante. L'oracolo riusa il piano della tappa
precedente, vincolandone esplicitamente file e hash; l'audit ricostruisce
indipendentemente tabelle, accessi e condizioni del dispatcher.

```sh
python3 Python_Trace_Scripts/s33_verify_tbib_parent_dispatch.py
python3 Python_Trace_Scripts/s33_audit_tbib_parent_dispatch.py outputs/gnu_arc700/20261026T113832Z_2373313c
```

Un controllo dell'auditor ha interrotto il primo tentativo perché una
variabile per lo stato del figlio oscurava lo stato iniziale del padre.
Separate le variabili, mantenendo i confronti puntuali con la trace; nessuna
modifica ai dati o eventi CPU, nessuna ammissione con audit fallito.

## Lavoro aperto

Raggiungere callback figli non nulli tramite registrazioni originali,
seguire altri dispatcher e categorie, verificare i domini invalidi dei
chiamanti e la durata dei servizi. Restano il ramo IDENTITY=13030513,
init 100559C, censimento TBIB OOB, AUX indiretti/overlay, BCR/SoC/DSP fisica.
Nessun boot completo, installazione o recupero hardware dimostrati;
l'universo fisico dei registri non è delimitato e il goal resta aperto.
