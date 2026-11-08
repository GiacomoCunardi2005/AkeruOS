# Nikon S33: loop FFC7000 e destinazioni fissate dai chiamanti

25 ottobre 2026. Mappa fisica incompleta; obiettivo attivo. GNU e firmware
originali invariati; nessun accesso hardware. NON_INSTALLARE invariato.

Sono aggiunte127posizioni MMIO concrete: **due indirizzi singoli e125celle di
trasferimento**, rappresentate separatamente. L’atlante contiene **1.026voci:
64posizioni core,197indici AUX,765indirizzi MMIO singoli**. Le posizioni core
includono encoding speciali/opzionali/riservati e non provano altrettanti
registri fisici. Le finestre passano da24a**37**, con **3.281appartenenze di
cella e3.249indirizzi distinti**. Restano32ripetizioni tra finestre eFF74088anche
scalare. Le due famiglie MMIO indicizzate precedenti restano irrisolte.

## Prove eseguite e confini

Fonte CPU:
`outputs/gnu_arc700/20261025T162924Z_00fa2f69/verified_evidence.json`,
PASS_FFC7000_BOUND_LOOP_WRITERS. **28scenari/56run,680accessi MMIO halfword:
132letture e548scritture**. Tutte le28coppie di tracce osservatore spento/acceso
sono identiche byte per byte. SP e sentinelle r13..r19 restano conservati.
Sette entry principali sono chiamate dai probe; i due helper parametrizzati
sono raggiunti dai wrapper originali. Gli helper condivisi di salvataggio e
ritorno eseguono invariati.

Ogni entry è provata con quattro input,compresi zero,FFFF/massimo,misti e valori
complementati o bit ignorati invertiti. Sono controllati i byte/halfword letti
dagli input nelle tracce. Input,stack,seed e backing sono fixture,non reset o
RAM fisica libera. Non sono eseguiti chiamanti arbitrari per ammettere nuove
basi MMIO: le basi dipendono dai pool dei wrapper originali selezionati.

## Packer di nove byte e tabella originale

`308ED4` legge9byte e aggiorna5celle `FFC7300..FFC7310`,passo4byte. L’indice di
cella è floor(i/2). La tabella originale a`354E50` contiene:

- due maschere16bit `00FF`,`FF00`;
- due shift byte `0`,`8`.

I sei byte `ff0000ff0008` provengono dal Main originale,mappato invariato.
L’audit verifica anche le nove letture della maschera e dello shift dalla copia
sullo stack, senza sostituire la tabella con una fixture.

Ogni byte produce una lettura e una scrittura halfword. Le prime quattro celle
ricevono low8 poi high8 in due operazioni distinte. La quinta riceve solo low8
**conservando il precedente high8**. Con seedA55A e input misto
00,FF,80,7F,01,FE,55,AA,81,le uscite finali sono
FF00,7F80,FE01,AA55,A581. Il byte alto A5 finale è provenienza della fixture,
non un reset Nikon. L’array è una finestra di5celle,non cinque registri di
controllo indipendenti.

## Otto finestre da tredici halfword,vincolate da quattro wrapper

Il helper `308F48` copia13halfword da r1 a r0,passo input2/output4. Preso da solo,
il suo argomento destinazione non delimita il dominio MMIO. Sono eseguiti i
quattro wrapper originali seguenti,ciascuno con due chiamate al helper:

| Wrapper | Prima base | Seconda base | Offset input delle chiamate |
|---|---|---|---|
| `308F7C` | `FFC7314` | `FFC7348` |0,26byte|
| `308F98` | `FFC737C` | `FFC73B0` |0,26byte|
| `308FB4` | `FFC73E4` | `FFC7418` |0,26byte|
| `308FD0` | `FFC744C` | `FFC7480` |0,26byte|

Sono104celle complessive. L’audit decodifica i BL originali verso308F48,i pool
delle basi e le istruzioni dei delay slot che legano r1 all’input o input+1A.
Nelle tracce ogni wrapper entra due volte nel helper; tutti i26valori caricati
dall’input corrispondono alle26scritture. I dati sono trasferiti come halfword
complete. Non sono provate atomicità,larghezze fisiche32bit o altri chiamanti.

## Due accumulatori di campi in posizioni fisse

`308FEC` legge due input di4byte e aggiorna gli indirizzi fissi `FFC74B4` e
`FFC74B8`,con quattro iterazioni:

- FFC74B4 usa mascheraF spostata di0,4,8,12bit,componendo quattro nibble;
- FFC74B8 usa maschera7 agli stessi shift,conservando bits3,7,11,15 del vecchio
  valore.

Ogni iterazione legge e scrive ciascun indirizzo. I due accumulatori sono voci
singole con campi software espliciti; non sono una singola operazione atomica.
Con gli input misti e seedA55A il risultato è F0F0 eF078. La seconda word
contiene i bit conservati dalla fixture. Invertire i bit alti ignorati dei due
input lascia invariata l’intera sequenza delle scritture.

## Quattro finestre low9 e target indiretto originale

`3090D0` carica dal pool`309134` il target`309090` ed esegue quattro JL indiretti.
I pool originali fissano le basi `FFC74BC`,`FFC74CC`,`FFC74DC`,`FFC74EC`.
Ogni chiamata aggiorna quattro celle,passo4byte,leggendo quattro halfword
successive dall’input. Gli offset iniziali delle quattro chiamate sono0,8,16,24.

Ogni cella riceve (vecchio&FE00)|(input&1FF). Le16celle conservano quindi high7.
L’audit verifica target,pool,delay slot,conteggio4,stride e le16letture d’ingresso;
nelle tracce il helper309090 è raggiunto quattro volte. Invertire high7 degli
input con seed invariato lascia identiche le scritture. L’insieme è ammesso
come quattro finestre vincolate dal chiamante,non come dominio generale del
helper parametrizzato.

## Audit e AUX

L’audit indipendente ricostruisce formule e destinazioni da64istruzioni mirate,
pool originali e tabella del firmware,poi confronta ordine,valori e larghezze
con le tracce GNU e gli eventi dell’osservatore. Controlla coppie begin/result,
backing finale,padding A5 e input immutati. Esito:
PASS_FFC7000_BOUND_LOOP_WRITERS_AUDIT. Due equivalenze metamorfiche riguardano
nibble e finestre low9.

Sono controllati112record SR LP_START/LP_END su8PC originali. L’atlante conserva
28record rappresentativi in7run; i PC ripetuti nello stesso run mantengono i
singoli record ma si contano una volta nella verifica dei siti. Risultato:
**14nuovi siti run/PC,160totali,22indici AUX distinti**. Gli otto PC sono nuovi
rispetto al parent; gli indici2/3 erano già presenti. I valori sono operandi
dei setter,non misura dello stato AUX successivo o dell’implementazione Nikon.

## Atlante e conservazione

Risultato: `Risultati/Processor_Registers/20261025T163546Z/REGISTER_MAP.md`,
con JSON,CSV,grafo e `atlas_validation.json`. Ledger SHA-256 di **267file**;
parent`20261025T162034Z`,261file,verificato e immutato. Le chiavi di registro e
le geometrie delle finestre dei **32atlanti precedenti validati** sono tutte
conservate. Le125nuove celle non intersecano registri singoli o finestre
precedenti; nessun alias fisico dedotto.

Copie delle prove: `evidence/ffc7000_loop_writers.json`,
`evidence/ffc7000_loop_writers_audit.json`,
`evidence/ffc7000_loop_writers_linear_navigation.txt`. Il listing lineare è
solo navigazione; gli audit si riallineano ai PC effettivi.
Script correnti: `Python_Trace_Scripts/s33_verify_ffc7000_loop_writers.py`,
`s33_audit_ffc7000_loop_writers.py`, `s33_integrate_ffc7000_loop_writers.py`.

Firmware SHA-256:
`1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`;
Main SHA-256:
`06754a1f451f17b3047fe03cdb83fd08af11dac725638818254ef0de26a5ed29`.

Funzione periferica,permessi,reset,side effect,IRQ,tempi e vincoli dei chiamanti
Nikon restano sconosciuti. Oltre ai wrapper eseguiti,i domini dei due helper
non sono chiusi. Nessun flash,dumper,NAND/vendor,resetUSB o scritturaSD.
Restano aperti il helper3090FC e il wrapper309188 con parametri dalla tabella
originale,altri gruppi MMIO,AUX parametrizzati,candidati codice/dati,BCR e
implementazione reale del SoC. La matematica dell’helper303A40 nel modello DSP
provvisorio resta non verificata indipendentemente. La mappa fisica completa
non è ancora dimostrata e non viene dedotta una percentuale globale.
