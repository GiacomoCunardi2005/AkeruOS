# Registri FE9: dispatcher fissi e helper con maschera

25 ottobre 2026. Atlante ammesso: `Risultati/Processor_Registers/20261025T192207Z/`.
**1052 voci: 64 posizioni core, 197 AUX, 791 indirizzi MMIO singoli.**
I cinque nuovi indirizzi derivano dai pool originali; gli indirizzi scelti per
provare gli helper generici non producono ammissioni o arricchimenti.
Mappa fisica incompleta; hardware non verificato, **NON_INSTALLARE**.

## Prove e ammissioni

- CPU originale GNU ARC700 defined-memory v2, senza modifiche al firmware o a
  GNU: `outputs/gnu_arc700/20261025T183314Z_6d11b579/verified_evidence.json`.
- Audit indipendente: `outputs/gnu_arc700/20261025T183314Z_6d11b579_audit.json`.
  206 istruzioni decodificate al PC esatto e confrontate con i byte originali;
  formule, pool, tabelle, eventi ordinati, fixture e tracce ricontrollati.
- 12 scenari, 24 esecuzioni: 12 coppie osservatore/riferimento con tracce
  identiche; nessun fault, ritorni e ripristino di stack/registri controllati.
- 4184 eventi halfword: **136 fissi (88 letture, 48 scritture)** ammessi come
  prove dei cinque indirizzi; **4048 generici (2112 letture, 1936 scritture)**
  esclusi dalle ammissioni. Le destinazioni sintetiche erano FFB8000/FFB8004:
  le loro precedenti schede nell'atlante sono conservate senza arricchirle.

| Indirizzo | Entry originale | Operazione software |
|---|---|---|
| `0x0FFC7070` | `0x309884` | Lettura completa dei 16 bit |
| `0x0FE9013C` | `0x309A2C` | Selettore 0: RMW low10; selettore 1: lettura full16 |
| `0x0FE90140` | `0x309A2C` | Selettore 2: RMW low10; selettore 3: cancellazione con maschera argomento |
| `0x0FE9813C` | `0x309C44` | Selettore 0: RMW low11; selettore 1: lettura full16 |
| `0x0FE98140` | `0x309C44` | Selettore 2: RMW low11; selettore 3: cancellazione con maschera argomento |

## Due dispatcher simili, campi diversi

Le due tabelle originali signed16, a `309A48` e `309C60`, contengono
`[4,41,20,32]`. Il target è `base_tabella + 2*elemento`; la CPU carica proprio
questi elementi, senza sostituire la tabella con una fixture.

Per l'argomento valore `v`, lo stato halfword `old` e la maschera di campo `m`:

| Selettore unsigned | Effetto | Ritorno |
|---|---|---|
| 0 | Primo indirizzo: `(old & ~m) | (v & m)` | 0 |
| 1 | Legge il primo indirizzo completo, senza maschera low10/11 | Valore letto |
| 2 | Secondo indirizzo: `(old & ~m) | (v & m)` | 0 |
| 3 | Secondo indirizzo: `old & (~v & 0xFFFF)` | 0 |
| maggiore di 3 | Nessun MMIO | `0x55AA` |

`m=0x03FF` per `309A2C`, `m=0x07FF` per `309C44`. Il selettore 3 usa
l'intera maschera halfword, anche fuori dal campo dei selettori 0/2.
Provati anche selettori `4`, `255`, `0x7FFFFFFF`, `0x80000000`, `0xFFFFFFFF`.
`55AA` è il risultato locale di queste routine, non una convenzione universale.

## Venti helper: contratto software senza dominio di destinazione chiuso

Le due famiglie contengono ciascuna un first-set-bit puro, sei setter di campo,
un setter/clear di un bit, uno split store e un getter mascherato.

| Tipo | Prima famiglia | Seconda famiglia |
|---|---|---|
| First-set-bit | `30989C` | `309AB4` |
| Setter di campo | `3098B8,309918,309944,309970,30999C,3099E4` | `309AD0,309B30,309B5C,309B88,309BB4,309BE0` |
| Flag | `3098E4` | `309AFC` |
| Split store | `3099C8` | `309C0C` |
| Getter | `309A10` | `309C28` |

Il first-set-bit cerca soltanto i bit 0–15 e restituisce **15 anche quando non
ne trova nessuno**. I due corpi hanno byte identici. Indicando con `s` quel
risultato e con `mask` l'argomento maschera:

- Setter: `((old & ~mask) | ((value << s) & mask)) & 0xFFFF`.
  Una maschera sparsa resta sparsa; non compatta i bit del valore.
- Flag: azzera il solo bit `s` se l'argomento flag è zero, lo imposta per
  qualsiasi argomento nonzero. Con maschera zero o solo bit alti, seleziona
  bit15: verificati 96 casi relativi a maschere `0`, `0x10000`, `0x80000000`.
  Non è una prova di difetto della fotocamera: la legalità di questi argomenti
  nei chiamanti Nikon resta da stabilire.
- Split: scrive low16 a `dest`, poi high16 a `dest+4`, con due store distinti.
- Getter: `((old & mask) >> s) & 0xFFFF`.

Provate 24 maschere, compresi ciascun bit basso isolato, maschere sparse,
zero, sole parti alte e tutti i bit. Gli indirizzi MMIO di queste prove sono
input del laboratorio; il contratto non delimita le destinazioni Nikon.

## Censimento delle chiamate e prossimi vincoli

La ricerca nei 16 payload verificati restituisce 37 candidati BL e nessun
puntatore word LE/ME verso le 23 entry esaminate. **36 sono istruzioni BL
qualificate**; il candidato `30AA10 → 309A10` cade dentro gli 8 byte di
`and r3,r0,0xFC00` a `30AA0A` ed è escluso sul percorso locale allineato.
Il censimento non esclude chiamate indirette o altri percorsi globali.

18 chiamate qualificate sono interne agli helper; altre 18 arrivano da nove
wrapper in `2EE760..2EE9C4`. Le tabelle di puntatori e maschere vengono
indicizzate tramite `base+4*indice`; i wrapper non mostrano un controllo
locale dell'intervallo. Non ammettere tutte le parole vicine come registri.

Prima ricognizione statica, non ancora prova CPU dei wrapper:

- Il selettore `2ED448` confronta l'argomento con zero e normalizza ogni
  nonzero a 1; non dimostra il significato fisico dei due rami.
- I 32 pool a `2EEA08..2EEA84` puntano a `40CA24..40D01C`, nel **payload 1**
  originale, caricato come candidato a `360800..428600`; non nel Main0.
  Una successiva prova deve caricare quei dati originali, anziché inventarli.
- Il wrapper `2EE9C4`, dopo la lettura in modo1, applica anche una AND con
  una parola della tabella puntata da `2EEA84`, indipendentemente dal ramo
  selezionato. Il risultato del wrapper può quindi differire dalla lettura
  full16 del dispatcher. Questo percorso richiede verifica separata.

## Conservazione e limiti

Il nuovo ledger comprende 286 file. Il parent `20261025T182643Z` (279 file)
è immutato; ricontrollati i ledger e la copertura di tutti i 37 atlanti
precedenti validati. Nessuna chiave o geometria persa. Tutte le 786 schede
MMIO precedenti rimangono identiche.

Conservati 50 transfer window, 3408 appartenenze, 3376 indirizzi di cella
distinti, 32 ripetizioni, due intersezioni fra finestre e una con uno scalare;
nessun alias fisico dedotto. AUX invariati: 22 indici con prove guest e
172 siti run-PC. Nessun nuovo LR/SR da questi test.

Il primo tentativo `183254Z_ed21f758` è conservato come FAIL: la finestra
statica terminava dentro un pool, prima delle prove CPU. L'audit del run
successivo inizialmente usava un offset errato per il delay slot del flag:
corretto da entry+8 a entry+10, senza cambiare firmware o ripetere la CPU.

Reset, permessi, W1C/FIFO, IRQ, temporizzazioni, atomicità, domini dei chiamanti,
BCR e matematica DSP restano aperti. Le fixture non sono misure del silicio.
