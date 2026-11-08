# Nikon S33 — espansione verificata della mappa registri

25 ottobre 2026, Europe/Rome. Gli identificativi delle directory restano in UTC.
**Obiettivo completo ancora aperto: non è una mappa fisica esaustiva del SoC.**

La [nuova mappa](../Risultati/Processor_Registers/20261024T230135Z/REGISTER_MAP.md)
conserva la versione precedente e raccoglie **346 voci**: 64 posizioni core,
113 indici AUX e 169 indirizzi MMIO. Dei 115 indirizzi inizialmente sostenuti
soltanto da costanti nei pool, tutti hanno ora una prova di accesso del codice.
Questo risultato riguarda quell'insieme iniziale, non tutti i registri fisici.

Formati: [JSON](../Risultati/Processor_Registers/20261024T230135Z/register_map.json),
[CSV](../Risultati/Processor_Registers/20261024T230135Z/register_map.csv),
[grafo delle fonti](../Risultati/Processor_Registers/20261024T230135Z/graph.html).

## Prove aggiunte

| Ambito | Risultato | Limite |
|---|---|---|
| Banco ausiliario FFCA | 38 candidati risolti; 47 indirizzi, 169 accessi, 87 maschere software | CFG locale e byte verificati; semantica fisica e raggiungibilità globale ignote |
| Sensore/runtime e tuning | 717 operazioni memoria osservate direttamente nel simulatore | Celle di storage sintetiche; nessuna risposta di periferica reale |
| Inizializzazione TBIB | 12 celle con scritture originali a 16 bit; tre replay identici | I readback del chiamante sintetico sono esclusi dalle letture originali |
| AUX custom | 19 indici concreti risolti da chiamanti e argomenti; nuove famiglie parametrizzate | Indici oltre 2047 non eseguiti nel banco GNU attuale |
| IDENTITY/cache | Nuovi siti e chiamanti verificati nei byte | Il confronto con 0x13030513 è software, non un'identificazione hardware misurata |

La verifica statica FFCA controlla 1.150 sequenze di byte, 1.077 transizioni CFG,
169 risoluzioni pool e 169 coppie opcode/larghezza. Ogni prova primaria evita
chiamate fra il caricamento del pool e l'accesso. Il percorso FFCA00C conserva
esplicitamente una condizione sull'argomento; non viene dichiarato incondizionato.

## Osservazione memoria senza modificare GNU

Il nuovo frontend esterno usa `--wrap` del linker per sei accessor libsim:
read/write aligned1, unaligned2 e unaligned4. Per ciascun accesso conserva
PC, indirizzo effettivo, larghezza e valore. Ogni wrapper delega esattamente una
volta all'accessor originale. Un evento iniziale senza risultato è un tentativo;
un risultato di scrittura prova il ritorno dell'accessor, non persistenza fisica.
Sono esclusi fetch istruzioni, DMA e trasferimenti che non passano da questi sei
accessor. Il filtro numerico è 0F000000–0FFFFFFF, non una dichiarazione di spazio
MMIO fisico valido.

I primi 470 eventi sensore coincidono, in ordine, con le tuple ricavate dalle
tracce indipendenti: PC/indirizzo/operazione/larghezza/valore. I 247 successivi
portano il totale a 717. Tutti i replay hanno tracce guest byte-identiche alle
rispettive tracce di riferimento. Sono 14 replay complessivi: tre TBIB e undici
sensore, inclusa una chiamata che si arresta dopo una lettura valida.

Un primo replay sensore era stato respinto perché il file di fixture conservava
il valore finale del run precedente. I replay accettati ricreano le celle dai
`fixtures.before` registrati e, quando necessario, i payload iniziali dai byte
hash-verificati del contenitore originale. I valori non sono ricavati dalla
traccia da confrontare. Originali e librerie GNU restano montati in sola lettura;
sono scritte soltanto nuove copie laboratorio degli ingressi e nuovi risultati.

## Condizioni e nuove correzioni

- La finestra storica 60FA40 inizia nel literal pool saltato dal firmware;
  non è un ingresso chiamabile. La routine runtime usata dai probe parte da
  60F8B4, con prologo e ritorno verificati.
- I probe supplementari impostano RAM 681145=1 nel chiamante sintetico: il codice
  originale legge il flag prima di un ramo di aggiornamento. È una condizione
  del banco di prova, non uno stato Nikon osservato. Non cambia alcuna istruzione
  originale né alcuna semantica del simulatore.
- FF98118, FF980B4, FF980C4 e FF98068 sono stati collegati ad accessi effettivi,
  anche quando mancavano nel censimento iniziale dei literal pool. FF98068 era
  il read16 che fermava il primo probe 6127E4; una cella di storage dedicata e
  dichiarata ha permesso la successiva verifica del percorso.
- FF900E0 ha un read16 con risultato a 797D24, seguito da un arresto sulla RAM
  non dichiarata 899614 a 79F152. Solo la lettura è promossa: completamento della
  routine e stato richiesto dal chiamante restano non provati.
- Le due condizioni del tuning precedente comprendono il DSP provvisorio già
  esistente, esplicitamente configurato dal chiamante. Non certificano l'estensione
  DSP del silicio Nikon.

## AUX oltre il modello corrente

I chiamanti risolvono 19 indici della famiglia
`0x10800 + (channel << 8) + offset`, per canali concreti 0–4 e soli offset
effettivamente verificati. Non viene generato il prodotto cartesiano di tutti
i canali e gli offset. Gli accessi sono LR/SR AUX, non load/store MMIO.

Le famiglie `0x10010 + r0`, `0x10020/21 + 2*r0` e il possibile ciclo
`0x10223 + i` restano parametrizzate o candidate: origine dei valori e chiamanti
non sono tutti risolti. Non sono aggiunti 85 registri fisici solo perché il
loop usa un conteggio 85. Un candidato LR dinamico a 3514C0 è stato respinto:
i byte appartengono a stringhe di formato `%u,%u,...`.

Non è stata allargata la banca GNU per far passare questi accessi. Il limite API
host/guest AUX512 e il setter STATUS32 senza effetto rimangono quelli già
documentati nella mappa precedente.

## Copertura e audit dell'obiettivo

La mappa conserva campi, maschere e prove con classificazioni separate. Le
definizioni architetturali, i nomi toolchain, il CFG statico, gli accessi CPU e
le fixture non sono trasformati in fatti hardware. Restano non determinati:

- configurazione fisica Nikon e valori BCR, estensioni custom/DSP implementate;
- insieme completo dei registri MMIO oltre gli indirizzi del censimento corrente;
- argomenti AUX dinamici e percorsi non raggiunti o senza chiamanti confermati;
- reset, FIFO/W1C, IRQ, DMA/cache, temporizzazioni e altri effetti reali.

Il superamento dei 115 candidati iniziali **non completa l'obiettivo generale**.
La verifica REA 6.7 conservata respinge ancora l'ammissione dell'ELF ARC;
nessun backend IDA per ARC è certificato da questo atlante. GNU resta il motore
CPU usato per queste prove.

Nessun accesso hardware, flash, comando NAND/vendor, reset USB o scrittura SD.
**NON_INSTALLARE** invariato.
