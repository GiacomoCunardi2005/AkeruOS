# AkeruOS — Mono RAW Luminance

Data di registrazione: **27 ottobre 2026**.

Fonte: proposta fornita dall'utente nella conversazione. Questa nota conserva
lo studio e i relativi limiti; non documenta una modalità implementata o un
frame RAW acquisito. La richiesta riguarda memoria e documentazione, senza
avviare un nuovo obiettivo operativo di sviluppo o ricerca firmware.

Ricerca successiva del 27 ottobre 2026: [HiddenMenu, flag RAW e percorso da
26,53 MB](S33_HiddenMenu_RAW_Massimo_20261027.md). Individuati flag e lunghezza
di esportazione nel codice V1.1; nessun frame reale o packing verificato.

## Obiettivo

Ottenere un'immagine B/N dai dati del sensore prima della normale elaborazione
colore, usando tutti i fotositi disponibili. La proposta è una pipeline
monocromatica dedicata per controllare dettaglio, rumore, contrasto e tonalità.

La S33 produce fotografie da **4160 × 3120 pixel**, ossia 12.979.200 pixel.
Il sensore è CMOS a filtri di colore primari. La disposizione precisa del CFA
non è accertata in questo studio: **Bayer RGGB è soltanto il modello ipotetico**.
Anche la profondità dei campioni RAW resta da identificare.

## Pipeline proposta

1. Sensore CMOS: circa 13 milioni di campioni filtrati R/G/B.
2. Accesso al RAW lineare.
3. Correzione del black level e dei difetti del sensore.
4. Ricostruzione monocromatica: stima della luminanza, combinazione dei campioni,
   riduzione degli artefatti.
5. Sviluppo fotografico B/N: curve tonali, contrasto e gestione del rumore.
6. JPEG monocromatico e conservazione del RAW originale, con salvataggio su SD
   **se supportato dalla pipeline e dopo la relativa verifica**.

Rispetto a Mono Green RAW non vengono scartati i campioni rossi e blu: servono
a stimare la luminosità e a distinguere, per quanto possibile, variazioni di
colore e variazioni di intensità. Ogni fotosito misura comunque una sola
componente filtrata: resta necessaria una ricostruzione spaziale delle
informazioni mancanti. Non si ottengono 13 milioni di misurazioni monocromatiche
indipendenti come con un sensore senza CFA.

## Ricostruzione della luminanza

Nel modello Bayer ogni posizione registra una sola componente; le altre si
stimano dai campioni circostanti. Per RGB **lineare calibrato nelle primarie
sRGB/BT.709**, la luminanza relativa è:

\[
Y = 0.2126R + 0.7152G + 0.0722B
\]

Questi coefficienti **non vanno applicati direttamente ai valori RAW nativi**:
risposta spettrale del sensore e spazio RGB standard sono differenti.

### A. Linear RGB Luminance

Ricostruire RGB in alta precisione, convertirlo nello spazio colore calibrato
e calcolare soltanto Y. Si evitano le elaborazioni estetiche della pipeline
JPEG originale, ma **non la demosaicizzazione**.

È il riferimento qualitativo proposto, più semplice da validare e con libertà
di elaborazione tonale.

### B. Direct RAW Luminance

Stimare direttamente la luminanza dalla struttura Bayer: usare i campioni verdi
per il dettaglio ad alta frequenza e rossi/blu per correggere la risposta ai
colori e ricostruire le variazioni tonali.

Potrebbe richiedere meno memoria e operazioni della pipeline RGB completa,
ma qualità e convenienza dipendono dall'algoritmo di interpolazione e devono
essere misurate. **Non è ancora un algoritmo validato sulla S33**.

Ordine sperimentale suggerito nella proposta: prima A come riferimento, poi B
per cercare vantaggi di velocità e qualità. Il confronto deve includere anche
Green RAW sul medesimo fotogramma.

## Confronto con il JPEG B/N convenzionale

Un miglioramento è possibile, ma non garantito.

| Caratteristica | JPEG B/N convenzionale | Mono RAW Luminance |
| --- | --- | --- |
| Risoluzione del file | 13 MP | Fino a 13 MP |
| Accesso al RAW | Non richiesto | Necessario |
| Controllo delle tonalità | Limitato dopo il JPEG | Ampio, prima della codifica |
| Dettaglio fine | Dipende dall'ISP Nikon | Dipende dall'algoritmo |
| Rumore | Elaborato dall'ISP | Personalizzabile |
| Gamma dinamica | Limitata dal JPEG finale | Maggior controllo prima del JPEG |
| Sensibilità fisica | Invariata | Invariata |

La risoluzione del file non garantisce il dettaglio effettivo di un vero sensore
monocromatico da 13 MP. Il controllo tonale permetterebbe, per esempio, di variare
la resa relativa di un edificio rosso e di una facciata verde durante lo sviluppo
RAW. Il JPEG finale mantiene i propri limiti di codifica.

## Profili sperimentali B/N

Tre profili proposti per la ricostruzione, non soltanto filtri dopo lo scatto:

| Profilo | Intento |
| --- | --- |
| Natural | Luminanza calibrata e risposta tonale equilibrata |
| Green Detail | Sperimentare una maggiore enfasi sul contributo verde |
| Red Emphasis | Sperimentare una maggiore enfasi sul contributo rosso |

Per Natural i pesi illustrativi arrotondati sono **21% R, 72% G, 7% B**, riferiti
a RGB lineare calibrato. Non sono una calibrazione del sensore S33. La proposta
non specifica pesi numerici per Green Detail e Red Emphasis.

Pesi regolabili dall'utente, con Natural predefinito, restano un'idea opzionale
da valutare; non sono una funzione implementata o richiesta in questa attività.

## RAM e ISP

Dimensioni indicative di un singolo buffer da 4160 × 3120, senza compressione
né padding; **MB decimali**:

| Formato intermedio | Memoria |
| --- | ---: |
| RAW packed 10 bit | 16,2 MB |
| RAW packed 12 bit | 19,5 MB |
| RAW 16 bit | 26,0 MB |
| RGB 16 bit per canale | 77,9 MB |
| Monocromatico 8 bit | 13,0 MB |

10 e 12 bit sono scenari di calcolo, non profondità RAW accertate della S33.
Questi valori non rappresentano il consumo totale della pipeline o la RAM
fisica disponibile. La conversione RGB completa potrebbe essere impegnativa
per il processore ARC700; alternative da studiare sono elaborazione per righe
o strisce, riuso dei buffer originali e accelerazione ISP se accessibile.
Il riuso richiede prima di conoscere proprietà, durata e sincronizzazione dei
buffer; uno spazio vuoto nel firmware non prova RAM libera.

## Collegamenti con le evidenze AkeruOS

- [Ingresso del servizio di acquisizione](S33_Ingresso_Acquisizione.md):
  documenta il servizio CapMgr `0x14AA24`, il passaggio della richiesta al task
  e i meccanismi di sincronizzazione. Non identifica un'uscita RAW utilizzabile
  e non fornisce un prototipo C completamente validato.
- [Dumper RAM: binding SD e ABI](S33_Dumper_RAM_Binding_SD_ABI.md):
  ricostruisce il percorso originale di scrittura e i suoi limiti. Non dimostra
  che si possa acquisire e salvare un fotogramma RAW prodotto dalla fotocamera.
  Stato, conteggio scritto, errori, close e persistenza restano distinti.

Gli indirizzi appartengono alle analisi/versioni documentate nelle fonti:
non trasferirli ad altre versioni senza riscontro. Le evidenze statiche e
le prove con fixture non equivalgono a una cattura reale.

## Ricerca futura suggerita

1. Identificare CFA e profondità dei campioni dai registri del sensore o dell'ISP.
2. Localizzare il buffer precedente alla demosaicizzazione e distinguerlo da
   YUV e JPEG.
3. Verificare la possibilità di acquisirlo senza alterare l'elaborazione
   originale, inizialmente in emulazione; la prova reale resta separata.
4. Confrontare Green RAW, Linear RGB Luminance e Direct RAW Luminance sullo
   stesso RAW.

L'esperimento decisivo proposto è ottenere un singolo frame RAW reale della
S33, elaborarlo sul PC con Python e confrontare dettaglio, rumore e tonalità
prima di implementare il processamento sulla fotocamera. Questi passi sono
una traccia di ricerca conservata, non attività eseguite in questa sessione.

## Limiti e provenienza

Mono RAW Luminance resta una proposta software derivata da un sensore a colori.
Direct RAW Luminance è la variante di maggiore interesse nella proposta per
il possibile risparmio rispetto a RGB completo, ancora da dimostrare.
Il salto fisico di sensibilità di un sensore senza CFA non si ottiene via
software mantenendo i filtri sul sensore.

Il testo fornito menziona Nikon e Imatest, ma i collegamenti incollati sono
favicon e non pagine tecniche utilizzabili come citazioni. Non sono stati
convertiti in fonti verificate. In questa attività sono stati controllati i
due riferimenti locali sopra; non è stata svolta una nuova verifica web delle
specifiche o delle formule, né un'analisi firmware aggiuntiva.

Nessun algoritmo implementato, prova hardware o modifica al firmware.
I candidati del progetto mantengono lo stato **NON_INSTALLARE**.
