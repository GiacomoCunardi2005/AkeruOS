# Nikon S33: writer FFC7000 da struttura RAM

25 ottobre 2026. Mappa fisica incompleta; obiettivo attivo. Nessun accesso
hardware, nessuna modifica a GNU o firmware originali. NON_INSTALLARE.

Sono mappate **38 nuove celle di trasferimento in due finestre**, con offset
d’ingresso, maschere e ordine originali. Il catalogo resta di **1.024 voci:
64 posizioni core,197 indici AUX,763 indirizzi MMIO singoli**. Le38celle non
vengono promosse a38registri di controllo indipendenti. Le posizioni core
comprendono encoding opzionali/riservati/speciali, senza prova di altrettanti
registri fisici.

Il totale delle finestre passa da22a**24**, con **3.156 appartenenze di cella e
3.124 indirizzi distinti**. Restano32ripetizioni tra finestre e il parametro
FF74088 condiviso con una finestra. Le due famiglie MMIO indicizzate conservano
domini dei chiamanti irrisolti. Nessuna percentuale globale fisica è dimostrata.

## Fonte originale ed esecuzioni

Writer selezionato: entry`308A74`, fine del corpo locale`308ED4`.
Fonte CPU:
`outputs/gnu_arc700/20261025T161433Z_ef92bed1/verified_evidence.json`,
stato PASS_FFC7000_BUFFER_WRITER. Otto scenari/16run,una chiamata al writer
per run. Completati **608accessi MMIO halfword:304letture e304scritture**.
Sono verificate anche le38letture halfword dall’input per ciascun run osservato.
Tutte le otto coppie di tracce osservatore spento/acceso sono identiche byte
per byte. SP e sentinelle r13..r19 sono conservati al ritorno.

Il buffer sintetico è mappato a700000 per126byte. Il writer legge38halfword,
con offset massimo124. Il buffer rimane immutato. L’input non è una
rivendicazione di RAM fisica libera o una definizione completa della struttura
Nikon usata dagli altri chiamanti.

## Mappa delle uscite e ordine effettivo

Le righe seguenti sono nell’ordine del writer. Ogni destinazione viene prima
letta, poi scritta; gli indirizzi delle celle hanno passo quattro byte.

| Destinazioni | Offset halfword nell’input, in byte | Campi | Celle |
|---|---|---|---:|
| `FFC71B8`, `FFC71BC` |38,40| Copia completa16bit |2|
| `FFC7124..FFC7160` |50..80,passo2| low9,preserva high7 |16|
| `FFC7164..FFC7170` |118..124,passo2| Copia completa16bit |4|
| `FFC7174..FFC7178` |82,84| low9,preserva high7 |2|
| `FFC7180..FFC71B4` |86..112,passo2| low9,preserva high7 |14|

In totale32campi low9 e6campi raw16. Per un campo low9 il risultato è
(vecchio&FE00)|(input_halfword&1FF). Per una copia completa il risultato è
input_halfword; la lettura preliminare del vecchio valore è comunque reale
nell’esecuzione osservata e resta nel conteggio. Non si inferiscono side effect
o permessi della periferica dalla fixture.

Sono rappresentate due finestre:

- `FFC7124..FFC7178`,22celle:16low9,4raw16,2low9;
- `FFC7180..FFC71BC`,16celle:14low9 e2raw16; le ultime due sono scritte prima
  di tutte le altre celle del writer.

Il writer non tocca`FFC717C`. Non viene introdotta una cella fittizia per
riempire il salto; ciò non prova assenza di un registro fisico o RAM libera.
Non si deduce un ordine crescente degli indirizzi dalle finestre: le prove e
il JSON conservano l’ordine effettivo.

## Campi letti, campi ignorati e verifiche metamorfiche

Gli offset delle38halfword lette sono38,40,50..112,118..124,con passo due
negli intervalli. Nell’input di126byte restano25halfword non lette da questo
writer: offset0..36,42..48,114,116. Questo non significa che siano inutilizzati
nell’intera struttura Nikon o da altre routine.

Gli scenari comprendono input tutti zero, tutti FFFF, misti e complementati;
valori di confine nei campi low9 includono1FF,200,8000,FFFF. Seed MMIO0000,
FFFF,A55A,5AA5. Quattro equivalenze confrontano l’intera sequenza delle scritture:

1. input misto contro lo stesso input con i sette bit alti dei32campi low9
   invertiti: uscite identiche;
2. input misto contro lo stesso input con le25halfword non lette invertite:
   uscite identiche;
3. stesso input e seed con secondo argomentoFFFFFFFF: uscite identiche;
4. stesso input e seed con secondo argomento0: uscite identiche.

Il secondo argomento iniziale non contribuisce alle uscite del corpo locale;
il flusso simbolico lo mantiene sconosciuto finché viene sovrascritto, senza
usarlo come oracolo dei valori MMIO. I domini dei chiamanti reali restano ignoti.

## Audit del corpo locale e flusso dei valori

`s33_audit_ffc7000_buffer_writer.py` segue il flusso originale da308A74,
rispettando i salti che scavalcano i literal pool. Decodifica e lega al firmware
**353istruzioni del corpo locale**, ricavando i valori dei pool e propagando
espressioni bit a bit da input e vecchie halfword MMIO fino a ogni store.
Non importa la tabella di slot del verificatore come proprio oracolo.

L’audit deriva38destinazioni e relativi load/input offset/mask/store. Controlla
che ogni store abbia un unico termine di input, che old/value mask siano
complementari nella halfword e che non ci siano altri contributi. Il risultato
è confrontato con gli eventi effettivi del modello e i valori letti dall’input
nelle tracce. Sono verificati ordine, larghezza2byte, tuple PC/indirizzo/valore,
coppie begin/result dell’osservatore, backing finale e gap A5.

Il walker salta il noto helper di salvataggio33412C e termina al ramo verso
l’helper di ritorno334194; le prove CPU eseguono entrambi invariati.
Esito PASS_FFC7000_BUFFER_CFG_DATAFLOW_AUDIT.

## Atlante e conservazione della copertura

Risultato: `Risultati/Processor_Registers/20261025T162034Z/REGISTER_MAP.md`,
con JSON,CSV,grafo e `atlas_validation.json`. Ledger SHA-256 di**261file**;
parent`20261025T160624Z`,255file,verificato e immutato.
Le voci singole e i manifest AUX rimangono invariati:22indici guest e146siti
run/PC. Nessun nuovo SR nelle tracce selezionate.

`coverage_lineage_audit.json` conserva tutte le chiavi dei**31atlanti
precedenti validati** e ora verifica anche che tutte le loro geometrie di
finestra siano presenti. Le nuove finestre non intersecano registri singoli
o finestre precedenti; contratti, varianti e fonti già consolidati sono conservati.

Copie delle prove: `evidence/ffc7000_buffer_writer.json`,
`evidence/ffc7000_buffer_writer_audit.json`,
`evidence/ffc7000_buffer_writer_linear_navigation.txt`. Il listing lineare è
solo navigazione; il walker segue i PC e salti effettivi.
Script correnti: `Python_Trace_Scripts/s33_verify_ffc7000_buffer_writer.py`,
`s33_audit_ffc7000_buffer_writer.py`, `s33_integrate_ffc7000_buffer_writer.py`.

Firmware SHA-256:
`1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`;
Main SHA-256:
`06754a1f451f17b3047fe03cdb83fd08af11dac725638818254ef0de26a5ed29`.

Backing,seed,stack e input sono fixture,non reset o RAM fisica libera.
Funzione periferica,permessi,side effect,IRQ,tempi e vincoli dei chiamanti
rimangono sconosciuti. Nessun flash,dumper,NAND/vendor,resetUSB o scritturaSD.
Restano aperti i loop writer da308ED4,altri blocchi MMIO,domini indicizzati,
AUX codice/dati,BCR e implementazione reale del SoC. La matematica
dell’helper303A40 nel modello DSP provvisorio resta non verificata
indipendentemente. La mappa fisica completa non è ancora dimostrata.
