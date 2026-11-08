# Copertura dell’esecuzione ASM e affidabilità del modello

20 ottobre 2026 — R3/R4. **Avvio incompleto, NO-GO flash e circa 10% funzionale invariati.** Le sei domande dell’utente restano l’ambito del lavoro; questa verifica misura il percorso raggiunto, mette alla prova gli zeri iniziali e risolve l’origine locale di r0 nei due ingressi osservati. Non certifica tutto il processore.

[Script riproducibile](../Python_Trace_Scripts/s33_audit_execution_coverage.py), [manifest della nuova esecuzione](../outputs/gnu_arc700/20261020T121732Z_315899bc/verified_evidence.json), [indirizzi distinti](../outputs/gnu_arc700/20261020T121732Z_315899bc/unique_pc.txt), [riscontri nel listato](../outputs/gnu_arc700/20261020T121732Z_315899bc/matched_listing.txt). Comando dalla radice: `python3 Python_Trace_Scripts/s33_audit_execution_coverage.py`, senza `-O`. Ogni esecuzione conserva una nuova directory; nessun report precedente è sovrascritto.

## Quanto ASM raggiungiamo davvero?

Il profilo Main GNU DSPv7/sorgente software vuota è quello descritto nel [checkpoint IRQ](S33_GNU_Sorgente_IRQ_Software_e_Proseguimento_Main.md). È stato rieseguito, senza filtro di indirizzi nella traccia, conservando lo stesso ELF, motore e input MMIO. Il riempimento zero riproduce esattamente l’hash della traccia precedente.

| Misura Main | Risultato |
|---|---:|
| Contatore GNU e record di istruzione della traccia | 583.306 |
| Indirizzi distinti raggiunti, incluso l’arresto | 3.194 |
| Indirizzi distinti del prefisso, escluso quello del fault finale | 3.193 |
| Di questi, indirizzi nel payload MainCode | 3.192 |
| Indirizzo fuori Main, nel vettore RAM eseguito quattro volte | 0x00000818 |
| Indirizzi Main coincidenti con un inizio riga del listato lineare | 3.168 |
| Altri indirizzi Main riancorati separatamente con GNU | 24 |

La lettura che ferma la prova è ancora halfword `0x0FED2018` a `0x169A84`. Escludere l’indirizzo del fault è una misura prudente del prefisso: non possediamo un oracolo di istruzioni ritirate e non attribuiamo a quel tentativo un’esecuzione completata.

Le 3.168 righe direttamente confrontabili sono **0,320604% delle 988.135 righe candidate MainCode** e **0,051718% delle 6.125.576 righe dell’intero listato**: circa **0,32% del listato Main** o **0,052% del listato complessivo**, per questo specifico esperimento. Non sono la percentuale del vero codice eseguibile Nikon: i denominatori includono dati interpretati come codice, altre regioni e fasi; l’intero listato comprende anche dati espliciti. Non sono una percentuale di completamento dell’avvio, del progetto, delle funzioni fotografiche o di tutti i test mai eseguiti.

I 24 inizi mancanti nel listato lineare sono stati controllati individualmente con GNU partendo dal PC effettivamente raggiunto; i disassemblaggi e l’elenco sono nel manifest. Per esempio `0x17A53C` è un vero inizio osservato che il listato lineare non rappresentava come riga autonoma. Questo spiega anche precedenti difficoltà di disassemblaggio a partire da quel punto. Il listato grande non viene rigenerato né trasformato in un CFG certificato.

La baseline TBIB è stata rieseguita separatamente: **10.952 nel profiler, 10.954 record, 1.111 indirizzi raggiunti, 1.110 escludendo il fault a 0x01009B6A**. Lo scarto di due record resta aperto. Questo è il profilo TBIB di riferimento, non quello periferico più avanzato dei rapporti storici. Non sommare i due percorsi come se fossero un unico avvio concatenato.

## 1. Quante istruzioni hanno semantica verificata?

**Una percentuale globale attendibile non è ancora disponibile. Esecuzione riuscita non equivale a semantica indipendentemente verificata.** I test esistenti controllano forme e contratti specifici; non abbiamo ancora associato a ciascuno dei 3.193 indirizzi, con i suoi operandi, flag, alias e contesto di esecuzione, un controllo indipendente pertinente.

Le correzioni SLEIGH di alias `ld.ab`, lettura STATUS32 e uscita LP restano verifiche limitate dei rispettivi rapporti. Non certificano tutte le altre forme SLEIGH né il motore GNU, che è un’implementazione distinta. Anche in GNU sono stati trovati successivamente difetti AUX/bounds e SR nel delay slot: dunque ulteriori errori sono una possibilità concreta da verificare.

Nella nuova traccia Main ci sono **132 etichette mnemoniche**, non 132 operazioni ISA certificate. Tre indirizzi DSP (`0x17A6F8`, `0x3342B4`, `0x3342BC`), eseguiti cinque volte in totale, usano esplicitamente il modello provvisorio. La traccia li etichetta `mululw`, mentre i byte e il log del modello distinguono MULDW/MULUDW. Contare i soli nomi stampati produrrebbe una copertura semantica ingannevole. Gli altri indirizzi non sono automaticamente certificati per esclusione.

Prossimo: inventario per byte/formato e confronto puntuale fra i due motori e le aspettative ISA già documentate, prima dei confini hardware; flag, delay slot e LP devono far parte del confronto, non soltanto il valore finale di r0.

## 2. Concatenare TBIB e Main conservando lo stato

È l’esperimento corretto da preparare. **Queste prove restano due ingressi distinti**, con ELF e contesto iniziale di laboratorio; la presenza contemporanea dei byte TBIB e Main nella mappa non dimostra che TBIB abbia caricato Main o gli abbia ceduto il controllo.

Per una concatenazione valida dobbiamo raggiungere la vera sequenza Nikon di lettura/copia/validazione e il salto finale, conservando nella stessa CPU RAM, registri, AUX, timer, interrupt e modifiche alla mappa. Spostare manualmente il PC a BB540, oppure precaricare una destinazione che il caricatore non riesce ancora a produrre, non dimostra il passaggio richiesto. Gli arresti periferici TBIB precedono quel raccordo: il caricamento da supporto e il passaggio effettivo restano da risolvere.

## 3. Gli zeri possono nascondere letture illegittime?

**Il motore GNU attuale può leggere RAM mai scritta ottenendo zero. Non traccia la provenienza di ogni byte.** Il profilo P-code `unknown` dei rapporti precedenti ha invece un arresto sulle letture non inizializzate nel perimetro modellato; non è una proprietà trasferibile automaticamente al motore GNU.

Nuova verifica: tre ingressi Main con RAM iniziale rispettivamente `00`, `A5`, `5A`, stessi quattro registri clock halfword sintetici zero e stesso motore DSPv7. Tre piccoli probe separati leggono `0x07000000` e controllano `0x00000000`, `0xA5A5A5A5`, `0x5A5A5A5A`: il riempimento diverso è stato effettivamente applicato. Quell’indirizzo è una sentinella del laboratorio, non RAM libera assegnata alla Nikon.

**Tutte e tre le tracce Main sono identiche byte per byte**, compresi risultati dei registri stampati e arresto finale. Nel prefisso esplorato non emerge quindi una dipendenza osservabile dal riempimento di quei buchi RAM. Questo è un controllo favorevole, non una prova che nessuna lettura sconosciuta avvenga: valori non usati, dipendenze che si cancellano, flag non stampati, campi non tracciati e percorsi diversi restano possibili.

I payload ELF, le sezioni NOBITS/stack inizializzate dal caricatore, i registri CPU, AUX e gli input MMIO rimangono identici nei tre esperimenti. Gli zeri già contenuti nei payload sono byte verificati del campione, ma il loro corretto caricamento al reset è ancora da dimostrare. Serve un controllo esplicito lettura-prima-della-scrittura anche in GNU, includendo fetch, accessi parziali e dati realmente caricati; il test dei tre riempimenti non lo sostituisce.

## 4. Provenienza effettiva di r0 nel selettore 12/13

La nuova traccia Main osserva due chiamate al selettore `0x12CA28`:

- `0x29F65C` chiama il wrapper `0x231420`; nel delay slot del suo salto verso il selettore, **0x231424 esegue `mov_s r0,0`**.
- `0x29F678` chiama lo stesso wrapper, che imposta nuovamente r0 a zero.

La baseline TBIB appena rieseguita mostra la sequenza corrispondente: `0x0101F558` chiama `0x010139D0`; **0x010139D4 imposta r0 a zero nel delay slot** del salto a `0x01009E54`. Le tre finestre Main e quella TBIB sono state ricontrollate con GNU, oltre agli assert sulle sequenze della traccia.

Pertanto **in questi ingressi r0 è deciso dal wrapper Nikon, non dal valore zero iniziale imposto dall’host**. Il selettore deve consultare il bit7 di FE800F8: nei profili zero osservati sceglie13. Il ramo r0 nonzero, già verificato isolatamente come selezione12 senza lettura F8, resta un percorso distinto; non è dimostrato chi lo scelga in tutte le fasi operative.

## 5. Configurazione delle aree 0x0F79xxxx

Resta aperta. I getter e i consumatori già verificati provano l’uso software delle basi e del workspace da16KiB, non il codice che configura una finestra fisica. Prima bisogna distinguere RAM, alias, SRAM di un dispositivo o aperture fisse: non è ancora provato che serva una configurazione dinamica da parte del firmware.

Il nuovo esperimento non raggiunge quelle aree e non le include nella RAM128MiB. Prossimo: risalire dai consumatori e dalle scritture di inizializzazione ai registri di base/banco/controller, con evidenza degli indirizzi effettivi. Non dedurre la capacità fisica dagli indirizzi alti.

## 6. Caricamento e sostituzione dei blocchi 11–15

Resta aperto quando siano residenti e chi li carichi. I descrittori del contenitore riportano la stessa base candidata `0x01044800`, con estensioni diverse: non sono una cronologia di esecuzione. Non dimostrano da soli un gestore overlay o che tutti siano codice anziché dati/risorse per fasi diverse.

Main e TBIB di questa verifica non caricano gli11–15. Prossimo: collegare indice/tipo/lunghezza del descrittore al lettore, alla copia/decompressione, alle destinazioni e ai salti dei consumatori. Finché tale collegamento manca, mantenere mappe e disassemblaggi separati; nessuna fusione in RAM per far avanzare il boot.

## Controlli e limiti della consegna

Sette casi GNU appena eseguiti: baseline TBIB, tre sentinelle di riempimento, tre ingressi Main. Ventotto disassemblaggi mirati: tre finestre selettore Main, una TBIB, ventiquattro riancoraggi. Verificati SHA del firmware V1.1 originale29.602.084byte,16payload, input/output del checkpoint Main precedente, motore DSPv7 e intero ASM399.542.290byte. I file e le tracce sono firmati nel manifest; il primo tentativo d’audit, fermato dall’assert che assumeva erroneamente tutti i PC dentro Main, è conservato. Il PC aggiuntivo818 viene ora contato separatamente, senza attribuirlo a un guasto Nikon.

Non sono stati rieseguiti tutti i test semantici storici e nessuno dei sette casi è una prova hardware. Restano modelloDSP provvisorio, timer/interrupt non certificati, memoria ignota senza tracking GNU e handoff reale non raggiunto. Nessun firmware Nikon modificato, comando USB/PTP o scrittura sulla fotocamera. Prossimo punto utile: tracciamento della provenienza delle letture e inventario semantico dei PC raggiunti, poi passaggio TBIB→Main con stato conservato.

## Continuazione: tracking RAM esplicito in GNU

La [nuova variante defined_memory_v2](S33_GNU_RAM_Definita_e_Letture_Prima_Scrittura.md) supera29casi e controlla provenienza perbyte negli accessiCGEN;Main583306 mantiene l’intera traccia precedente senza segnalazioniundefined. Il runner Main ordinario resta sulmodello precedente: il tracking viene attivato dalnuovo verificatore. Non copreCPUregisterinit,DMA,ognihostcallback oMMIOalto;semanticaDSP e boot completo ancoraaperti.
