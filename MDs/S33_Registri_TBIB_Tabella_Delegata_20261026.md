# S33 — tabella delegata 1014B08 e tre celle FED38

26 ottobre 2026. Firmware V1.1, CPU GNU ARC700 con MMIO e contesto kernel
modellati. Nessun hardware; NON_INSTALLARE.

## Risultato

Atlante `Risultati/Processor_Registers/20261026T111110Z/`: **1265 voci**,
64 posizioni core / 200 AUX / 1001 MMIO. Aggiunti FED3814, FED3818 e FED3830.
Ledger di 340 file verificato; nessuna perdita di chiavi o geometrie rispetto
ai 47 atlanti PASS precedenti. Restano invariati 25 indici AUX con semantica
guest, 204 ancore run-PC, 50 finestre e due famiglie calcolate.

Il servizio originale completo 1014B08 carica da due pool lo stesso puntatore
1040800. Il primo gruppo ha header a 1040800 e sette record: per i selettori
3007,3006,3005,3001,3002,3003,3004 i bit sono rispettivamente 6,5,4,3,2,1,0.
Scrive una maschera con un solo bit a FED3818, poi legge e modifica FED3814.

Il secondo gruppo ha header a 104088C e otto record: 4001..4008 corrispondono
ai bit 7..0. Il codice lo raggiunge tramite offset 148/152 dal puntatore del
primo gruppo e modifica FED3830. Non effettua lo store con un solo bit in
questo ramo. FED3834 compare nell'header ma **non viene acceduto**: non è
ammesso nell'atlante e non è mappato dal harness. Fra i due gruppi esiste
uno spazio che non viene interpretato come record o RAM libera.

Per entrambi i gruppi, argomento zero cancella il bit, nonzero lo imposta.
La relazione statica con i chiamanti originali 1014C54 e 1014CE6 è verificata,
compresi i delay slot che impostano rispettivamente r1=1 e r1=0. Questi
chiamanti esterni non vengono eseguiti: modificano anche stato e callback
RAM, distinti dai tre indirizzi MMIO ammessi qui.

## Prove CPU e audit

Tutti i 15 selettori originali e cinque casi senza corrispondenza
(0,3000,3008,4000,4009) sono provati con flag 0/1/2/FFFFFFFF, tre seed MMIO
e profondità del contesto 1/2/7 abbinate ai seed. Dodici scenari, 24 run,
20 chiamate per scenario. Dodici coppie di tracce con/senza osservatore
identiche; 444 MMIO, di cui 180 letture e 264 scritture. Verificati 3060
carichi di pool/tabelle e 99 istruzioni ridisassemblate indipendentemente.

Il nuovo harness riusabile `s33_tbib_nested_context_harness.py` conserva lo
stesso modello esplicito della tappa selettori: struttura file-backed `.data`,
gate a +24 uguale a 1, task a +28, annidamento task+104. Il globale 104126C
viene installato temporaneamente dal solo harness e ripristinato a zero.
Tutte le 180 coppie di servizi originali 1013D34/1013DFC incrementano e
decrementano il contatore. Stack e r13..r19 sono controllati dopo ogni
chiamata; il TBIB runtime finale coincide integralmente con l'originale.
Nessun FLAG/LR/SR, fault, DSP provvisorio o modifica di istruzioni/tabelle.

Nel percorso annidato provato, il ritorno r0 del helper valido coincide con
la profondità lasciata da 1013DFC. Nei casi senza corrispondenza conserva il
selettore. Non trasformare questi valori in un contratto pubblico di errore
0/1: i chiamanti esterni applicano la propria logica.

Evidenze CPU e audit:
`outputs/gnu_arc700/20261026T110920Z_8823dd7f/verified_evidence.json` e
`tbib_delegated_table_audit.json`; copie nell'atlante sotto `evidence/`.
Il publisher v2 conserva tutti i controlli del publisher precedente e prende
la data dall'evidenza, evitando di etichettare come 25 ottobre una tappa del
26 ottobre. Gli script già vincolati dai vecchi ledger restano invariati.

```sh
python3 Python_Trace_Scripts/s33_verify_tbib_delegated_table.py
python3 Python_Trace_Scripts/s33_audit_tbib_delegated_table.py outputs/gnu_arc700/20261026T110920Z_8823dd7f
```

## Copertura e limiti

I 1265 record non costituiscono il denominatore di tutti i registri Nikon:
le 64 posizioni core sono posizioni di codifica, non 64 registri fisici tutti
verificati; i 200 AUX mescolano documentazione architetturale ed evidenze
firmware. Soltanto 25 indici AUX hanno record semantici da CPU guest originale.
Il rapporto 25/200 misura quella proprietà del catalogo, non la percentuale
di scoperta dell'intero hardware. Il totale SoC, le opzioni BCR fisiche e
le estensioni proprietarie non sono ancora delimitati: nessuna percentuale
globale è sostenibile dai dati disponibili.

I manuali pubblici sono utilizzati come fonti effettive: ARCompact 5115-029
(per esempio BCLR/BSET, pagine 213/225), ARC700 Memory Components e MMU.
Nel catalogo architetturale sono già tracciate correzioni ottenute dalle
figure dei PDF. Il 26 ottobre sono ricontrollati BSET p225, i BCR dei
componenti di memoria p8 e il diagramma MMU_BUILD p21. Non risolvono da soli
la configurazione effettiva della Nikon o la semantica dei suoi MMIO.

Restano aperti chiamanti esterni 1014BCC/4C64, altre categorie delegate,
registrazioni/callback RAM, rami non annidati FLAG/IRQ, censimento TBIB OOB,
AUX indiretti/overlay, BCR/SoC e DSP fisica. Nessuna prova di reset, W1C,
timing, controller, boot completo, installazione o recupero sulla fotocamera.
