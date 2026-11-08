# S33 — chiamanti FED38: errore di registrazione e modifiche successive

26 ottobre 2026. Firmware V1.1, CPU GNU ARC700 con MMIO e contesto kernel
modellati. Nessun accesso hardware; NON_INSTALLARE.

## Risultato

Eseguiti integralmente i chiamanti originali 1014BCC e 1014C64, il helper
1014B08 e i servizi di registrazione/rimozione nei loro rami originali con
registrazione disabilitata. Il byte 10411E4 è zero nel firmware originale e
non viene alterato. Il ritorno 200604 dei servizi **non impedisce** le
successive modifiche delle maschere RAM o gli accessi MMIO FED38.

Atlante `Risultati/Processor_Registers/20261026T112040Z/`: 1265 voci
(64 posizioni core / 200 AUX / 1001 MMIO), nessun indirizzo aggiunto e tre
voci arricchite: FED3814, FED3818, FED3830. Ledger SHA-256 di 344 file
verificato; 48 atlanti PASS precedenti conservano chiavi e geometrie.
Invariati 25 indici AUX guest, 204 ancore run-PC, 50 finestre e due famiglie.

## Sequenza originale e significato dei bit

1014BCC, quando entrambe le maschere RAM sono vuote, chiama 1004A78 e
10049C8. Entrambe incontrano il gate zero e restituiscono 200604. Il codice
continua: aggiorna una maschera RAM, chiama 1014B08 con r1=1 e restituisce
l'esito conservato in r15. Se altre attivazioni sono già presenti, salta
quei servizi e può restituire zero pur con lo stesso gate disabilitato.

1014C64 cancella il bit RAM. Quando entrambe le maschere diventano zero,
chiama 1004A20, che restituisce 200604 dal ramo disabilitato. Anche qui
prosegue: chiama 1014B08 con r1=0, poi restituisce l'esito conservato in r14.

Le maschere RAM sono a 1041390 e 1041392, per i gruppi 3000 e 4000. L'indice
software è `(selettore & 31) - 1`. Gli indici MMIO sono invece quelli delle
tabelle originali 1040800 e 104088C: per esempio 3001 usa bit RAM0 ma bit
MMIO3, mentre 4001 usa bit RAM0 ma bit MMIO7. Non trasferire la codifica
di una maschera all'altra.

Nel primo gruppo il helper scrive un solo bit a FED3818 sia nel percorso
r1=1 sia in quello r1=0, poi imposta/cancella il bit di FED3814. Nel secondo
gruppo modifica soltanto FED3830. FED3834 resta un indirizzo d'header senza
accesso osservato: non è aggiunto alla mappa.

## Prove e audit

Tutti i 15 selettori originali sono esercitati in quattro sequenze:

- Attivazione e disattivazione di ogni selettore prima di passare al seguente.
- Attivazione di tutti, poi disattivazione nello stesso ordine.
- Attivazione di tutti due volte, poi una sola disattivazione di ciascuno.
- Attivazione di tutti, poi disattivazione nell'ordine inverso.

Tre seed MMIO abbinati a profondità di contesto 1/2/7 producono 12 scenari
e 24 esecuzioni con/senza osservatore. Sono provati 405 chiamanti completi,
810 coppie di servizi annidati, 999 MMIO (405 letture / 594 scritture),
266 istruzioni ridisassemblate e 12 coppie di tracce identiche.

297 chiamate restituiscono zero e 108 restituiscono 200604. Tutte le 108
chiamate con errore eseguono MMIO: 270 eventi in quei soli percorsi. Le
funzioni di registrazione/rimozione incontrano il gate zero 162 volte.
Nella sequenza a coppie tutte le 30 chiamate di ogni scenario falliscono;
nelle altre sequenze solo la prima attivazione e l'ultima disattivazione
restituiscono l'errore. La ripetizione dell'attivazione non crea un conteggio
di riferimenti: dopo due attivazioni basta una disattivazione per cancellare
quel bit RAM, nel dominio e negli stati provati.

L'audit usa insiemi di selettori attivi come riferimento indipendente per
le maschere RAM, controlla gli effettivi store e i puntatori da pool e
calcola il RMW MMIO bit per bit. Verifica ogni ritorno, il helper chiamato,
gli ingressi al gate disabilitato e l'intero incremento/decremento annidato.
I callback MMIO indipendenti controllano PC, indirizzo, larghezza, valore e
coppie begin/result. Verificati anche byte di guardia, stack e r13..r19.

Il contesto `.data` del harness è esplicito: gate +24=1, task +28 e livello
iniziale non nullo. Solo 104126C viene temporaneamente puntato al contesto
del harness e poi ripristinato. Le due maschere RAM tornano a zero tramite
i chiamanti originali; tutto il TBIB runtime finale coincide con l'originale.
Nessuna istruzione, tabella o byte di configurazione è sostituito per far
passare le prove. Non eseguiti FLAG/LR/SR o DSP provvisorio; nessun fault.

Due attese dell'auditor sono state corrette prima della pubblicazione: lo
store del prologo varargs a 103EFC6 non segue la cadenza di quattro byte
assunta inizialmente; nella disattivazione inversa l'ultima chiamata del
primo gruppo ha tre MMIO, portando il totale dei casi con errore a 270.
Nessun controllo sugli eventi effettivi o byte firmware è stato rimosso.

CPU: `outputs/gnu_arc700/20261026T111738Z_3cee1158/verified_evidence.json`.
Audit: `tbib_outer_callers_audit.json` nella stessa directory. Copie e script
sono sotto `evidence/` nell'atlante.

```sh
python3 Python_Trace_Scripts/s33_verify_tbib_outer_callers.py
python3 Python_Trace_Scripts/s33_audit_tbib_outer_callers.py outputs/gnu_arc700/20261026T111738Z_3cee1158
```

## Limiti e seguito

Il ramo di registrazione abilitata, identity AUX, installazione dei callback
e i rami non annidati FLAG/IRQ non sono provati. Non estendere il dominio
dei 15 selettori provati agli argomenti invalidi dei chiamanti esterni: i
percorsi di ingresso/uscita dei servizi possono differire.
Una maschera RAM non è un registro SoC e una scrittura con un solo bit non
dimostra acknowledge/W1C o eventi fisici. Restano censimento TBIB OOB,
AUX indiretti/overlay, BCR, SoC, DSP fisica e la mappa completa; nessuna
installazione, avvio completo o recupero sulla fotocamera dimostrati.
