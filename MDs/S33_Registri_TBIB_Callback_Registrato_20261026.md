# S33 — registrazione abilitata, callback originale e IDENTITY modellato

26 ottobre 2026. Firmware V1.1, esecuzione CPU GNU ARC700 con contesto e MMIO
esplicitamente modellati. Nessun hardware, nessuna modifica a GNU o agli
originali. NON_INSTALLARE.

## Risultato

Atlante `Risultati/Processor_Registers/20261026T113207Z/`: **1266 voci**,
64 posizioni core / 200 AUX / 1002 MMIO. Aggiunto FED3834 con letture e
scritture CPU effettive: nelle tappe precedenti era soltanto nell'header.
Arricchiti FED3814, FED3818, FED3830 e FEF0028. IDENTITY, AUX4 già catalogato,
ha ora 12 record guest originali, tre PC distinti in tre run: gli indici AUX
con semantica guest passano da 25 a 26 e le ancore run-PC da 204 a 213.

Ledger SHA-256: 351 file verificati; tutti i 49 atlanti PASS precedenti
conservano chiavi e geometrie. Invariate 50 finestre e due famiglie MMIO
calcolate. Nessun registro è dichiarato fisicamente verificato.

## Percorso completo

Il harness imposta temporaneamente a 1 il byte RAM 10411E4, gate usato dai
servizi originali, e lo riporta a zero al termine. Non altera istruzioni o
header delle tabelle. Esegue i 15 selettori originali di 1040800/104088C
tramite 1014BCC, chiama il callback originale 1014D6C, quindi esegue i 15
1014C64. Infine usa l'API originale 1004A78 con `(610,0)` per cancellare
lo slot callback 1040628, controllandone il ritorno e il contenuto zero.

Alla prima attivazione, 1004A78 registra 1014D6C nello slot del selettore
610, prima voce della tabella 1040618. Il successivo 10049C8 percorre la
lista varargs fino al terminatore FF e imposta FEF0028 bit15 tramite
10047C8. All'ultima disattivazione, 1004A20 percorre la lista e cancella quel
bit. I callback vengono installati e rimossi dalle istruzioni originali,
senza scrivere direttamente lo slot dal harness.

Il callback 1014D6C viene chiamato dal harness dopo questa registrazione:
non è una consegna IRQ né l'esecuzione del dispatcher padre originale.
Scorre i sette record del primo gruppo e gli otto del secondo. Per ogni
record legge prima la maschera abilitazioni e, se il bit è attivo, la parola
di stato. Se anche quel bit è attivo, consulta il callback figlio e scrive
una maschera con un solo bit alla parola di stato. I callback figli sono
zero nei dati originali: i loro salti indiretti vengono saltati.

| Gruppo | Maschera letta | Stato letto e scritto |
|---|---|---|
| 1040800, sette record | FED3814 | FED3818 |
| 104088C, otto record | FED3830 | FED3834, ora ammesso |

La routine restituisce r0=8 alla fine della scansione nel percorso provato;
questo è il valore lasciato dal ciclo, non un codice IRQ o errore fisico.

## IDENTITY e limiti del modello

Sono eseguiti i tre LR originali a 1004A8A, 10049E2 e 1004A3A. IDENTITY
restituisce zero dal banco AUX ordinario del simulatore. Il codice non
prende quindi il ramo di confronto uguale a 13030513. Il valore zero non
è un ID Nikon, una lettura BCR o uno stato di reset misurato. Nessuna SR a
IDENTITY, sostituzione dell'emulatore o ID inventato per selezionare un ramo.
Le istruzioni, byte firmware e valori osservati sono vincolati alle tracce;
un ELF di sola analisi contiene il TBIB originale completo per verificare
indipendentemente tutte le nuove ancore AUX.

I MMIO sono backing di memoria ordinaria. La scrittura con un solo bit
sostituisce l'intera parola nel modello: i bit di stato inizialmente presenti
possono quindi scomparire prima delle iterazioni successive. Nel secondo
gruppo sono osservate queste trasformazioni:

| Seed MMIO | FED3834 prima | FED3834 dopo | Selettore corrispondente |
|---|---|---|---|
| 0000 | 4E0D | 0008 | 4005 |
| FFFF | B1F2 | 0080 | 4001 |
| A55A | EB57 | 0040 | 4002 |

Non attribuire questo effetto al silicio: W1C, acknowledge, latch, IRQ e
concorrenza hardware non sono modellati o verificati. Non è una prova che
il dispositivo reale perderebbe o gestirebbe gli stessi eventi.

## Verifica e conservazione delle prove

Tre scenari con seed MMIO abbinati a livelli di contesto 1/2/7, sei run
con/senza osservatore e tre coppie di tracce identiche. Novanta chiamanti
esterni completi, tre callback originali e tre pulizie tramite API originale.
Verificati 330 MMIO (186 letture / 144 scritture), 186 coppie di servizi
annidati, 421 istruzioni ridisassemblate e 12 letture IDENTITY modellate.

Il contesto `.data` resta esplicito, con gate +24=1, task +28 e annidamento
task+104. Stack, r13..r19, ogni ritorno, callback zero alla fine e ogni
begin/result MMIO sono controllati. Il globale 104126C e il gate 10411E4
sono ripristinati; tutte le maschere RAM e lo slot callback ritornano ai
byte originali tramite il percorso dichiarato. Il TBIB runtime finale è
integralmente identico all'originale. Nessun FLAG/SR o DSP provvisorio, né
fault. Sono provati solo questi contesti e sequenze, non tutti i domini.

CPU: `outputs/gnu_arc700/20261026T112709Z_6165adeb/verified_evidence.json`.
Audit: `tbib_registered_callback_audit.json` nella stessa directory; copie
pubblicate sotto `evidence/` nell'atlante.

```sh
python3 Python_Trace_Scripts/s33_verify_tbib_registered_callback.py
python3 Python_Trace_Scripts/s33_audit_tbib_registered_callback.py outputs/gnu_arc700/20261026T112709Z_6165adeb
```

Il publisher v3 aggiunge soltanto i quattro campi trace previsti dell'AUX
IDENTITY; gli altri campi e tutti gli altri AUX restano invariati. Verifica
che le vecchie run AUX rimangano un prefisso identico, con nuove ancore
verificate dai byte originali. Per i MMIO, fields/sources/additional_accessor_runs
si estendono senza perdere alcun elemento precedente; il nuovo elemento
additional_accessor_runs deve coincidere esattamente con i nuovi eventi.

Due copie intermedie sono conservate come FAIL_NOT_ADMITTED:
20261026T113018Z e 20261026T113119Z. Il vecchio controllo trattava la lista
additional_accessor_runs come campo immutabile; il nuovo publisher prova
esplicitamente vecchio prefisso e nuovo elemento esatto. Un'ulteriore attesa
usava un intero per il campo lista degli indici AUX: corretta confrontando
l'unione ordinata e il suo conteggio. Nessun vecchio script vincolato dagli
hash, dato firmware, evento CPU o controllo di perdita copertura modificato.

## Seguito

Restano consegna tramite dispatcher padre, callback figli non nulli,
ramo IDENTITY uguale a 13030513, domini invalidi dei chiamanti e lifetime
dei servizi. Aperte altre categorie delegate, init 100559C, censimento TBIB
OOB, AUX indiretti/overlay, BCR, SoC e DSP fisica. Nessun avvio completo,
installazione o recupero sulla fotocamera dimostrati: mappa incompleta.
