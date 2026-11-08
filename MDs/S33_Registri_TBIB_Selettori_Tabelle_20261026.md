# S33 — selettori TBIB e quattro tabelle originali

Rapporto del 26 ottobre 2026 su esecuzioni UTC del 25 ottobre 2026. Firmware
V1.1, CPU GNU ARC700 con contesto e MMIO modellati. NON_INSTALLARE; nessun
hardware, modifica del firmware originale o degli strumenti GNU.

## Risultato

Atlante `Risultati/Processor_Registers/20261025T210538Z/`: **1262 voci**
(64 core / 200 AUX / 998 MMIO), sei indirizzi nuovi e due arricchiti.
Ledger di 334 file verificato. Le chiavi e geometrie dei 46 atlanti PASS
precedenti sono conservate; invariati 204 siti AUX, 25 indici AUX guest,
50 finestre e due famiglie calcolate.

1004744 cerca un selettore nelle quattro tabelle puntate da 1043480; se lo
trova scrive una maschera con un solo bit all'indirizzo nel primo campo.
10047C8 sceglie la tabella dalla categoria del selettore, poi effettua RMW
sul secondo indirizzo: zero cancella il bit, qualunque argomento non nullo
lo imposta. Nomi di tabella e colonne qui sotto descrivono solo il software.

| Tabella | Record | Store con un solo bit | RMW |
|---|---:|---|---|
| 1040500 | 16 | FEF0050 (già presente) | FEF0080 (nuovo) |
| 104058C | 6 | FEF0328 (già presente) | FEF0068 (nuovo) |
| 1040618 | 16 | FEF0074 (nuovo) | FEF0028 (nuovo) |
| 10406A4 | 14 | FEF0040 (nuovo) | FEF002C (nuovo) |

I record sono `<selettore16, indice_bit8, indice_bit8, callback32>` dopo
l'header di 12 byte. Le due colonne bit coincidono nei 52 record originali;
il campo callback è zero ma non viene alterato in questi percorsi.
Il dominio contiene 0401..0410, 0501/02/03/05/06/07, 0601..0610 e
0901..0907/090A..0910. Gli indici bit non sempre corrispondono a
`selettore-1`, quindi non sono stati ricostruiti da una formula inventata.

Provati tutti i 52 selettori originali e cinque invalidi (0,0411,0504,0908,
0909), per argomento 0/1/2/FFFFFFFF e tre seed. I casi invalidi restituiscono
200601 senza MMIO o ingresso nei servizi di annidamento.

## Contesto e verifica

Per eseguire i servizi originali 1013D34 e 1013DFC si installa temporaneamente
in 104126C un puntatore a una struttura `.data` del solo harness. La struttura
ha gate a +24 uguale a 1, puntatore task a +28 e contatore task+104 impostato
a 1,2,7 nei tre scenari seed. I servizi incrementano e poi decrementano il
contatore; tutte le 1248 coppie preservano il livello iniziale. Non vengono
eseguiti FLAG, LR o SR. Il puntatore globale torna a zero; la copia TBIB
runtime è identica all'originale al termine. Nessuna istruzione o tabella
viene modificata. Non è uno stato di reset o una struttura kernel misurata.

Dodici scenari, 24 esecuzioni con/senza osservatore, 114 chiamate originali
per scenario, 12 coppie di tracce identiche. Verificati 1872 MMIO (624 letture,
1248 scritture), 96816 carichi di pool/puntatori/count/selettori/indici e
126 istruzioni ridisassemblate. Callback indipendenti confermano PC,
indirizzo effettivo, larghezza e valore, inclusi begin/result. Verificati
valori finali, byte di guardia, stack e r13..r19 dopo ogni chiamata.

La prima attesa dell'auditor confrontava l'operando intero dello store con
il valore halfword: per bit15 la trace mostra FFFF8000, mentre il callback
e i byte scritti sono 8000. L'audit confronta i 16 bit dello store mantenendo
il controllo indipendente della larghezza di due byte; non sono stati
modificati CPU, firmware o gli eventi osservati.

Fonti: `outputs/gnu_arc700/20261025T210326Z_8056c71d/verified_evidence.json`
e `tbib_selector_tables_audit.json`; copie nell'atlante sotto `evidence/`.

```sh
python3 Python_Trace_Scripts/s33_verify_tbib_selector_tables.py
python3 Python_Trace_Scripts/s33_audit_tbib_selector_tables.py outputs/gnu_arc700/20261025T210326Z_8056c71d
```

## Limiti e continuazione

I seed MMIO sono combinati con profondità 1/2/7; gli argomenti non nulli
provati sono 1,2,FFFFFFFF. Non è una prova universale su tutti gli stati
kernel, sui rami non annidati, o su altre categorie delegate. Una scrittura
di maschera con un solo bit non prova W1C, acknowledge o IRQ fisico.
Restano reset, timing, permessi, nomi SoC, installazione/recupero e mappa
fisica incompleta. Resta il limite OOB del censimento lineare globale TBIB.
Continuare dalle categorie delegate 1014BCC..1015E50 e dall'init 100559C.
