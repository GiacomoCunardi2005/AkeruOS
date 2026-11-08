# S33 — due configurazioni TBIB assemblate da byte

25 ottobre 2026. Ricerca offline sul firmware V1.1, con CPU GNU ARC700 e MMIO
modellati. Nessuna prova hardware; NON_INSTALLARE.

## Risultato

Atlante `Risultati/Processor_Registers/20261025T210001Z/`: **1256 voci**,
64 core / 200 AUX / 992 MMIO. Undici indirizzi aggiunti e FE10004 arricchito.
Ledger SHA-256 di 330 file verificato; tutti i 45 atlanti PASS precedenti
conservano chiavi e geometrie. Invariati 204 siti AUX verificati, 25 indici
AUX guest, 50 finestre e due famiglie MMIO calcolate.

I wrapper originali 10056C4 e 10056CC caricano rispettivamente i puntatori
1042874 e 104288C da pool; entrambi caricano 104120A in r1 nel delay slot
del salto al writer 10053A8. Sono eseguiti entrambi i wrapper e il writer
completo, inclusi prologo/epilogo condivisi. Non è eseguito l'inizializzatore
più ampio 100559C né un boot TBIB completo.

Il writer legge 22 byte dal primo puntatore e due dal secondo, senza
allineare o sostituire i dati originali. Per ogni coppia scrive
`byte_basso + 256 * byte_alto` con uno store halfword `.di`.
Le dodici scritture sono nell'ordine seguente; valori in esadecimale:

| Destinazione | Wrapper 10056C4 | Wrapper 10056CC |
|---|---:|---:|
| FEE0004 | 1014 | 140C |
| FEE0008 | 1119 | 1910 |
| FEE000C | 071D | 1D11 |
| FEE0010 | 1801 | 0107 |
| FEE0014 | 0C02 | 0218 |
| FEE0018 | 0316 | 0316 |
| FEE001C | 0504 | 0504 |
| FEE0020 | 060E | 060E |
| FEE0024 | 0D08 | 0D08 |
| FEE054C | 1312 | 1312 |
| FEE05C4 | 1C15 | 1C15 |
| FE10004 (già presente) | 0514 | 0514 |

Le prime cinque parole differiscono fra le configurazioni originali; le
altre sei parole della tabella e la parola comune coincidono. L'ordine è
software osservato; nessuna attribuzione di funzione fisica a questi valori.

## Verifica ed evidenze

Tre scenari cambiano soltanto il seed delle dodici celle MMIO (0, FFFF,
A55A, combinato con l'indirizzo). Dati e puntatori nel firmware restano
identici; entrambi i wrapper vengono chiamati in ogni scenario. Sono sei
esecuzioni CPU con/senza osservatore, tre coppie di tracce identiche e
72 scritture MMIO senza letture MMIO. Verificati anche tutti i 144 carichi
byte dai dati originali, 84 carichi da pool, 95 istruzioni ridisassemblate,
valori finali e byte di guardia, conservazione stack/r13..r19.

L'audit indipendente ricava valori dai singoli byte e confronta gli indirizzi
effettivi con i callback dell'osservatore. I primi controlli statici hanno
rilevato due errori dell'auditor: spostamento del branch relativo a PCL
allineato e padding della prima sequenza. Corrette le attese dell'auditor;
nessun byte firmware, test CPU o strumento GNU modificato o controllo rimosso.

CPU: `outputs/gnu_arc700/20261025T205902Z_bfdeaf78/verified_evidence.json`.
Audit: `tbib_byte_config_audit.json` nella stessa directory. Copie e script
sono nell'atlante, sotto `evidence/`.

```sh
python3 Python_Trace_Scripts/s33_verify_tbib_byte_config.py
python3 Python_Trace_Scripts/s33_audit_tbib_byte_config.py outputs/gnu_arc700/20261025T205902Z_bfdeaf78
```

## Lavoro ancora aperto

Seguire i gruppi originali con selettori/tabelle 1004744 e 10047C8 e le
dipendenze dell'inizializzatore 100559C. Non sostituire servizi con stub né
ammettere indirizzi scelti dal solo harness. Il censimento lineare completo
TBIB conserva il suo limite OOB: le finestre delimitate e le esecuzioni qui
verificate non lo risolvono. Restano aperti AUX indiretti/overlay, BCR, SoC,
DSP e la mappa fisica. Non dimostrati reset/W1C/IRQ/timing, funzionamento dei
controller, installazione o recupero sulla fotocamera.
