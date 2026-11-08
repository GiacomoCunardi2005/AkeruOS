# S33 — tabella TBIB originale di scritture mascherate

25 ottobre 2026. Firmware Nikon V1.1, analisi statica e CPU GNU ARC700 con
backing MMIO modellato. Nessun accesso hardware; candidati NON_INSTALLARE.

## Risultato

L'atlante `Risultati/Processor_Registers/20261025T205524Z/` contiene 1245 voci:
64 core, 200 AUX, 981 MMIO. Sono aggiunti 42 indirizzi e arricchiti FF04020 e
FF04024. Ledger SHA-256: 326 file verificati; 44 atlanti PASS precedenti
conservano tutte le chiavi e geometrie. Le 204 ancore AUX, 25 indici guest,
50 finestre e due famiglie calcolate restano invariati.

Il collegamento statico originale è `1004442 → 1004468`; il delay slot
`1004446` legge dal pool `1004458` il puntatore `1043258`. La tabella contiene
68 record `<indirizzo32, maschera16, valore16>` e termina con indirizzo zero a
`1043478`. I record interessano 44 indirizzi distinti, con scritture ripetute
che devono mantenere l'ordine originale. Il chiamante completo `1004440`
non è stato eseguito; il corpo completo `1004468` sì, con questa tabella.

Ogni record effettua lettura e scrittura halfword `.di`:
`nuovo = (vecchio & ~maschera) | (valore & maschera)`, troncato a 16 bit.
Il codice ricarica l'indirizzo prima della scrittura: quattro carichi dalla
tabella per record, più la sentinella, quindi 273 carichi per esecuzione.

Prima del ciclo FEF0144 conserva i sei bit alti e forza i dieci bassi a 2AA.
Il record 31 cambia poi il campo basso a 155. La prima scrittura non è il
valore finale. Record e offset originali sono nell'audit JSON.

## Accessor e verifica

Nove ulteriori routine verificano FF04020 bit15, FF04024 bit0, FEF00D8 bit1,
FF04000 bit8 e bit5, e due selettori di modalità. I getter 10045F4 e 1004614
invertono il bit: `bxor ...,0` indica l'indice del bit da invertire, non XOR
con il numero zero. Il primo restituisce 1 dopo clear del bit1 e 0 dopo set.

1004648: modalità 1 cancella FF04004 bit9, modalità 4 lo imposta.
10046AC: modalità 1 imposta FEF00D8 bit0, modalità 2 lo cancella.
Le altre modalità provate restituiscono 1 senza MMIO; quelle valide 0.

Tre seed (0, FFFF, A55A) per sei modalità (0,1,2,3,4,FFFFFFFF): 18 scenari,
36 esecuzioni, dieci routine distinte e 16 chiamate per scenario. Tutte le
18 coppie di tracce con/senza osservatore sono identiche. Verificati 2778
eventi MMIO (1488 letture,1290 scritture), 4914 carichi dalla tabella, 264
carichi da pool e 72 istruzioni con ridisassemblaggio indipendente.
Stack e r13..r19 preservati, nessun fault, AUX o evento DSP provvisorio;
payload TBIB completo invariato. I seed e le modalità sono casi selezionati,
non una prova di equivalenza sull'intero dominio degli argomenti.

Evidenze CPU: `outputs/gnu_arc700/20261025T205220Z_a41c2726/`.
Copie pubblicate: `evidence/tbib_mask_table_cpu.json` e
`evidence/tbib_mask_table_audit.json` nell'atlante.

Riproduzione dalla radice:

```sh
python3 Python_Trace_Scripts/s33_verify_tbib_mask_table.py
python3 Python_Trace_Scripts/s33_audit_tbib_mask_table.py outputs/gnu_arc700/20261025T205220Z_a41c2726
```

## Limiti

Sono provati accessi CPU e trasformazioni software, con stack e MMIO fixture.
Non sono provati nomi delle periferiche, reset, W1C, permessi, IRQ, timing,
domini reali dei chiamanti, raggiungibilità globale o avvio TBIB completo.
Il limite OOB del censimento lineare TBIB resta esplicito e non è aggirato.
GNU e firmware originali non sono modificati; mappa fisica incompleta.
