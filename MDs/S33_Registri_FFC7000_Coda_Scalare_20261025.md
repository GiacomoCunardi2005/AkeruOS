# FFC7000: coda scalare e ordine dei campi

25 ottobre 2026. Atlante corrente:
[20261025T182643Z/REGISTER_MAP.md](../Risultati/Processor_Registers/20261025T182643Z/REGISTER_MAP.md),
**1.047 voci: 64 posizioni core, 197 indici AUX e 786 indirizzi MMIO singoli**.
Sono aggiunti 16 scalari e arricchiti due esistenti. La mappa fisica resta incompleta.

## Prove ammesse

[CPU](../outputs/gnu_arc700/20261025T182229Z_156ce85a/verified_evidence.json):
16 entry originali, nove scenari/18 run e **675 transazioni halfword**,
342 letture e 333 scritture. Le nove coppie con/senza osservatore hanno tracce
identiche; nessun fault o accesso indefinito. SP e sentinelle r13..r19 sono conservati.

L'[audit](../outputs/gnu_arc700/20261025T182229Z_156ce85a_audit.json)
ricostruisce maschere e destinazioni da 129 istruzioni originali, pool e shift;
confronta 63 carichi byte dagli input con i dati delle fixture. Controlla
ordine, valori e larghezze delle transazioni, ritorno del getter, backing finale
e padding A5. La decodifica riparte da ogni PC rilevante: il listing lineare
che attraversa pool rimane solo materiale di navigazione.

## Campi aggiornati in sequenza

| Entry Main V1.1 | Indirizzo software | Operazione sostenuta dalle prove |
|---|---|---|
| 309504 | FFC7718 | Prima arg0 low7, poi arg1 low7 in bits8..14; conserva bits7/15 |
| 309558 | FFC771C e FFC7720 | Due buffer di due byte: low8 poi high8, con RMW distinti per ogni word |
| 3095DC | FFC7724 | Prima arg0 low3, poi arg1 low3 in bits8..10; conserva F8F8 |
| 309620 | FFC7204,7208,720C | Tre byte di input nei rispettivi low4; conserva upper12 |
| 3096B8 e 309738 | FFC7228 | Low2 dell'argomento, altri bit conservati |
| 3096E0 | FFC722C | LSB dell'argomento, altri bit conservati |
| 309760 | FFC7238 | LSB dell'argomento, altri bit conservati |
| 3097B8 | FFC721C | Low2 dell'argomento, altri bit conservati |
| 3097E0 | FFC7220 | LSB dell'argomento, altri bit conservati |

Per un campo con maschera M e shift s, l'effetto verificato è
`(precedente & ~M) | ((argomento << s) & M)`, sulla halfword.
Quando un secondo campo usa lo stesso indirizzo, il suo read vede il risultato
del primo write nel backing del modello. L'ordine non viene collassato in una
scrittura finale, perché le transazioni intermedie possono essere rilevanti.

Nel writer 309504 le maschere sono 007F e 7F00. Nel writer 3095DC sono 0007
e 0700. I bit conservati provengono dai seed, non da un reset osservato sulla Nikon.
Le entry 3096B8 e 309738 modificano entrambe low2 di FFC7228: non sono campi
diversi dedotti dalla sola presenza di due entry.

## Setter che confrontano con 1 e getter

| Entry | Indirizzo | Bit |
|---|---|---:|
| 309684 | FFC7224 | 0 |
| 309704 | FFC7230 | 0 |
| 309784 | FFC7218 | 0 |
| 309804 | FFC7200 | 0 |
| 309850 | FFC7064, già catalogato | 1 |

Queste cinque entry impostano il bit **solo per argomento == 1**, altrimenti
lo cancellano. Ciascuna è provata con 0,1,2,FFFFFFFF e verifica la conservazione
degli altri bit. Copiare LSB o trattare ogni nonzero come vero darebbe risultati
diversi: le regole dei writer LSB nella tabella precedente non sono trasferite qui.

309838 legge FFC7080, già catalogato, e restituisce solo bit0. Il valore di
ritorno è controllato dal caller di prova. Il significato fisico di quel bit
non viene assegnato dal nome descrittivo del getter.

## Equivalenza, etichette e conservazione

Una coppia di scenari inverte **upper16 degli argomenti dei writer di campo**,
lasciando invariati seed, flag dei setter e byte dei buffer. Tutta la sequenza
MMIO resta identica. Questo non prova che upper16 sia ignorato dai setter che
confrontano l'intero argomento con 1; i loro flag non sono stati invertiti in
questa equivalenza e hanno prove distinte.

Sono inoltre corrette due etichette storiche di accesso software: FFC7524/7528,
le cui prove precedenti contengono solo store, passano da `read_write_halfword_di`
a `write_halfword_di`. Vecchia etichetta, motivazione e fonte restano nel record.
Non viene dichiarato un permesso fisico write-only.

Le finestre restano **50**, con **3.408 appartenenze/3.376 indirizzi distinti**;
restano 32 ripetizioni e FF74088 anche scalare. Nessun nuovo scalare interseca
le celle delle finestre. AUX invariato: 22 indici con evidenze guest e 172 siti
run/PC. Le prove nuove non eseguono LR/SR. Due famiglie MMIO parametriche restano aperte.

[Validazione finale](../Risultati/Processor_Registers/20261025T182643Z/atlas_validation.json),
[ledger di 279 file](../Risultati/Processor_Registers/20261025T182643Z/sha256.json).
Parent 165109Z: 273 file immutati. La verifica delle chiavi e delle geometrie
conserva tutta la copertura dei 36 atlanti precedenti validati, senza promuovere
celle di trasferimento a registri indipendenti. Le istantanee intermedie della
stessa integrazione restano tracciate; i 16 nuovi indirizzi sono contati una volta.

Alla ripresa è stata anche completata la documentazione della
[tappa con tabelle e loop](S33_Registri_FFC7000_Tabelle_e_Coda_20261025.md),
già validata a disco ma non riportata nel checkpoint breve. Le sue prove CPU
sono state riutilizzate dopo verifica degli hash, senza nuove esecuzioni.

## Riproduzione e lavoro aperto

Script: [CPU](../Python_Trace_Scripts/s33_verify_ffc7000_scalar_tail.py),
[audit](../Python_Trace_Scripts/s33_audit_ffc7000_scalar_tail.py),
[integrazione](../Python_Trace_Scripts/s33_integrate_ffc7000_scalar_tail.py).

```sh
python3 Python_Trace_Scripts/s33_verify_ffc7000_scalar_tail.py
python3 Python_Trace_Scripts/s33_audit_ffc7000_scalar_tail.py SOURCE AUDIT_JSON
python3 Python_Trace_Scripts/s33_integrate_ffc7000_scalar_tail.py --parent Risultati/Processor_Registers/20261025T165109Z --source SOURCE --audit AUDIT_JSON
```

Proseguire da 309884 e altri gruppi MMIO. Restano aperti domini di chiamanti
indicizzati/tail, candidati AUX codice-dati, BCR e configurazione reale del SoC.
La provenienza dei 38 output dell'helper FFB303A40 resta separata dalla verifica
matematica indipendente, ancora mancante nel modello DSP provvisorio.

Input, stack e storage MMIO sono fixture. Funzione periferica, permessi, reset,
W1C, effetti collaterali, IRQ, tempi e atomicità non sono verificati su hardware.
GNU e originali preservati; nessun flash/dumper/NAND/vendor/resetUSB/SD.
**NON_INSTALLARE** invariato, obiettivo attivo.
