# S33 — prenotazione delle risorse SD e stop software originali

23 ottobre 2026, R0/R1/R4. Continuazione dei [callback di stato](S33_Dumper_RAM_SD_Callback_Stato_Errori_e_Inizializzazione.md). Eseguiti anche costruttore, prenotazione, attesa e post dei semafori usati dal receive, oltre ai sei helper che azzerano i flag software. Nel nuovo profilo questi servizi non restituiscono più valori sostitutivi.

**Correzione semantica:**1594E4 è un **try-acquire**, non una query di sola lettura. Quando trova un token ne decrementa il contatore, poi scrive un solo byte1 all'uscita; senza token scrive0. Il precedente nome “query” descriveva il confine della fixture e non provava questa mutazione.

## Prove

[34 casi CPU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Arbitration/20261023T142719Z/verified_evidence.json), [traccia](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Arbitration/20261023T142719Z/trace.txt), [GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Arbitration/20261023T142719Z/gnu_verified.txt):16 casi risorse/selezione/helper e18 scenari del lettore ereditati dal gruppo stato, **tutti ritornati**.14 finestre GNU,20 istruzioni chiave,16 hash dei payload, sorgenti e comando conservati.

```sh
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_arbitration.py
```

[Runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_read_arbitration.py), [probe](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDReadArbitration.java). Riutilizzati ProbeDumpSDReadStatus e i suoi helper senza modificarli.

## Oggetti semaforo e contatori

15933C(id) scorre la tabella statica **373D18**, record38hex, e inizializza il corpo inferiore tramite23EA7C, con il contatore statico1. Non è necessario scrivere a mano il marker inferiore o dichiarare il semaforo già attivo.

| ID | Record superiore | Oggetto inferiore | Ring waiter | Count waiter | Token | Oggetto receive |
|---|---|---|---|---|---|---|
| 1E00003 | 3743A8 | record+10 | record+18/+1C | half record+20 | word record+28 | 512CC8 |
| 1E00004 | 3743E0 | record+10 | record+18/+1C | half record+20 | word record+28 | 512CEC |
| 1E00005 | 374418 | record+10 | record+18/+1C | half record+20 | word record+28 | 512D10 |

Gli offset sono esadecimali. Il magic superiore è53454D4C, quello inferiore6C77736D a record+24. Il costruttore inserisce gli oggetti nella lista globale kernel+23C/240 e incrementa la halfword kernel+244; tre oggetti producono count3.

1594E4→159378 risolve ID e marker, poi23EF54 entra nella sezione critica e decrementa il token se positivo. Tre sequenze provano successo1, secondo tentativo0 e post1594A4→23EE48 che ripristina1. Le guardieA5 dimostrano che il wrapper modifica **un byte**, non quattro. ID assente→20050A e marker inferiore invalido→200503 lasciano uscita e contatore invariati.

## Attesa e trasferimento del token

Due casi prenotano prima il token di1E00004 e invocano1593AC(id,5). Il corpo originale accoda il task nel ring semaforo e nella lista temporizzata, fino aB2D50: stato52B, un waiter e una deadline assoluta5 nel profilo temporale predisposto.

- Cinque invocazioni originali del tick2F70C4 raggiungono la scadenza, rimuovono entrambi i nodi e permettono al wrapper di restituire **200507**.
- Il post originale1594A4 risveglia il waiter, azzera task+30 e permette il ritorno0. Il contatore resta **0**: il token viene consegnato al waiter, non reso nuovamente prenotabile nello stesso momento.

Nel timeout task+30 può restare nonzero anche con liste vuote; nel post viene azzerato. Il ritorno daB2D50 rimane un confineCABI astratto dopo la verifica dello stato pronto. Non viene eseguito il frameCPU, né una reale alternanza fra due task.

## Selezione e rilascio

Le prove usano il selettore originale27FCD4 e2801F0:

- primo token disponibile e stato pronto→512CC8;
- primo già prenotato, terzo pronto→512D10;
- primo e terzo già prenotati→attesa su1E00004, immediatamente soddisfatta dal suo token1→512CEC;
- campioni MMIO non pronti per primo e terzo→entrambi i token prenotati per il controllo vengono restituiti prima di passare al secondo oggetto.

Una sequenza conserva **tre acquisizioni contemporaneamente vive**, nello stesso task di laboratorio: ordineCC8,D10,CEC, tre token0 e tre oggetti distinti. Il rilascio inverso attraverso281158/281064 azzera ogni handle/id e ripristina tutti i token1. È una prova sequenziale di tre associazioni vive, non di arbitraggio fra task concorrenti.

I modi configurati3/4/6 nel record3F76D4 selezionano invece l'oggetto fisso e saltano try-acquire/post: i tre token restano1. La proprietà ottenuta sul percorso ordinario non va applicata automaticamente al ramo configurato.

Nei18 scenari del lettore con eventi e callback originali, ogni normale completamento/errore esegue un try, un post e un helper software; il primo token torna1. Nei due errori precoci di enable framework200604 resta0 insieme all'oggetto e alla maschera non ripuliti: la precedente uscita parziale conserva ora anche una prenotazione effettiva nel modello.

## “Stop” non è un'attesa dell'hardware

267BAC/BB4/BBC azzerano rispettivamente i byte36B3E7/E8/E9;267BC4/BCC/BD4 azzerano36B3E4/E5/E6. Ogni corpo contiene carico del puntatore, store byte0 e ritorno. I sei casi isolati partono daA5 e verificano lo zero originale; r0 rimane l'indirizzo del flag, non un contratto di stato errore.

Le scritture MMIO dei chiamanti281158/281064 sono eseguite, ma il solo azzeramento di un flag non prova arresto elettrico, svuotamento del motore o ultimo uso fisico del buffer. Le vecchie fixture con ritornoE09999 non attribuivano un errore reale a questi helper.

## Limiti e prossimo passo

Restano sintetici kernel/ready con un task, campioni MMIO, gate framework, identitàCPU, clock1000/1000 e prodotti3342A8/336364. Nessuna fixture per API risorse o helper stop nel nuovo gruppo; nessuna copiaDMA. Le18 matrici del lettore controllano ancora buffer31 e guardieA5 invariati.

La [continuazione write](S33_Dumper_RAM_SD_Scrittura_Asincrona_e_PIO_Originali.md) esegue anche il chiamante di scrittura e le copiePIO originali. Per il dump restano raccordo filesystem/write/creazione esclusiva/close, mappa fisica completa e task/hook compatibile. Nessun hardware o firmware installabile prodotto; GNU eC AkeruOS invariati, **NON_INSTALLARE**, circa10% funzionale invariato.
