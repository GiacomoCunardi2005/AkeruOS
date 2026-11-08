# S33 — dimensionamento e retry del workspace degli stadi

Analisi statica V1.1, 19 ottobre 2026. Continuazione delle [origini delle celle buffer](S33_Origine_Celle_Buffer_e_Area_Condivisa_Stadi.md). Nessun accesso hardware.

## Risultato

Il builder `0x243F48` ripete la costruzione con parametro **3 → 2 → 1**, se le quantità sono valide ma lo spazio non basta. Il valore iniziale3 viene conservato **nel delay slot** della chiamata che richiede la regione3: non è il ritorno zero della chiamata. Alla terza insufficienza viene restituito `0x08200008`.

Risolte le formule locali dei due percorsi. Nel percorso alternativo **W+0x10 e W+0x14 ricevono lo stesso puntatore**; le due configurazioni riusano un'area dimensionata con il massimo delle rispettive richieste. Inoltre, un argomento stack uguale esattamente a1 salta il confronto finale con la capienza. Il ritorno zero, da solo, non certifica quindi che i buffer rientrino nei16KiB.

Questi risultati restringono il contratto software del builder. Non attribuiscono direzione dei dati, sicurezza della sovrapposizione durante l'esecuzione o ultimo accesso fisico. Circa10% funzionale AkeruOS, invariato.

## 1. Ammissione e parametro iniziale

Il prefisso `0x243F52..F98` confronta senza segno le dimensioni degli input con r4/r5 e con le loro metà intere, calcolate tramite shift logico. Una dimensione insufficiente porta al codice `0x0820000C`, letto dal pool `0x244054`. Non è una verifica generale di tutti i puntatori o delle quantità successive.

Sequenza della prima query:

```text
0x243FA6  r0 = 3
0x243FA8  bl.d 0x1774C8
0x243FAC  r21 = r0        # delay slot, prima dell'ingresso nel chiamato
0x243FAE  confronto r0 con zero, dopo il ritorno
```

Pertanto r21=3 anche quando r0, dopo la query, vale0. La seconda query usa selettore4. La somma delle lunghezze resta0x4000, con base iniziale B=`0x0F79B180`, come già verificato nel rapporto precedente.

Il parametro k=r21 è scritto nei campi config800+`0x30` e config1000+`0x3C`; nel percorso alternativo ci sono altre due scritture a config1000+`0x3C`. Le code dei servizi `0x24BB60/0x24BBF0` rileggono questi campi prima di chiamare `0x3342A8`. Il parametro arriva dunque ai calcoli inferiori. Non viene qui ricostruita tutta la loro geometria, né dimostrata la monotonia delle quantità per ogni input.

## 2. Quantità osservate ai confini dei servizi

Sia W il descrittore di lavoro (`0x4453DC` nel chiamante task), con:

| Quantità | Percorso normale | Percorso alternativo |
|---|---|---|
| Q0 | uscita halfword stack+1C di `0x24AF64` | uscita halfword stack+1C di `0x24B6F8`, prima configurazione |
| Q1 | uscita halfword stack+20 di `0x24B6F8` | uscita halfword stack+20 di `0x24B6F8`, seconda configurazione |
| D0 | ritorno di `0x24BB60`, salvato a W+8 | primo ritorno di `0x24BBF0`, salvato a W+8 |
| D1 | ritorno di `0x24BBF0`, salvato a W+C | secondo ritorno di `0x24BBF0`, salvato a W+C |

Gli offset sono esadecimali. Q0/Q1 sono riletti dal builder come parole stack inizialmente azzerate, dopo gli store halfword dei servizi. La presente verifica fornisce le quantità all'ingresso dei tratti aritmetici: non emula i servizi di calcolo.

Ognuna delle quattro quantità viene confrontata con zero prima di proseguire; i rami selezionano il codice `0x08200001`. A `0x2441E0` il pool è **PCL allineato +4×(-105)=`0x24403C`**: il commento non scalato del disassemblatore non è l'indirizzo effettivo.

## 3. Percorso normale: aree in sequenza

Definendo A8(x)=arrotondamento per eccesso a8, nel dominio senza overflow:

```text
W+1C = B
P0 = B + A8(Q0)                    → W+10
W+20 = P0 + 2*D0
P1 = P0 + 2*D0 + A8(Q1)            → W+14
P2 = P1 + 2*D1                     → W+18
E  = P1 + 4*D1
consumo = E-B
```

I primi avanzamenti sono `0x24405C..078`, il secondo gruppo `0x2440D2..0F6`. I blocchi D0 e D1 sono moltiplicati rispettivamente per2 e4 dagli `add1/add2`; non ne viene dedotto un formato immagine.

## 4. Percorso alternativo: basi condivise

In questo ramo le due configurazioni temporanee vengono costruite nella medesima area config1000, una dopo l'altra. W+1C e W+20 ricevono entrambi B. Poi `0x2441D2..20E` seleziona i massimi:

```text
P = B + A8(max(Q0,Q1))
P0 = P1 = P                       → W+10 e W+14
P2 = P + 2*D1                     → W+18
E  = A8(P + 2*max(D0,2*D1))
consumo = E-B
```

L'uguaglianza delle prime due basi è provata dagli store `0x2441F2/200`. Dimostra un alias software intenzionale nel layout. Per riutilizzarlo in AkeruOS occorre ancora stabilire quali stadi accedano alle aree, in quale ordine e fino a quando.

Le formule sono riportate come interi non traboccanti. Le istruzioni operano a32bit e l'allineamento effettivo usa `(x+7)`, shift logico destro3 e sinistro3; non è provata la sicurezza per indirizzi o quantità arbitrari.

## 5. Capienza, retry e uscite

Il suffisso `0x244210..232` decide:

| Condizione locale | Esito |
|---|---|
| argomento stack entrante =1 | uscita con stato corrente, senza confronto capienza |
| altrimenti, consumo ≤ capienza | uscita con stato corrente |
| consumo > capienza e k diverso da1 | r0=k; r21=r0-1; nuova costruzione da `0x243FDA` |
| consumo > capienza e k=1 | stato `0x08200008`, poi uscita |

La capienza è confrontata senza segno e l'uguaglianza è accettata. Lo stato corrente è0 dopo le due query riuscite. Errori delle query e quantità zero hanno uscite precedenti; non comportano automaticamente un altro tentativo.

Il limite di tre passaggi riguarda il controllo locale e assume chiamate che ritornino rispettando l'ABI di conservazione dei registri. Non è un timeout hardware. Il salvataggio r25..r13 nel helper `0x334104` e il ripristino di r21 sono verificati; non viene provata la terminazione di ogni chiamata inferiore.

Le scritture alle configurazioni e a W precedono il confronto finale. Un errore non ripristina localmente il descrittore precedente: i chiamanti devono gestire il ritorno senza usare automaticamente i campi prodotti dal tentativo fallito.

## 6. Origine dell'argomento che salta il confronto

Lo stack del builder contiene push blink4byte, tredici registri52byte e locali36byte: totale **0x5C**. Il suo `[sp+0x5C]` coincide quindi con `[sp]` del chiamante.

Nel task a `0x15F01C/020`, l'argomento è la parola **C+0x90**, con C=`0x367490`, già usata nell'instradamento dei tre stadi. La guardia locale del builder richiede **esattamente1**: valori2 o `0xFFFFFFFF` non saltano il controllo. Il ramo alternativo interno al builder è invece scelto dall'argomento r6 nonzero (byte C+A8 nel chiamante task). Le due selezioni sono distinte.

La scansione lineare del blocco00 contiene anche il chiamante diretto `0x24C33C`: conserva nello stesso argomento stack un valore0/1 preparato dai rami precedenti e passa r6=1. L'identità della sua modalità non viene attribuita qui. I due siti diretti verificati non escludono chiamate indirette o altri blocchi.

## Evidenze e prossimo passo

[Script](../Python_Trace_Scripts/s33_trace_stage_workspace_retry.py), [JSON](../Ghidra_Results/ghidra_reports/stage_workspace_retry/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/stage_workspace_retry/gnu_verified.txt).

Riproduzione: `python3 Python_Trace_Scripts/s33_trace_stage_workspace_retry.py`.

Verificati **16 hash, roundtrip ELF blocco00, 9 finestre, 16 collegamenti, 20 istruzioni chiave, 13 store di salvataggio stack, 3 pool, 4.102 costruzioni e 60 decisioni del suffisso**. Il modello interpreta le istruzioni decodificate dei tratti locali; quantità sintetiche nonzero fino a65535, indirizzi senza overflow. Controllato separatamente il valore3 prima del ritorno della query. Rieseguita con successo anche la verifica precedente delle origini:2.048 casi.

Prossimo: completare la geometria dei servizi che producono Q0/Q1 e D0/D1, verificare l'indice della banca `0x392288`, poi correlare l'alias delle basi al protocollo degli stadi. Nessuna prova di pronto al prossimo scatto o compatibilità runtime V1.0.

## Continuazione — indice e layout della banca

Il [rapporto sulla banca](S33_Banca_Terne_Indice_e_Layout.md) collega il reset e tre avanzamenti modulo4 di C+51, risolve i sei casi della tabella e il layout locale di quattro terne. La validità globale dell’indice e l’ordine di inizializzazione restano da dimostrare; nessun controllo locale i<4 nel lettore selezionato.
