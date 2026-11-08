# S33 — transizioni dei controlli negli avvii e negli arresti

Analisi statica V1.1, 19 ottobre 2026. Continuazione dei [tre stadi e delle callback](S33_Tre_Stadi_Callback_Configurazione_e_Dispatch.md). Nessun accesso hardware.

## Risultato

Risolte le scritture di controllo che precedono le notifiche dei due stadi associati a `0x800/0x1000`: l'avvio **azzera bit1 e bit0** del primo registro, quindi **imposta bit0** di un secondo registro. I gestori, prima di stato3 e callback, **impostano bit1 e bit0** del primo registro.

Le funzioni di accesso ricostruite effettuano letture/modifiche/scritture halfword senza polling locale. Il significato fisico di questi bit resta aperto: non sono ancora chiamati «stop», «reset», «busy» o «DMA completato». La notifica software e queste scritture non provano da sole che il buffer non sia più usato. Circa 10% funzionale AkeruOS, invariato.

## 1. Stadi associati a 0x800 e 0x1000

| Percorso | Stadio evento `0x800` | Stadio evento `0x1000` |
|---|---|---|
| Avvio superiore | `0x24B230` | `0x24BA5C` |
| Registro controllo A | `0x0FFC4000` | `0x0FFC3000` |
| Accessor bit0 | `0x2E38A0` | `0x2E3BE0` |
| Accessor bit1 | `0x2E38D4` | `0x2E3C14` |
| Registro B | `0x0FFC4004` | `0x0FFC3004` |
| Gestore | `0x24BCB8` | `0x24BCF4` |

Gli accessor ricevono r0: se vale1 impostano il bit, per ogni altro valore lo cancellano. L'istruzione che sceglie l'indice bit è nel delay slot del ramo condizionale, quindi vale per entrambi i percorsi.

Nel tratto di avvio verificato:

```text
pubblica stato2
→ r13 = 0
→ accessor bit1(0)
→ accessor bit0(0)
→ carica registro B
→ leggi halfword B, imposta bit r13 (=0), riscrivi halfword
→ restituisce0 nel tratto ammesso
```

Il bit impostato nel registro B è **bit0**, perché r13 viene azzerato a `0x24B284` oppure `0x24BAD0`; non si ricava l'indice dal nome del registro o dal solo `bset`.

Nei gestori, dopo i test bit4 e la scrittura locale di `0x10` già documentati, vengono chiamati accessor bit1(1), poi bit0(1). Solo dopo questi ritorni viene pubblicato stato3 e invocata l'eventuale callback configurata.

Questa sequenza descrive l'ordine delle istruzioni CPU. Il comportamento interno del motore hardware e l'eventuale ritardo dopo la scrittura richiedono altra evidenza.

## 2. Percorsi di disattivazione superiore

Sono seguiti i servizi **`0x24B2C8`** e **`0x24BB14`**, per i rispettivi stadi. Se lo stato è0 possono uscire subito; altrimenti:

1. chiamano `0x2661D8`, rispettivamente con ID `0x600C` o `0x600B`;
2. chiamano `0x2E3A24` o `0x2E3D74`, con r0=0 e r1=`0x10`, cancellando bit4 nelle halfword `0x0FFC400C/300C`;
3. se il ritorno conservato della disabilitazione ID è0, scrivono stato0; se è diverso da0, saltano questo store;
4. continuano comunque con accessor bit1(1) e bit0(1), poi altri servizi di pulizia.

La mancata scrittura dello stato0 non impedisce le successive scritture di controllo nel tratto verificato. Non si deduce da ciò un errore funzionale: occorre ricostruire gli invarianti dei chiamanti e la gestione dell'esito.

Non compare nel corpo locale una lettura ripetuta di un bit di inattività prima di queste operazioni. Questa osservazione è limitata alle finestre analizzate: non esclude attese in chiamanti, altri servizi o dispositivi.

## 3. Controlli dello stadio associato a 0x2000

Per `0x24A6CC`, nel percorso che passa dai controlli iniziali e dalla configurazione, sono risolti:

| Funzione | Registro | Operazione osservata |
|---|---|---|
| `0x2E3498` | `0x0FFC2098` | imposta bit1 |
| `0x2E3820` | stesso | imposta bit12 |
| `0x2E34B4` | stesso | cancella bit1 |
| `0x2E383C` | stesso | cancella bit12 |
| `0x2E35E4` | `0x0FFC20B8` | scrive i 16 bit bassi del complemento dell'argomento |
| `0x2E3610` | stesso | imposta bit0 |
| `0x2E347C` | `0x0FFC2098` | imposta bit0 |

Le prime due chiamate sono a `0x24A75E/762`; le ultime sono nel tratto `0x24A906..91C`. I rami dipendono dal campo di configurazione: non si assume che ogni chiamata dell'avvio percorra l'intera sequenza.

La costante del pool `0x24A998` è **`0x0000FFFF`** come parola little-endian. Passata a `0x2E35E4`, produce halfword0; la successiva `0x2E3610` imposta bit0 dello stesso registro. Il risultato non va ricavato leggendo i pool come istruzioni ARC.

Come già verificato, il gestore dello stadio scrive1 a `0x0FFC20B4`, pubblica stato3 e invoca la callback del bit `0x2000`. La relazione fisica fra i registri `2098`, `20B4` e `20B8` non è ancora nominata.

## 4. Forma degli accessor e limiti sul riuso

Gli accessor dei bit usano `ldh.di`, `bset/bclr` e `sth.di`: si tratta di operazioni halfword di lettura/modifica/scrittura. I corpi non contengono un ciclo di attesa. I pool di indirizzi sono esclusi dalle finestre di istruzioni e verificati separatamente.

Il controllo del bit4 nelle due callback e la successiva impostazione dei controlli possono far parte di un protocollo di completamento. Rimane un'inferenza: per stabilire la durata del buffer bisogna collegare registri di indirizzo, ammissione dell'hardware, notifica e ultimo accesso effettivo, comprese le interazioni con cache e altri stadi.

## Evidenze e prossimo passo

[Script](../Python_Trace_Scripts/s33_trace_stage_control_transitions.py), [JSON](../Ghidra_Results/ghidra_reports/stage_control_transitions/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/stage_control_transitions/gnu_verified.txt).

Riproduzione: `python3 Python_Trace_Scripts/s33_trace_stage_control_transitions.py`.

Verificati **16 hash, roundtrip ELF blocco00, 36 finestre, 23 collegamenti diretti, 74 istruzioni chiave, 20 pool e 12 accessor di controllo**. Non è un modello del dispositivo né una prova di esecuzione.

Prossimo: collegare l'abilitazione/disabilitazione ID600A/B/C al gruppo superiore e al vettore CPU; poi ricostruire le scritture dei puntatori dei tre stadi e le dipendenze dei buffer.


## Continuazione — interrupt padre e slot CPU

Il [rapporto sul gruppo6000](S33_Gruppo_6000_Abilitazione_e_Interrupt_Padre.md) risolve il padre090D, la bitmap `0x36B330` e il raccordo statico attraverso slot runtime9 e relativo stub CPU. Restano aperte installazione/esecuzione reali, stato corrente dei vettori e fine dell’uso fisico dei buffer.
