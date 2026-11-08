# S33 — gruppo 0x6000, abilitazione e interrupt padre

Analisi statica V1.1, 19 ottobre 2026. Continuazione dei [controlli dei tre stadi](S33_Transizioni_Controlli_Stadi_Avvio_e_Arresto.md) e dei [tre stadi con callback](S33_Tre_Stadi_Callback_Configurazione_e_Dispatch.md). Nessun accesso hardware.

## Risultato

Il gruppo logico degli ID `0x600A/0x600B/0x600C` è collegato al padre **`0x090D`**, callback **`0x26627C`**, attraverso la tabella `0x424C30`. Il padre è gestito dal dispatcher dello **slot runtime9**, già collegato allo stub CPU `0xB2FF2` e all'ingresso comune.

L'abilitazione usa una **bitmap halfword a `0x36B330`**, inizialmente0. Con bitmap vuota richiede registrazione e abilitazione del padre; quando la bitmap dopo una disabilitazione è0 richiede la disabilitazione del padre. Gli ID dei tre stadi corrispondono ai bit9/10/11 della bitmap e della tabella interna.

Questa è una catena statica condizionale completa fino ai gestori già risolti. La base vettori effettiva e le callback installate sulla fotocamera non sono state osservate. Circa 10% funzionale AkeruOS, invariato.

## 1. Primo ID abilitato e registrazione del padre

`0x266170` accetta il gruppo quando `(ID & 0x6000) == 0x6000`. Carica la halfword `0x36B330`. Se è0, esegue:

```text
0x26619A: registrar 0x16D898(ID 0x090D, funzione 0x26627C)
0x2661A2: abilitazione 0x16D7E8(ID 0x090D, terminatore 0xFF)
```

Se la bitmap è già nonzero salta entrambe le richieste. Per gli ID concreti dei tre stadi ricava poi `bit = (ID & 0x1F) - 1`, imposta tale bit nella bitmap, e chiama `0x2660E8(ID,1)`.

Il ritorno della registrazione a `0x26619A` **non viene confrontato prima dell'abilitazione**. Il valore conservato in r13 viene invece dalla seconda chiamata. Inoltre il ritorno di `0x2660E8` non sostituisce quel risultato. Il ritorno finale non certifica quindi ogni preparazione interna.

Le guardie del registrar superiore, fra cui stato di inizializzazione e controllo `identity`, rimangono applicabili. Non si presume che una richiesta di registrazione sia sempre accolta.

## 2. 0xFF come terminatore della lista

Le API `0x16D7E8` e `0x16D840` percorrono argomenti ID: confrontano il valore con **255** e terminano su `0xFF`. Per ogni ID precedente chiamano `0x16D5BC`, con r1=1 per abilitare o r1=0 per disabilitare. In caso di errore interrompono la scansione.

Nei chiamanti del gruppo `0x6000`, `0xFF` è quindi il terminatore della richiesta. Non viene interpretato come maschera hardware di otto bit.

Per il gruppo padre `0x0900`, il servizio inferiore seleziona `0x424C30` e imposta/cancella il bit d'abilitazione della voce nel registro indicato dall'intestazione.

## 3. Tabella padre e collegamento allo slot9

La tabella `0x424C30` contiene puntatori `0x0FEF0040` e `0x0FEF002C`, conteggio14 e record da8byte. La voce verificata per **`0x090D`** è:

| Campo | Valore |
|---|---|
| Indice | 3 |
| Record ID | `0x424C54` |
| Cella callback | `0x424C58`, inizialmente0 |
| Indici bit sorgente/abilitazione | 12/12 |
| Maschera | `0x1000` in entrambi i registri |
| Funzione richiesta | `0x26627C` |

Il dispatcher `0x264308` legge le due halfword MMIO, scorre i record e invoca il puntatore solo se i rispettivi bit sono presenti e la callback è nonzero. Per questa voce raggiunge quindi `0x26627C`, sotto tali condizioni.

La verifica include nuovamente la richiesta dell'inizializzatore `0x16D3F0`, che passa **slot9 e `0x264308`** al registrar `0x231428`, lo stub9 e la selezione del record nell'ingresso comune `0xB3054`.

```text
voce vettore9 → stub 0xB2FF2 → ingresso comune 0xB3054
→ record runtime9 → 0x264308
→ ID padre 0x090D, cella 0x424C58 → 0x26627C
→ tabella interna 0x424E00 → gestore dello stadio
→ callback configurata → evento task 0x08200011
```

Il raccordo al record9 usa i limiti della tabella runtime, con sottrazione del limite inferiore e passo12. L'indice9 resta quello passato dallo stub; il puntatore della tabella è letto da kernel+`0x238`. Base assoluta del vettore e stato corrente della registrazione rimangono variabili runtime, come discusso nel [rapporto vettori](S33_Vettori_Interrupt_e_Tabella_Runtime.md).

## 4. Tabella interna, bitmap e maschere

`0x424E00` contiene 16 record e punta a `0x0FEF0228/0x0FEF022C`. Per i tre stadi:

| ID | Bit bitmap e tabella interna | Cella callback interna | Gestore | Bit evento task |
|---|---:|---|---|---|
| `0x600A` | 9 (`0x200`) | `0x424E40` | `0x24A97C` | `0x2000` |
| `0x600B` | 10 (`0x400`) | `0x424E38` | `0x24BCF4` | `0x1000` |
| `0x600C` | 11 (`0x800`) | `0x424E30` | `0x24BCB8` | `0x800` |

Le equivalenze fra formula dell'ID, indici della tabella e bitmap sono verificate sui byte e sulle istruzioni. La bitmap rappresenta ID abilitati; non conta quante richieste/clienti usano lo stesso ID.

Il servizio `0x2660E8` cerca l'ID nella tabella interna, scrive una halfword con il solo bit sorgente a `0x0FEF0228`, poi imposta o cancella il relativo bit a `0x0FEF022C` secondo r1 ricevuto. La scrittura al primo registro precede la modifica dell'abilitazione. Il significato elettrico della scrittura non è assunto come W1C.

Il dispatcher interno verifica i due bit indicati dalla voce e chiama la callback se nonzero, poi scrive il bit sorgente allo stesso registro. Gli ulteriori test locali dei tre gestori rimangono quelli già documentati.

## 5. Disabilitazione e bitmap vuota

`0x2661D8`, per un ID concreto, ricava lo stesso bit e lo cancella dalla bitmap. Se il risultato è0 richiede `0x16D840(0x090D,0xFF)`; se rimangono altri ID, salta tale richiesta e conserva ritorno0 nel tratto normale.

Infine chiama comunque `0x2660E8(ID,0)` per cancellare la relativa abilitazione interna. Il ritorno finale conserva quello della richiesta al padre, quando eseguita. Non si deduce che sia stato verificato il termine delle operazioni dei motori hardware: questi servizi coordinano ID, maschere e bitmap.

Una scansione globale di tutti gli scrittori della bitmap non è parte di questo checkpoint. Restano da chiarire proprietà, concorrenza e riabilitazione nelle modalità alternative.

## Evidenze e prossimo passo

[Script](../Python_Trace_Scripts/s33_trace_stage_irq_parent.py), [JSON](../Ghidra_Results/ghidra_reports/stage_irq_parent/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/stage_irq_parent/gnu_verified.txt).

Riproduzione: `python3 Python_Trace_Scripts/s33_trace_stage_irq_parent.py`.

Verificati **16 hash dei payload, roundtrip blocco00, 17 finestre, 8 collegamenti diretti, 49 istruzioni chiave, 9 pool e 30 record delle due tabelle**. Un interprete del tratto aritmetico decodificato controlla **48 casi** di aggiornamento della bitmap, per i tre ID, otto stati iniziali e operazioni enable/disable.

Restano aperti osservazione runtime, base vettori corrente, proprietà completa della bitmap e fine dell'uso fisico dei buffer. Prossimo: seguire le scritture dei puntatori nei tre stadi e collegarle alle banche di buffer già ricostruite nel task.


## Continuazione — puntatori e registri dei tre stadi

Il [rapporto sui puntatori](S33_Puntatori_Tre_Stadi_e_Registri_Buffer.md) collega i record runtime a 11 coppie di registri e distingue l’instradamento con C+90=0 o diverso da0. Restano da risolvere le origini di alcune celle e la durata fisica dei buffer.
