# S33 — destinazione del worker e registri di indirizzo

Analisi statica V1.1, 19 ottobre 2026. Continuazione del [ciclo degli slot](S33_Ciclo_Slot_Worker_Flag_e_Indici.md). Nessun accesso hardware.

## Risultato

Collegato un percorso condizionale dalla destinazione del worker fino alla programmazione di un indirizzo hardware:

```text
banca destinazioni → record consumatore+0x28 → stack+8
→ 0x2960B0 → 0x2ED9FC → setter generico, indice2/banca1
→ halfword bassa a 0x0FE9811C, alta a 0x0FE98120
```

Il setter richiede puntatore nonzero e allineato a otto byte. La scrittura dei due registri non contiene un'attesa di completamento: questo raccorda l'indirizzo del buffer al livello hardware, ma **non prova il termine dell'ultimo uso** prima dell'azzeramento dei flag. Circa 10% funzionale invariato.

## 1. Dalla banca di destinazioni al record del consumatore

Il task consumatore usa il record **`0x445268`**, caricato in r19 dall'istruzione PCL scalata `0x15D03E`. Il pool effettivo è `align4(site)+177*4 = 0x15D300`.

Nel tratto `0x15D29E..2D8`, sotto le guardie del chiamante, legge l'indice richiesto a struttura `0x3920B8+0x8E` e seleziona le banche già attribuite:

| Selettore | Banca lavoro | Banca destinazione |
|---|---|---|
| 0 | +`0x20` | +`0x40` |
| 1 | +`0x30` | +`0x50` |
| ramo default | +0 | +`0x10` |

Il puntatore destinazione viene scritto a **`0x445220+0x70 = 0x445290`**. Questo indirizzo coincide con **record `0x445268+0x28`**.

Dopo l'attesa dello slot, `0x15D4A8` chiama `0x24863C`, passando nel delay slot r0=r19. L'identità dell'indice letto qui e di quello usato dal produttore richiede ancora le invarianti descritte nel rapporto precedente: la corrispondenza delle banche non prova da sola che il contenuto sia pronto o corretto.

## 2. Percorso selettore1 del consumatore

`0x24863C` ha varie guardie di stato e più percorsi. Nel percorso con **byte dell'input+0x60 uguale a 1**, dopo le guardie e i controlli intermedi, copia 32 byte da input+`0x20` sullo stack locale.

La destinazione presente a input+`0x28` si trova quindi a **stack+8**. A `0x2487D8` questa parola viene caricata in r1; il codice prepara r0=1 e chiama **`0x2960B0`**, assegnando r2=0 nel delay slot.

La verifica attribuisce questo percorso condizionale, non dichiara che il selettore1 sia attivo in ogni ripresa. Gli altri selettori e le guardie upstream possono portare a sequenze diverse.

## 3. Setter dell'indirizzo e controllo di allineamento

`0x2960B0`, quando il primo argomento è 1, inoltra il puntatore a **`0x2ED9FC`** con secondo argomento 1.

Il corpo di `0x2ED9FC`:

1. rifiuta un puntatore zero, preparando `0x03F00022`;
2. verifica i tre bit bassi con `bmsk.f ...,0x2`; se nonzero prepara `0x03F00013`;
3. entra nella sezione critica tramite `0x1786E8`;
4. chiama **`0x2EE8F0`** con indice registro 2, puntatore e selettore banca 1;
5. esce tramite `0x179354` e imposta r0=0.

Il ritorno r0 lasciato dalla chiamata interna non viene propagato. Questo non viene interpretato come perdita certa di un errore: il contratto completo di tutti i getter/setter inferiori deve ancora essere attribuito. È invece osservabile che la routine conclude il percorso ordinario con zero senza un controllo locale del completamento fisico.

L'allineamento a otto byte è coerente con gli arrotondamenti delle aree già ricostruiti. Non dimostra che ogni puntatore letto dalla tabella sia ancora valido o che tutti gli scrittori rispettino quel requisito.

## 4. Tabelle dei registri e scritture halfword

`0x2EE8F0` normalizza il selettore banca tramite `0x2ED448`: zero rimane zero, qualsiasi nonzero diventa 1. Sceglie poi una delle due tabelle di indirizzi e legge la voce `indice*4`.

| Banca | Tabella | Voce indice2 | Routine di scrittura |
|---|---|---|---|
| 0 | `0x40CDA4` | `0x0FE9011C` | `0x3099C8` |
| 1 | `0x40CDD8` | `0x0FE9811C` | `0x309C0C` |

Le voci delle tabelle sono state lette dal payload verificato del blocco che le contiene. Nel percorso selettore1 seguito qui viene usata la seconda riga.

Il writer `0x309C0C` conserva il puntatore in r13, ne estrae i 16 bit bassi e li scrive con **`sth.di`** all'indirizzo della voce. Avanza l'indirizzo di quattro byte, sposta il puntatore a destra di 16 bit e scrive la metà alta con un altro `sth.di`.

Per il puntatore P:

```text
[0x0FE9811C] halfword = P & 0xFFFF
[0x0FE98120] halfword = P >> 16
```

Il writer della banca0 usa la stessa struttura sui registri `0x0FE9011C/0x0FE90120`. Le due scritture separate non costituiscono, da sole, una prova di atomicità verso il dispositivo. La sezione critica protegge una sequenza CPU, ma l'effetto sull'hardware richiede il contratto dei registri.

## 5. Limite della prova di completamento

Nel tratto osservato si **programma un indirizzo**. Non si legge uno stato di fine, non si attende un evento e non si verifica che il dispositivo abbia terminato di leggere il buffer.

Nella sequenza più ampia di `0x24863C` compaiono anche chiamate di configurazione e attivazione, fra cui `0x29601C`. Il loro completamento e il collegamento al successivo azzeramento dei flag restano da seguire. Il ritorno del setter e il flag software dello slot non vengono presentati come prova dell'ultimo uso fisico.

## Evidenze e continuazione

[Script](../Python_Trace_Scripts/s33_trace_worker_destination_mmio.py), [JSON](../Ghidra_Results/ghidra_reports/worker_destination_mmio/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/worker_destination_mmio/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_worker_destination_mmio.py`.

Verificati **16 SHA-256, roundtrip ELF del blocco 00, 11 finestre, 11 collegamenti diretti, 33 istruzioni chiave e 7 pool**, oltre alle due voci di tabella, l'alias fra i campi del record e quattro esempi di ricomposizione delle metà del puntatore. Gli esempi controllano l'aritmetica di split, non eseguono le scritture MMIO.

Prossimo: seguire attivazione `0x29601C/0x2EDC60`, notifiche e lettori dello stato del dispositivo, e confrontarli con il momento in cui il consumatore azzera il flag dello slot. Restano aperti durata del buffer, coerenza dei selettori e modalità runtime.


## Continuazione: handshake di attivazione

Il [rapporto sull’handshake](S33_Handshake_Attivazione_e_Polling_Dispositivo.md) risolve gli aggiornamenti dei controlli e i tre polling di stato, senza identificarli come fine uso del buffer. Notifiche e completamento fisico restano aperti.
