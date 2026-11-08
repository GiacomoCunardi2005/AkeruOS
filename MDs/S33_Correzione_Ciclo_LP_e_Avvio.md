# Cicli LP: uscita anticipata corretta e nuovo limite hardware

20 ottobre 2026, R3/R4. **Il vecchio modello Ghidra riattivava il ciclo quando il firmware saltava al suo termine.** La variante separata `ARCompact:LE:32:loopfix` corregge questo caso; i due campioni superano la scansione dei template e si fermano sullo stesso registro hardware non modellato. Non è ancora un avvio completo.

## Fonte e comportamento atteso

La sorgente GNU ARC700 CGEN `tools/gnu-arc700-sim-src/cpu/ARCompact.cpu`, righe3224–3266, distingue il raggiungimento naturale del termine dalla destinazione di un ramo. `current_loop_end_after_branch` dà priorità al ramo preso, senza decrementare LP_COUNT; il commento vieta di attivare la fine ciclo all'inizio di un blocco raggiunto tramite salto. [Fonte primaria ARC/CGEN](https://github.com/foss-for-mips-arc-processors/cgen/blob/arc-1.0-dev/cpu/ARCompact.cpu). Il checkout locale del simulatore GNU è al commitfa7f0c2d4e8e670a608337d71857408010551215; è stato letto e conservato perhash, non compilato/eseguito come secondo simulatore. La sorgente distingue anche un comportamentoARC600 diverso: non viene applicato adARC700.

Nel firmware reale `LP` a29F2C0 definisce il corpo29F2C4..29F2DC e l'indirizzo successivo29F2DE. Il ramoBEQ29F2DA salta a29F2DE quando la scansione incontra il terminatore. Il vecchio controllo Ghidra era posto all'ingresso29F2DE, quindi decrementava il contatore e ripartiva dalcorpo anche dopo quel salto, fino a leggere oltre il payload.

La nuova variante deriva da `statusreadfix`: il controllo viene eseguito **dopo il naturale completamento dell'istruzione che precede LP_END**. I salti presi terminano il flusso prima di quel controllo. Non sono cambiati byte Nikon, modello originale, aliasfix o statusreadfix. La variante conserva i limiti preesistenti suSTATUS32, interrupt e CPU non ancora verificata; non si dichiara una correzione completa dei cicli programmati tramiteSR, delay slot, annidamenti o ritorni daeccezioni.

## Prove eseguite e riproduzione

```bash
python3 S33-sections/safety_audit_codex/verify_loop_exit.py
```

[Runner](../S33-sections/safety_audit_codex/verify_loop_exit.py), [probe](../S33-sections/analysis_ghidra/scripts/ProbeLoopExit.java), [helper riusato](../S33-sections/analysis_ghidra/scripts/ProbeStatusRead.java), [manifest](../S33-sections/safety_audit_codex/loop_exit_verified.json), [GNU](../S33-sections/safety_audit_codex/evidence/loop_exit_gnu.txt), [log](../S33-sections/safety_audit_codex/evidence/loop_exit_run.log).

I test eseguono le istruzioni originaliLP/BEQ/NOP/store: ramo preso/non preso ×contatore1/2/5/65535. Si controllano destinazione, contatore residuo, conservazioneZ ed esecuzione dello store esterno al ciclo. I registri e una parola destinazione sono inizializzati esplicitamente come contesto di laboratorio. Primo fault o errore ferma la prova, anche quando `step()` restituiscevero.

| Modello e campione | Casi | Discrepanze dall'attesoGNU |
|---|---:|---:|
|statusreadfix, CMP3 |8 |4, tutti i rami presi |
|loopfix, CMP3 |8 |0 |
|loopfix, CMP1 |8 |0 |

**24casi isolati**, più **8tentativi limitati di avvio**: TBIB/MainCode ×STATUS32 iniziale0/6 ×CMP3/CMP1. Il probe riusa esattamente il metodo di avvio già presente, senza duplicarlo o estendere la RAM per aggirare la tabella. I16tentativi del [checkpointSTATUS32](STATUS32_BOOT.md) rimangono validi per quel modello storico e non sono stati rieseguiti qui; i relativi file e hash sono ricontrollati immutati prima e dopo.

## Nuovi confini raggiunti

| Tratto per ciascun campione e profilo | Esito corrente |
|---|---|
|TBIB da01000000 |10.695passi riusciti; stop01009E68 sulla lettura halfword hardware0FE800F8 |
|MainCode daBB540 |444.280passi riusciti; stop12CA3C sulla stessa lettura halfword0FE800F8 |
|AzzeramentoMainCode |1.758.364byte daA5 a0, integralmente verificati dopo439.690passi |

Gli assert controllano esattamente questi confini e il fault `uninitialized_read=ram:0fe800f8 size=2`, senza erroreGhidra. Le tracce CMP3/CMP1 sono identiche nel perimetro registrato. Nessun confrontoHiddenMenu è raggiunto. I conteggi diminuiscono rispetto al vecchio modello perché è eliminato il passaggio artificiale alla pseudo-fine ciclo e perché la scansione termina correttamente: non misurano prestazioni fisiche né percentuale del boot completato.

Sono conservate le ipotesiCPU del laboratorio: altri bitSTATUS32 iniziali0/6, base vettori0, nessun interrupt esterno, payload dati1 precaricato, registri core iniziali espliciti. Gli ingressiTBIB eMainCode sono prove separate, non una catenaROM→TBIB→MainCode completa. Il modello non conosce il valore del nuovo registro: **non viene sostituito automaticamente conzero**.

La funzioneMainCode12CA28, sotto r0=0, legge0FE800F8 e controlla bit7 prima di selezionare12/13 e passare al servizio17A000; funzione e istruzioni richiedono un riancoraggio separato dal pool letterali12CA34/38 prima di attribuire un significato fisico. Al momento il nome della periferica e il suo comportamento temporale non sono dimostrati. Prossimo: ricostruire questo accesso, i consumatori e i due valori delbit nel simulatore, mantenendo separate le risposte ipotetiche dalle misure della Nikon.

Restano scrittori indiretti dello statoHiddenMenu, interferenze task/interrupt del3temporaneo, CPU/DSP completa, avvio/UI completi e recupero fisico. **NO-GO flash e circa10% funzionale invariati.** Nessun accessoUSB/PTP o scrittura sulla fotocamera, nessun firmware modificato.
