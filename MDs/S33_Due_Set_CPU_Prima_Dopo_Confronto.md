# Due set eseguiti dalla CPU prima e dopo il confronto

20 ottobre 2026, R3/R4. **Ora il prototipo esegue davvero due chiamate al setter Nikon**, non due scritture esterne del computer: `set(3) → getter → confrontoCMP3 → set(1) → ramo`. Il test riesce nel perimetro descritto. Non è ancora una modifica collegata a un firmware installabile.

## Codice reale del prototipo

[Sorgente assembly](../S33-sections/safety_audit_codex/state_setter_trampoline.s), [disassemblato GNU](../Ghidra_Results/ghidra_reports/state_setter_calls/stub_gnu.txt), [ELF di laboratorio](../Ghidra_Results/ghidra_reports/state_setter_calls/stub.elf), [byte del solo prototipo](../Ghidra_Results/ghidra_reports/state_setter_calls/stub.bin). È codice nuovo da86byte, assemblato ARC700 little-endian, senza copiare/modificare un'immagine Nikon da installare.

Il prototipo a `0x02000000` chiama il vero setter `0x129904` con3, ripristina r1, chiama il vero getter `0x129920`, poi esegue lo stesso `cmp_s r0,3` del campioneCMP3. I due byte83E0 della copia a `0x0200001C` sono verificati identici a quelli originali a `0x1353F6`. Non si sostiene che il PC del confronto copiato sia rimasto quello originale.

Dopo il confronto vengono salvati r0/r1, viene eseguito `set(1)`, poi i registri sono ripristinati. Il link viene riportato a `0x1353F6`, come nel prefisso originale. Il ramo usa i flag del confronto e rientra nel codice Nikon a `0x1353FA` oppure `0x135410`.

Le «due operazioni di set» sono due chiamate logiche, non due soli opcode: chiamata, preparazione degli argomenti e conservazione del contesto richiedono più istruzioni. Il setter osservato non contiene istruzioni di aggiornamento dei flag, ma la conservazione è anche controllata durante l'esecuzione.

## Controlli sulla seconda chiamata

Prima e dopo `set(1)` sono confrontati r0..r25, gp, fp, sp, ilink1/2, lp_count e Z/N/C/V. Devono restare identici; r0 torna3, la variabile RAM diventa1, blink riceve il valore originale atteso. In35casi il controllo è riuscito. Nel prefisso si osservano12byte di stack aggiuntivi al massimo; dopo le chiamate lo stack pointer torna al valore precedente.

Codice e stack sono collocati soltanto come input di laboratorio: `0x02000000` e `[0x07000000,0x07001000)`, entro la fascia128MiB scelta. **Non sono spazi liberi o riservati sulla Nikon.** Questo test del selettore mappa soltanto i blocchi e lo stack necessari; non riesegue il bootstrap della bancaRAM128MiB né un boot completo.

L'emulatore parte direttamente dal prototipo. Non è stato inserito un salto di collegamento in un'immagine firmware Nikon e non sono stati verificati posizione definitiva, portata del salto, checksum del pacchetto, residenza/overlay o recupero per una patch installabile.

## Risultati eseguiti

```bash
python3 S33-sections/safety_audit_codex/verify_setter_calls.py
```

[Runner](../S33-sections/safety_audit_codex/verify_setter_calls.py), [probe CPU](../S33-sections/analysis_ghidra/scripts/ProbeSetterCalls.java), [manifest](../Ghidra_Results/ghidra_reports/state_setter_calls/verified_evidence.json), [tracciaCMP3](../Ghidra_Results/ghidra_reports/state_setter_calls/CMP3_pcode.txt), [tracciaCMP1](../Ghidra_Results/ghidra_reports/state_setter_calls/CMP1_pcode.txt), [log](../Ghidra_Results/ghidra_reports/state_setter_calls/run.log).

**105scenari**: sette esiti filesystem ×stati iniziali0/1/2/3/255 ×tre configurazioni: CMP3 originale, CMP1 originale, CMP3 con due chiamateCPU. Nei35casi del prototipo sono eseguite70chiamate reali al setter, sempre in ordine3poi1, con stato finale1 e flag conservati. Gli stati iniziali diversi daquelli osservati normalmente sono input sintetici, non stati dimostrati raggiungibili sulla macchina.

I quattro servizi filesystem sono ancora simulati come nel [test precedente](MENU_DIFFERENTIAL.md). Getter, setter, confronto e gestione della ricerca/attributi vengono eseguiti. La prova si ferma all'ingresso del managerUI `0x1453E4`, prima di eseguirlo, oppure al ritorno normale del selettore `0x135426`. Non è una sessioneUI completa e non esegue voci menu o scritture flash.

| Situazione | Effetto delle due chiamateCPU |
|---|---|
|Stato iniziale1, HiddenMenu trovato come directory |Richiesta root20; i7esiti selettore coincidono conCMP1/stato1 perPC,richiesta,sonde,risposte simulate e stato finale |
|HiddenMenu assente, marcatoreNAND presente |Dopo il ripristino a1 non viene richiesto menu4A |
|Errore volume/mount o attributo non directory |Ramo normale, stato finale1 |
|Stato iniziale0/2/3/255 |Si forza comunque il controllo HiddenMenu e si lascia1 alla fine; comportamento più ampio della solaCMP1 |

Non è affermata uguaglianza dell'intera memoria: le chiamate scrivono anche nello stack. I file firmware canonici sono rimasti identici perhash; la variante del decoderloopfix è quella già verificata, non una nuova semantica aggiunta per far passare il test.

## Conseguenze e rischi rimasti

La nuova prova risponde all'intento chiarito dall'utente e supera il limite del precedente impulso host3→1. **Il ripristino non è però atomico.** Nel caso iniziale1/HiddenMenu presente, fra i due store del setter la traccia registra una distanza di17passi del modello, non cicli fisici o microsecondi. Altri task/interrupt potrebbero vedere3 in quella finestra; il test non ne consegna e non prova un'esclusione reciproca.

Inoltre si ripristina sempre1, non il valore precedente. Se il precedente fosse2 o3, quella distinzione viene persa. Questa è una proprietà osservata nei test, da valutare rispetto agli [altri consumatori](menu_state_dependencies.md), non una garanzia di innocuità. La [lista degli scrittori](S33_Lista_Scrittori_Stato_HiddenMenu.md) separa i writer originali da quelli aggiunti dal prototipo.

Prossimi: risolvere scrittori indiretti e contesto task/interrupt del punto d'inserimento, poi verificare collegamento e stack nel contesto reale prima di proporre una patch installabile. L'avvio continua sul [modello128MiB](S33_Emulazione_RAM_128_MiB.md), con [parametri hardware ancora aperti](S33_Parametri_Clock_e_Proseguimento_Boot.md). **NO-GO flash e circa10% funzionale invariati**; nessuna operazione sulla Nikon.
