# HiddenMenu attivabile con il file modifica.modifica sulla SD

20 ottobre 2026 — R3/R4. **Sì: il prototipo offline usa il file come interruttore del menu, senza cambiare la variabile di stato Nikon.** Non è ancora inserito in un firmware installabile e non ripristina il firmware originale. NO-GO flash e circa10% funzionale invariati.

## Cosa farebbe sulla fotocamera

Il comportamento desiderato al punto di selezione è:

| Situazione | Scelta del prototipo |
|---|---|
| File `modifica.modifica` nella radice della SD | Richiesta di apertura HiddenMenu, ID20/0x20 |
| File assente | Continuazione normale |
| Cartella chiamata `modifica.modifica` | Continuazione normale |
| Servizio restituisce errore di volume, mount, ricerca o rilascio | Continuazione normale |

Il file può essere vuoto: il codice non ne legge il contenuto, controlla l’esistenza attraverso gli attributi. Questo viene provato con risposte filesystem simulate, non creando un file sulla SD reale. `B:` è associato staticamente a `DEVSD:` nella [tabella volumi Nikon](S33_Apertura_File_e_Volumi.md). Il percorso inserito nel codice è esattamente `B:\modifica.modifica`.

Togliere il file servirebbe a disattivare la richiesta HiddenMenu alla successiva esecuzione del controllo. **Non rimuoverebbe la patch dalla memoria della fotocamera.** Il software installato resterebbe modificato, anche usando l’interfaccia normale.

## Perché non basta come recupero

L’interruttore funziona soltanto se la macchina arriva a eseguire il controllo e i servizi chiamati terminano. Non ripara un caricatore danneggiato, una scrittura flash interrotta, un errore precedente al controllo o un servizio SD bloccato. I casi provati gestiscono risposte di errore: non dimostrano timeout o uscita da ogni attesa hardware.

Questo è quindi un modo per scegliere il percorso normale invece del menu di servizio, non un sistema di recupero o un ritorno automatico al binario Nikon originale. Restano necessarie le verifiche di avvio e recupero della [spiegazione semplice sulla sicurezza](S33_Sicurezza_Flash_Spiegata_Semplice.md).

## Prototipo effettivamente eseguito

[Sorgente ARC700](../S33-sections/safety_audit_codex/sd_marker_gate.s), [runner](../S33-sections/safety_audit_codex/verify_sd_marker_gate.py), [probe](../S33-sections/analysis_ghidra/scripts/ProbeSdMarkerGate.java), [manifest](../Ghidra_Results/ghidra_reports/sd_marker_gate/20261020T122656Z_85ce536b/verified_evidence.json), [disassemblato nuovo codice](../Ghidra_Results/ghidra_reports/sd_marker_gate/20261020T122656Z_85ce536b/gate_gnu.txt), [finestre originali](../Ghidra_Results/ghidra_reports/sd_marker_gate/20261020T122656Z_85ce536b/gnu_verified.txt), [traccia CPU](../Ghidra_Results/ghidra_reports/sd_marker_gate/20261020T122656Z_85ce536b/pcode.txt).

Il codice nuovo comprende340byte, stringhe incluse, collocati a `0x02000000` soltanto nel laboratorio. Lo stack è `[0x07000000,0x07001000)`. Nessuno dei due intervalli è identificato come spazio libero della fotocamera. Il test parte direttamente dal nuovo codice: nessun salto è stato scritto nel firmware Nikon e nessun pacchetto da installare è stato prodotto.

Il prototipo conserva r0..r12 sullo stack e usa i contratti della sonda Nikon già studiata: stato volume12B8E8, mount12B7E4 se necessario, predicato12BBB8/18B45C e rilascio12B888 se il mount è stato richiesto qui. Il predicato viene chiamato con r1=0, quindi accetta un oggetto trovato senza il bit directory0x10. Il percorso HiddenMenu originale usava invece r1=1 e richiedeva quel bit. Nel nuovo codice i controlli e la selezione sono istruzioni CPU, non una decisione impostata dal computer.

Il rilascio richiesto viene eseguito anche se il lookup fallisce. Un suo risultato nonzero disabilita la richiesta del menu; le due finestre12B888..12B8E8 documentano la propagazione del risultato r14→r0. Non vengono inventati nomi o significati fisici per i codici errore sintetici1/5.

Dopo il ripristino del contesto, se il file è valido il codice salta a135404, dove le istruzioni Nikon preparano ID20 e argomento0 prima della chiamata al manager1453E4. Nel caso normale esegue il vero getter129920, il confronto con2 e ripristina il link135414, quindi entra a135426. Non scrive366880 e non usa le due chiamate setter3→1 del prototipo precedente.

**Questa variante sostituisce entrambe le scelte diagnostiche del vecchio selettore**: senza file non cerca né HiddenMenu né ENABLE_NAND_TOOL, anche dagli stati sintetici2/3/255. È la scelta intenzionale per rendere il file il solo interruttore di questo prototipo. Non è equivalenza globale con ogni modalità di servizio Nikon preesistente.

## Verifiche appena eseguite

Comando dalla radice: `python3 S33-sections/safety_audit_codex/verify_sd_marker_gate.py`, senza `-O`.

- **60scenari**: stati iniziali0/1/2/3/255 ×12risposte filesystem: file, file vuoto, sola lettura, nascosto, assente, directory, errore volume, mount con file, mount senza file, errore mount, errore lookup, errore rilascio.
- **25richieste ID20 e35continuazioni normali**, senza fault o superamento del budget.
- In tutti i60casi il byte366880 conserva il valore iniziale e il tracking non registra alcuna scrittura a quella cella. Non viene chiamato il setter129904.
- Al punto di ripristino coincidono r0..r25, gp, fp, sp, ilink1/2 e lp_count con il contesto d’ingresso; il link è usato per il trasferimento di controllo. Non è dichiarata conservazione generale di STATUS32, timer o IRQ.
- **Una baseline originale CMP3/stato1** viene eseguita da1353F2 a135426. Nei sette casi normali con stato1, registri controllati, flagZ/N/C/V, SP e blink coincidono con quella baseline allo stesso confine. Non si afferma uguaglianza dell’intera RAM o degli effetti filesystem: la nuova sonda usa stack e servizi aggiuntivi.
- **8finestre GNU** controllano selettore, sonda, predicato file e ritorno del rilascio. Verificati campione originaleV1.1,16payload e hash della variante loopfix precedente. Nessuna nuova semanticaCPU.

Quattro servizi filesystem continuano a ricevere risposte simulate:12B8E8,12B7E4,12B888,26E6BC. Predicato12BBB8/18B45C, gestione stack, rami, getter e preparazione della richiesta menu sono eseguiti. La prova termina prima di eseguire il manager1453E4, oppure al confine normale135426: nessuna schermata o sessione UI completa dimostrata.

## Prima di un possibile collegamento al firmware

Restano posizione/residenza del codice, salto di aggancio, margine stack, corretto caricamento, integrità del pacchetto, avvio e recupero. Va verificato che la SD e i servizi siano disponibili proprio a quel punto anche nello stato ordinario1: l’originale normalmente saltava la sonda in quello stato.

`modifica.modifica` ha un’estensione più lunga del formato8.3: il nome esatto e il comportamento del filesystem fisico devono essere verificati. Il predicato Nikon osservato controlla il bit directory, non costituisce una validazione FAT indipendente di ogni combinazione anomala degli attributi. Non sono modellati rimozione concorrente della scheda, attese infinite, timer, interrupt e tutte le conseguenze dei mount/rilasci. La capacità RAM128MiB resta un’ipotesi del laboratorio.

Nessuna SD, RAM, flash o USB/PTP della Nikon è stata modificata o interrogata. Il file firmware originale resta identico per hash. Prossimo punto utile: disponibilità e durata dei servizi SD al punto di aggancio e collegamento della patch, continuando in parallelo logico le verifiche CPU/boot già aperte; il file non elimina i requisiti di recupero.

## Continuazione: collegamento reale nella copia offline

Il [nuovo bundle](S33_HiddenMenu_Prototipo_Collegato_Offline.md) esegue anche il salto a1353F2 nella copiaMain,con routine272byte e altri60scenari+baseline. Gli indirizzi restano laboratorio; la posizione candidata finale35BB04 è stata respinta perché referenziata come dato. Non è stato prodotto un contenitore Nikon da installare.
