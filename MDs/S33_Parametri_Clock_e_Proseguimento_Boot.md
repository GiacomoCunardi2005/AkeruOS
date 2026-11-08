# Record hardware e sorgenti del calcolo clock candidato

**Continuazione GNU, 20 ottobre 2026.** [Integrazione e prove nuove](S33_GNU_ARC700_Integrazione_e_Limite_DSP.md): baseline TBIB riprodotta con profiler10.952; quattro combinazioni F8/word50–64 e un profilo RAM128MiBzero superano la lettura108/120 sintetica e si fermano sul decode vuoto di MULDW a01009B8C. Sei probe separano `sr`/lettura r57 eseguibili da MULDW/MULUDW rifiutate dal motore. Non è ancora calcolo completo o frequenza fisica; non sostituire il DSP con l'ipotesi aritmetica del vecchio modello. Il testo seguente conserva il checkpoint P-code precedente e i suoi conteggi, distinti dal nuovo motore GNU.

20 ottobre2026,R3/R4. Continuazione della [RAM128MiB](S33_Emulazione_RAM_128_MiB.md). Con RAMunknown, i record12/13 leggono una halfword da0FE80050/64: il firmware conserva il nibble basso come parametro e bit4 sceglie modalità8 oppure16. Il nome clock è un'interpretazione della forma dei calcoli, non una frequenza fisica misurata.

[Runner](../S33-sections/safety_audit_codex/verify_clock_registers.py), [probe](../S33-sections/analysis_ghidra/scripts/ProbeClockRegisters.java), [manifest](../S33-sections/safety_audit_codex/clock_registers_verified.json), [11finestreGNU](../S33-sections/safety_audit_codex/evidence/clock_registers_gnu.txt), [log](../S33-sections/safety_audit_codex/evidence/clock_registers_run.log). Riproduzione: `python3 S33-sections/safety_audit_codex/verify_clock_registers.py`.

Eseguiti48casi isolati: MainCode/TBIB ×record12/13 ×word0/1/15/16/31/65535 ×CMP3/CMP1. Gli assert controllano PC di uscita, r0=modo16 sebit4zero oppure8 seuno, r13=word&15, assenza di fault e budget.32tentativi limitati di avvio combinano word0/16 al registro selezionato, selettoreF8=0/128, STATUS32nonflag0/6, dueingressi e duecampioni. Rimangono basevettori0 e contesto core sintetici; nessun interrupt fisico. TracceCMP3/CMP1 identiche nel perimetro registrato, BSS1.758.364byte daA5 ricontrollata a439690passi.

| Word simulata50/64 | Modo scelto | Lettura successiva | Main: passi conF8=0/128 | TBIB: passi conF8=0/128 |
|---|---:|---|---|---|
|0 |16 |halfword0FE80108 |444369/444370 |10784/10785 |
|16 |8 |halfword0FE80120 |444368/444369 |10783/10784 |

ArrestoMain17A6D6,TBIB01009B6A, stessoindirizzo/dimensione di fault attesi perogni profilo e nessunerroreGhidra. Non sono risposte del silicio: i registri50/64 ricevono soltanto le parole costanti dichiarate; gli altriMMIO restano sconosciuti. Il modello128MiBunknown e gli helperCPU vengono riusati, senza nuovi decoder.

La tabella byte con segno179EFA, riletta come dati, manda modo8 a179F0E→179ECC→17A768, modo16 a179F12→179EE0→17A784. I getter consultano cache367B78+4/+8: sezero chiamano17A6CC rispettivamente con le coppie di registri0FE80118/120 e0FE80100/108. Il primo registro letto è il secondo argomento. Più avanti17A6F8 contieneMULDW, non ancora supportata: non è stata eseguita nei boot diquestotest, non sostituita e non convalidata. Per proseguire servono valori di laboratorio espliciti per i nuovi parametri e una semanticaDSP verificata prima di completare quelcalcolo.

Firmware e decoder precedenti immutati, hash manifestRAM128 ricontrollati prima/dopo. Nessun hardware, nessun boot/UI/recupero completo; NO-GO e circa10% funzionale invariati.
