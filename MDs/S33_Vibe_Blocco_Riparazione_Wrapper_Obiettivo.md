# Vibe: ciclo di correzioni e riparazione del verificatore obiettivo

21 ottobre 2026 — supporto R0/R1. Circa 10% funzionale invariato.

Il processo runner PID 781196 e il figlio Vibe PID 783934 erano ancora attivi.
Il log segnalava modifiche ripetute al verificatore wrapper. Il runner è stato
fermato con SIGTERM prima di modificare il file; entrambi i processi sono usciti,
`Risultati/Vibe_Offline/latest.json` registra `status: stop`, exit 3,
`vibe_outcome: terminated`. Il ciclo non è stato riavviato da noi.

## Causa e riparazione

Una sostituzione `sed` globale aveva sostituito l'escape del punto nelle regex
con il testo `[r3+0xC6..0xDA] observed 198..218`: 11 occorrenze danneggiate.
Lo script precedente è conservato in `Wrapper_Repair/.../before.py` con hash
e provenienza. La riparazione usa una sostituzione letterale esatta, senza
eliminare le asserzioni. Il comando Python è stato eseguito direttamente:
la precedente pipe `| tail` poteva restituire il successo di tail dopo un
fallimento del verificatore.

Dopo la riparazione delle regex è emersa un'asserzione con `mov_s r0,0x0`;
GNU stampa l'istruzione come `mov_s r0,0`. Il confronto è stato corretto sulla
finestra originale, conservando la verifica dello store successivo.

La finestra switch partiva da 0x1EE730 ma attraversava la tabella dati a
0x1EE77A: il disassemblaggio lineare perdeva il primo load di alcuni rami.
Ora si decodificano separatamente:

- Header `[0x1EE730,0x1EE77A)`.
- Sette target `0x1EE782`, `0x1EE79C`, `0x1EE7B6`, `0x1EE7D0`, `0x1EE7EA`,
  `0x1EE85A`, `0x1EE874`, calcolati come base tabella + 2×byte.
- Tratto comune `[0x1EE802,0x1EE830)`.

Ogni ramo è verificato sui due load halfword: campi `196+2*i` e `210+2*i`,
cioè 14 campi da **0xC4 a 0xDE**, non la lista incompleta derivata dalla
decodifica precedente. La seconda tabella inline a 0x1EE852 resta esclusa
da queste finestre; non viene presentata come codice verificato.

## Verifica e limiti

Comando effettivo:

```bash
python3 Python_Trace_Scripts/s33_verify_lens_wrapper_classification.py
```

Esito **PASS**, exit 0, senza pipe. Conservati elenco dei 33 chiamanti,
controlli letterali e finestre wrapper; aggiunti controlli specifici per i
sette rami. [Script](../Python_Trace_Scripts/s33_verify_lens_wrapper_classification.py),
[prove classificazione](../Risultati/Lens_MCU_Interface/Wrapper_Classification/latest.json),
[riparazione, snapshot e log](../Risultati/Lens_MCU_Interface/Wrapper_Repair/latest.json).

La classificazione per chiamante resta un'analisi candidata su finestra limitata
del listato lineare: 13 siti restano `other`. Il wrapper diaframma/iris non è
identificato; i significati fisici dei byte non sono provati. Nessun firmware
eseguito, nessun accesso hardware, nessuna conclusione di installabilità.

Il prompt del runner ora richiede verificatori senza pipe che mascherino gli
errori, patch esatte per le regex, checkpoint intermedi e cambio di domanda
dopo tre tentativi falliti sullo stesso problema. Richiede inoltre di evitare
cicli ripetuti di listing/sleep. Sono istruzioni al modello, non un limite
automatico imposto dal supervisore. Le chiamate Vibe restano seriali.

Prossimo passo: usare il risultato verificato senza rifare queste correzioni;
ricercare una prova distinta per associare un wrapper al comando iris oppure
passare a un altro punto offline se manca un'ancora. Il checkpoint del runner
è aggiornato per non ricominciare dal file danneggiato.
