# Semantica del record 22 byte, di 0x301EC0 e degli argomenti degli orchestratori comandi obiettivo

**Correzione23ottobre2026:** [S33_Correzione_Identita_Cluster_25F338_NAND.md](S33_Correzione_Identita_Cluster_25F338_NAND.md). L’attribuzione di25F338/25CBxx–260Dxx al MCU dell’obiettivo è ritirata: percorsi originaliDEVNAND/updater verificati. Questo rapporto conserva byte/formule/provenienza storici; le relative etichette ottiche non sono conclusioni valide.

**Data:** 22 ottobre 2026 (iterazione 8 del ciclo Vibe persistente; recupera anche la documentazione dell'iterazione 7 interrotta) · **Tappe:** R0/R1 · **Esito:** PASS statico, decodifica del punto aperto dell'iterazione 7, nessun hardware toccato · **Stima complessiva: circa 10% invariata**

- Script riproducibile: [Python_Trace_Scripts/s33_verify_lens_orchestrator_args.py](../Python_Trace_Scripts/s33_verify_lens_orchestrator_args.py)
- Evidenze: [Risultati/Lens_MCU_Interface/Orchestrator_Args/latest.json](../Risultati/Lens_MCU_Interface/Orchestrator_Args/latest.json) (4 finestre GNU allineate + corpo 0x301EC0 verificato byte-exact, pool raw LE, modello ceil su 65.536 valori, snapshot script e hash sorgenti)
- Chiude il punto aperto 9 di [Chiamanti del modulo orchestratore](S33_Obiettivo_Chiamanti_Modulo_Orchestrazione.md): «decodificare il riempimento del record 22 byte in 0x301EC0».
- Agente `orch-args-audit` (revisione indipendente, configurazione ereditata): esito in §8.

## 1. Domanda e metodo

Punto aperto dell'iterazione 7: sulla rotta statica payload4(tuning) → 0x301E1C (strato API stato) → 0x29E8F0 (orchestratore) → scrittori ctrl → wire, decodificare il significato del «record 22 byte» che 0x301E1C azzera prima della chiamata, il ruolo della funzione 0x301EC0 (chiamata subito dopo l'azzeramento) e la semantica dei 7 argomenti r0–r6 passati a 0x29E8F0. Metodo: finestre GNU allineate agli ingressi delle quattro funzioni coinvolte, lettura dei pool pcl come word LITTLE-ENDIAN dai byte raw del payload0 (la colonna byte di objdump stampa i chunk da 32 bit in ordine di halfword «istruzione» ARC: il pool 0x301EF4 vale 0xE972, non 0x72E9), corpo di 0x301EC0 verificato byte-exact contro il layout regolare, modello Python della trasformazione halfword su tutti i 65.536 valori.

## 2. Il record 22 byte È il blocco argomenti

Il «record 22 byte» non è una struttura separata: è il blocco degli argomenti impacchettato `{a0..a4 word, a5[15:0]}`.

- **Chiamante 0x301E1C**: `memcpy(dst=fp-0x18, src=0x354DE4, len=0x16)` (pool 0x301EBC); i 22 byte a 0x354DE4 sono tutti zero, subito dopo le stringhe `BootNANDBase.bin` (0x354DC1) e `BootNANDBase.dmp` (0x354DD2). Il frame è 0x18=24 byte, quindi la copia da 22 lascia `[fp-2],[fp-1]` non inizializzati.
- **Orchestratore 0x29E8F0**: salva i propri argomenti `r0..r5` a `[sp+0x28..0x3C]` (r0@0x28, r1@0x2C, r2@0x30, r3@0x34, r4@0x38, r5@0x3C) e ricopia esattamente 22 byte di quell'area (`[sp+0x28..0x3D]` = r0..r4 interi + mezza word bassa di r5) nel record locale a `[sp+4]` con `memcpy(sp+4, sp+0x28, 0x16)`. Anche qui la copia lascia `[sp+0x1A],[sp+0x1B]` non coperti nella sesta word inoltrata.

Il layout del record è quindi: offset 0–3 = a0, 4–7 = a1, 8–11 = a2, 12–15 = a3, 16–19 = a4, 20–21 = a5[15:0].

## 3. 0x301EC0: non un riempitore, ma 4 strobe MMIO sul banco 0x0FE400xx

La funzione 0x301EC0 (chiamata da 0x301E1C subito dopo l'azzeramento del record, prima dei validatori) è una sequenza di quattro scritture halfword `.di` (bypass cache) a indirizzi e valori costanti da pool pcl:

| valore | indirizzo | pool (addr, val) |
|---|---|---|
| 0x4321 | 0x0FE40004 | 0x301EC8, 0x301ECC |
| 0x6641 | 0x0FE40008 | 0x301EDC, 0x301EE0 |
| 0xE972 | 0x0FE4000C | 0x301EF0, 0x301EF4 |
| 0xFFFF | 0x0FE40010 | 0x301F04, 0x301F08 |

Ogni blocco è `ld_s r1,[pcl,8]` (indirizzo) + `ld_s r0,[pcl,8|0xC]` (valore) + `b_s` sopra il pool + `sth.di r0,[r1]`; il primo blocco non ha `nop_s` di padding, gli altri tre sì; chiusura `pop_s blink; j_s [blink]` (0x301F10/0x301F12). Il corpo intero (0x54 byte, 0x301EC0..0x301F14) è verificato byte-exact contro questo layout.

**Collegamento al boot:** il banco **0x0FE400xx** è lo stesso su cui l'emulazione GNU DSPv5 si è sempre fermata in TBIB (scrittura halfword 0x4321 → 0x0FE40004 a 0x010091F8; [AUX/IRQ e fonti](S33_GNU_AUX_Interrupt_e_Fonti_Archiviate.md)). 0x301EC0 è uno **scrittore Main-side dello stesso banco**: la rotta API stato lo tocca prima di ogni validazione. L'identità della periferica resta aperta; il rapporto AUX ricorda che il wrapper TBIB scrive 0x4321 in 0x0FE40008 e 0xECA2 in 0x0FE4000C construendo campi dai suoi 4 argomenti.

## 4. 0x301E1C: la rotta API stato passa un record TUTTO ZERO

Dopo 0x301EC0, 0x301E1C esegue i validatori `0x3013A0` e `0x30183C`, poi `0x30026C` (arg0==1) o `0x30144C`, poi `0x300D94`; ogni ritorno non zero esce con errore. Quindi ricarica le 6 word dal frame azzerato (`ld r15,[fp,-8]`, `ld r5,[fp,-4]`, `ld r0,[fp,-24]` … `ld r3,[fp,-12]`), mette `mov r6,r13` (arg1) e chiama `0x29E8F0(r0..r5 = zeri, r6 = arg1)`. Seguono `0x16F200` e `0x30188C`.

Quindi sulla rotta API stato: **a0..a4 = 0** e **a5 porta 16 bit di residuo di stack** (`[fp-2],[fp-1]` non coperti dalla copia da 22 byte). L'unico input non zero è **r6 = arg1**, il selettore (valori 1 e r16 nei tre siti del tuning payload4). La rotta è coerente con un comando/query «senza parametri»: i parametri halfword dei contesti (campi 0xC4..0xDE) non vengono forniti da questo strato.

## 5. 0x29E8F0: risoluzione ctxA, copia, scalatura ceil(h/8) condizionale, dispatch

Semantica byte-verificata dell'orchestratore chiamato:

1. salva `r0..r5` in `[sp+0x28..0x3C]` (r6 NON è salvato: vedi §7);
2. risolve ctxA con `0x25CAEC(0)`, risultato in `[sp,0]` (ancora di iterazione 2: ctxA = 0x50F52C);
3. copia il blocco argomenti da 22 byte nel record locale `[sp+4]`;
4. se il **bit 0xA di ctxA[+2]** è attivo (`btst_s`), trasforma le 5 halfword di parametro del record agli offset 6..14 (fonte `[sp,46/48/50/52/54]` = r1_hi, r2_lo, r2_hi, r3_lo, r3_hi) con `h ← ceil(h/8)`:
   `ldh r0,[sp,SRC] / bmsk.f 0,r0,0x2 / asr_s r0,r0,0x3 / beq_s +4 / add_s r0,r0,0x1 / sth r0,[sp,DST]`;
   `bmsk.f 0,…` è l'idioma ARC a destinazione fittizia flags-only (72 `sub.f 0,` nel listato integrale): i flag dicono `(h & 7) != 0`, mentre `asr_s` (senza flag) calcola `h>>3` dall'h originale, quindi il risultato è `(h>>3) + ((h&7)?1:0) = ceil(h/8)`, verificato dal modello su tutti i 65.536 valori;
5. controlla `0x1593AC(0x1B00001, 0)` (pool 0x29EB84 = 0x1B00001, id errore dell'iterazione 5); ritorno non zero → uscita di errore via `0x1594A4`;
6. ricarica le 6 word del record `[sp+4/8/0xC/0x10/0x14/0x18]` e chiama **0x29E680(record[0..20])**.

Le trasformazioni sono in-place: l'offset di destinazione del record coincide con l'offset di fonte −0x28 (6,8,10,12,14).

## 6. 0x29E680: intake del blocco a 6 word via 0x25C038

L'orchestratore principale salva i 6 argomenti a `[sp+0x1C..0x30]`, risolve ctxA con `0x25CAEC(sp+4)` e quindi chiama **`0x25C038(r0=ctxA, r1=sp+0x1C)`**: l'indirizzo del blocco argomenti viene passato insieme al puntatore di contesto — candidato intake del blocco nei campi comando di ctxA (0xC4..0xDE del dispatch 0x1EE730 di iterazione 2), da byte-verificare dentro 0x25C038. Seguono: `0x25BFB0`, `0x25CADC`, `0x25CAF4`, attenzione `0x25F28C` (0xFF), fill ctxB `0x25C020`, controllo dello stride 236 (`add2 r0,r1,0x3b / sub / cmp 236`; esito diverso → id errore 0x1B00105, pool 0x29E758), controllo di stato `0x25D3AC`, e le copie del template 0x3F6698 → 0x50F210 (528 byte) e → 0x50F310 (244 byte) — ancore di iterazione 5 confermate.

## 7. Il settimo argomento (r6) resta aperto

0x29E8F0 non salva né ricarica r6: il suo inoltro a 0x29E680 dipende dal fatto che `0x25CAEC`, `0x128C20` e `0x1593AC` preservino r6 (ABI callee-saved non verificata). Anche 0x29E680 non salva r6 nel prologo esaminato. Non affermare che arg1 arrivi a destinazione: è un punto aperto, con i 2 byte di residuo della sesta word (§2) come secondo canale non determinato.

## 8. Revisione indipendente (agente)

Esito dell'agente `orch-args-audit` (configurazione ereditata; lo strumento «task con agente explore» non esiste in questo ambiente, come già annotato nelle iterazioni precedenti): vedere il checkpoint di consegne [S33_Vibe_Offline_Checkpoint.md](S33_Vibe_Offline_Checkpoint.md), sezione iterazione 8.

## 9. Limiti

- Statico: nessun MMIO, nessuna MCU obiettivo o fotocamera toccata, nessun firmware eseguito; NON_INSTALLARE.
- La semantica ceil(h/8) deriva dal listato (idioma flags-only + `asr_s` senza flag) ed è modellata in Python su tutti i 65.536 valori; non è provata sulla CPU fisica.
- I valori runtime del residuo di stack nelle 2 byte non coperti, e l'inoltro di r6, restano indeterminati.
- `0x25C038` va ancora byte-verificato per chiudere il legame blocco→campi ctxA 0xC4..0xDE.
- L'identità della periferica 0x0FE400xx resta aperta; il riferimento incrociato TBIB (0x4321→0x0FE40004 a 0x010091F8) viene dal rapporto GNU DSPv5, non è stato riverificato qui.
- V1.1 analizzato vs macchina V1.0: nessun trasferimento automatico di indirizzi.

## 10. Prossimo passo (non ripetitivo)

Byte-verificare **0x25C038** (intake candidato: dove scrive le 6 word del blocco dentro ctxA e in quali campi 0xC4..0xDE), per chiudere il cerchio argomenti → contesti → switch 0x1EE730; in alternativa identificare la periferica del banco 0x0FE400xx risalendo ai suoi lettori/scrittori nel Main (0x301EC0 è il primo scrittore Main-side noto del banco).
