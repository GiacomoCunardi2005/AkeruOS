# MULUDW: codifica verificata, ipotesi aritmetica e limite del modello

**Continuazione GNU corrente:** [SRdelay e controlli boot](S33_GNU_Controlli_Boot_e_Correzione_SR.md). Il default usa SRdelayv2; DSP separato v6.54test correggono la perdita del salto conSR nel delay slot. Main conclock100zero arriva adAUX201 a000B3106 (475857profiler); TBIB ha profili condizionali FED3800zero/nonzero distinti. Non usare la variante SRdelayv1 respinta, né le sintesi storiche sotto come punto corrente.

**Continuazione corrente,20 ottobre2026:** leggere prima [AUX/IRQ e fonti archiviate](S33_GNU_AUX_Interrupt_e_Fonti_Archiviate.md). Il motore GNU originale ha un difetto AUX fuori array confermato nel TBIB. `gnu-main` usa ora AUXv2 corretto; DSP separato v5 supera il vecchio limite AUX512 e arriva a scrittura4321→FE40004, restando provvisorio. I riferimenti a v3, attesaPDF e motore originale come default nelle sezioni storiche sotto sono superati.

**Continuazione GNU,20 ottobre2026.** [Nuovo rapporto](S33_GNU_MainCode_Divisione_e_DSP_Sperimentale.md): acquisito sorgente MAME fissato percommit, con doppio prodotto signed16×16. Non fornisce il contratto completo MULUDW/raw r56/r57 Nikon. Variante GNU separata v3 implementa soltanto ZA/noF/MACMODE0, piccoli operandi positivi oppure un operandozero;41casi verificano il modello e i suoi rifiuti, non la CPU fisica. Due MULUDW a fattorezero passano nel TBIB, poi guardia0103ECC8 con ingressi00B71B00/00010000. Formula completa e mapping raw restano da convalidare. Il manuale ARC700 DSP Options Reference rimanda al login Synopsys; link consegnato all'utente. In parallelo,49 divisioni TBIB sono eseguite e verificate sul motore GNU originale, senza alcuna semanticaDSP ipotizzata.

20 ottobre 2026 — R3/R4. **La semantica CPU completa di `muludw` non è ancora convalidata.** Non è stata aggiunta all'emulatore. Il nuovo controllo separa i byte verificati, le fonti indipendenti parziali e una proprietà matematica dell'ipotesi, evitando che un risultato aritmetico assunto venga presentato come inizializzazione UI eseguita.

## Controllo riproducibile

```bash
python3 S33-sections/safety_audit_codex/muludw_semantics_verify.py
```

[Script](../S33-sections/safety_audit_codex/muludw_semantics_verify.py), [JSON](../S33-sections/safety_audit_codex/muludw_semantics_verified.json), [GNU](../S33-sections/safety_audit_codex/evidence/muludw_semantics_gnu.txt), [log](../S33-sections/safety_audit_codex/evidence/muludw_semantics_run.log). Eseguito senza `-O`: **PASS,16payload,2finestre GNU,11istruzioni controllate,3codifiche e4.196coppie dell'ipotesi**. L'esito non è una convalida della CPU: il JSON conserva esplicitamente `independent_cpu_semantics_proven=false`.

Input CMP3/CMP1:29.602.084byte ciascuno, SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39` e `932281f89b840a45dc1b050dac52d5250f040ea6576b94696b55f3b93e123f1c`. Identità ricontrollate alla fine, insieme ai file originali del linguaggio e ai file firmati del modello aliasfix. Nessun firmware, decoder o probe UI modificato. Le finestre GNU derivano dal payload originale verificato; non sono una nuova esecuzione dei28casi UI.

## Byte e istruzioni effettivi

La tabella GNU locale `work/binutils-2.45/opcodes/arc-tbl.h` classifica `muludw` come DSP per ARC600/ARC700, con maschera `0xF8FF003F` e valore `0x280D003E` per la forma con destinazione0. Il bitF è0 in tutti e tre i punti controllati. Questo identifica codifica e assenza del suffisso `.f`, senza stabilire tutti gli effetti della CPU o degli accumulatori.

| Punto | Byte | Decodifica GNU |
|---|---|---|
| `0x3342B4` | `0d 28 be 00` | `muludw 0,r0,r2` |
| `0x3342BC` | `0d 28 7e 00` | `muludw 0,r0,r1` |
| `0x1563F4` | `0d 28 7e 00` | `muludw 0,r0,r1` |

Il corpo `0x3342A8` scrive0 ad `aux_macmode`, ruota il secondo operando di16bit, esegue la prima `muludw`, somma r56/r57, esegue la seconda `muludw` e ricombina il risultato con uno shift16. Il punto `0x1563F4` è anch'esso preceduto dalla scrittura0 ad `aux_macmode` e usa r57 nell'addizione successiva. Il modello UI resta fermo su queste istruzioni, come documentato nel [confronto differenziale](MENU_DIFFERENTIAL.md).

## Che cosa aggiungono le fonti indipendenti

Il [brevetto ARC US20050278505A1](https://patents.google.com/patent/US20050278505A1/en), descrizione della figura3, qualifica `Muldw` come doppia moltiplicazione16bit. È un riscontro indipendente dell'operazione parallela ipotizzata; **non definisce `MULUDW`, mappatura dei risultati, flag o modalità**. Non si usa la traduzione automatica della corrispondente domanda cinese come fonte più forte del testo inglese.

Il [sorgente GCC ARC](https://chromium.googlesource.com/chromiumos/third_party/gcc/+/refs/heads/firmware-veyron-6588.B/gcc/config/arc/arc.c) distingue i registri DSP fisici r56/r57, denominati acc1/acc2, dai registri dell'opzione mul64. È un riscontro dei nomi, non della funzione esatta di `muludw`. Non confondere la numerazione interna GCC, dipendente dall'endianness, con quella fisica.

Il nuovo [manuale Synopsys ARC EM, versione5755-101](https://docs.alexrp.com/arc/arc_em.pdf) consultato riguarda ARCv2 e non contiene `MULUDW`: le sue istruzioni DSP non vengono trasferite automaticamente al caso ARCv1. Anche il [contributo libgcc del2013](https://gcc.gnu.org/pipermail/gcc-patches/2013-September/369320.html) usa `mululw` e altre operazioni, senza risolvere `muludw`. Il simulatore GNU locale enumera MULUDW13, ma implementa un'operazione diversa, `mululw`, come32×16: la presenza del nome nell'enumerazione non è un'implementazione.

La [documentazione primaria del modello OVP ARC700](https://www.ovpworld.org/modeldocs/OVP_Model_Specific_Information_arc_700.pdf) descrive un modello ARCv1, ma non fornisce una definizione DSP/MULUDW nel documento consultato. L'accesso alle pagine della libreria è fallito durante questa ricerca; il sorgente del modello non è stato acquisito, compilato o eseguito. Non è quindi un secondo simulatore usato per convalidare i risultati.

## Proprietà condizionale del calcolo Nikon

Ipotesi da convalidare, **non semantica installata**:

```text
r56 = high16(A) * high16(B), prodotti senza segno
r57 = low16(A)  * low16(B)
```

Scrivendo A=Ah·2^16+Al e B=Bh·2^16+Bl, il primo prodotto dopo la rotazione diB fornisce i due termini incrociati Ah·Bl e Al·Bh. Il risultato del corpo Nikon sarebbe quindi:

```text
Al·Bl + ((Ah·Bl + Al·Bh) << 16)  modulo 2^32
  = A·B modulo 2^32
```

Questa identità vale algebricamente per tutti gli operandi32bit sotto l'ipotesi dichiarata. Le4.196coppie deterministiche, incluse100combinazioni di bordi, controllano l'implementazione Python della formula; **non forniscono4.196osservazioni della CPU**.

Il controllo negativo mostra perché non si può inserire un prodotto32×32 generico con parte alta inr56 e bassa inr57: per A=1,B=0x10000, il corpo ricombinato darebbe0x20000 invece di0x10000. È un controesempio a quella sostituzione, non un'esecuzione di `mulu64` GNU. L'istruzione `mulu64` ha anche un contratto di registri distinto.

Prima di estendere l'emulatore restano da verificare indipendentemente la variante unsigned e l'ordine dei canali, la pubblicazione acc1/acc2, guardie e stato degli accumulatori, eventuali effetti senza `.f`, il significato di MACMODE0 e l'assenza di effetti XY nella forma usata. Serve una definizione ARCv1 DSP pertinente, un modello indipendente che implementi davvero l'istruzione o una prova autorizzata specifica. Nessuna azione hardware è stata effettuata.

**Il test non fa avanzare il menu e non dimostra boot o recupero. NO-GO flash e circa10% funzionale invariati.** Prossimo punto: acquisire quella definizione prima di produrre nuovi risultati UI oltre i limiti già registrati.
