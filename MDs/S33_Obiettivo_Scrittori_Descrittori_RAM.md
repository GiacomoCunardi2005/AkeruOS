# Scrittori dei descrittori RAM obiettivo, template statico 0x3F6698 e provenienza di r57

**Correzione23ottobre2026:** [S33_Correzione_Identita_Cluster_25F338_NAND.md](S33_Correzione_Identita_Cluster_25F338_NAND.md). L’attribuzione di25F338/25CBxx–260Dxx al MCU dell’obiettivo è ritirata: percorsi originaliDEVNAND/updater verificati. Questo rapporto conserva byte/formule/provenienza storici; le relative etichette ottiche non sono conclusioni valide.

**Data:** 21 ottobre 2026 (iterazione 2 del ciclo Vibe persistente) · **Tappe:** R0/R1 · **Esito:** PASS statico, nessun hardware toccato · **Stima complessiva: circa 10% invariata**

- Script riproducibile: [Python_Trace_Scripts/s33_verify_lens_descriptor_writers.py](../Python_Trace_Scripts/s33_verify_lens_descriptor_writers.py)
- Evidenze: [Risultati/Lens_MCU_Interface/Descriptor_Writers/latest.json](../Risultati/Lens_MCU_Interface/Descriptor_Writers/latest.json), 10 finestre GNU allineate in `gnu_windows.txt` nella cartella datata.
- Chiude il punto 1 del prossimo passo del checkpoint Status_API ([contesti e API stato](S33_Obiettivo_Contesti_Parametri_e_API_Stato.md), §8): scrittori dei descrittori RAM e provenienza di r57. Continua [il protocollo wire](S33_Obiettivo_MCU_Formato_Wire_Decodificato.md) e [la classificazione wrapper](S33_Vibe_Blocco_Riparazione_Wrapper_Obiettivo.md).

## 1. Domanda e metodo

Chi riempie a runtime i descrittori della transazione obiettivo — ctrl **0x36B254** e record **0x50E940**, dominanti su r2/r1 di 0x25F338 — e da dove viene r57 della primitiva di movimento 0x29DDD4? Metodo consolidato: scansione word LE a passo 2 su payload0 con classificazione pcl/limm/straddle, ingressi ricostruiti dall'halfword `push_s blink` (0xC0F1), finestre GNU allineate, censimento chiamanti su tutti i 16 listati; un agente indipendente (`desc-writers-audit`) ha ripetuto il censimento in parallelo, includendo la ricerca dei limm middle-endian e delle funzioni feeder; le sue affermazioni chiave sono state riverificate sui byte in questa sessione (tre finestre aggiunte al verificatore).

## 2. I descrittori sono oltre l'immagine payload0

payload0 = [0x0AD800, **0x35BC00**). Tutti gli oggetti 0x36B254/0x36B25C/0x36C3E8 e 0x50E140/0x50E340/0x50E940/0x50E950/0x50F210/0x50F21A/0x50F310/0x50F31A sono **≥ 0x35BC00**: RAM senza contenuto statico nell'immagine. La cella **0x54D8A8** sta nel gap RAM fra payload1 (fine 0x428600) e payload2 (base 0x5FE800).

## 3. Scrittori del descrittore ctrl 0x36B254 (byte-verificati)

| Funzione | Scritture su ctrl | Ruolo |
|---|---|---|
| **0x29E1A4** | `stb [ctrl+0]` conteggio (1), `stb [ctrl+1]` byte comando = 0, `stw [ctrl+2]` = 0 o halfword da **ctxA[+0xE4]**; limiti ctxB[+4]/[+6] | **loop write-verify-reinit n.2**: 0x25F6A4(record 0x50E940) → 0x25F28C → 0x25CBF0 → 0x29DDD4 → 0x260C6C, retry via 0x1EDC10. Specchio del loop 0x1EEF6C |
| **0x29DF18** | `stb [ctrl+0]=0`, `stb [ctrl+1]=0`, `stw [ctrl+2]` contatore, limite ctxB[+4] | writer fratello (variante senza fase parametri) |
| **0x29E458** | passa ctrl (ld.as pool 0x29E2AC) a 0x25C1F0, legge halfword [ctrl+2] | record writer + bulk 0x13A954 con 0x50E140 e ctxA[+0x10]×512 |
| **0x29E574** | `stb [ctrl+1]=0`, `stb [ctrl+0]=0`, `stw [ctrl+2]=1`, legge ctxB[+0xC4] | 0x25C37C(ctrl) + 0x13A954 con 0x50E140; **ctxB[+0xC4]** è il primo campo della famiglia 0xC4..0xDE dello switch 0x1EE730 |

Layout confermato del ctrl: **+0 byte conteggio/stato** (0 o ctxA[+4]−1), **+1 byte stato/tipo** (0/4/8/0x11, incrementato nei loop e confrontato col comando ctxA[+5] — non è un byte dati; il byte wire resta iniettato per-transazione da 0x25F3F4), **+2 word** (stw_s/ldw_s, contatore o parametro). Le due `ld.as` dei fratelli risolvono con la formula scalata (PC&~3)+s9·4 → pool 0x29E2AC → 0x36B254. Lo switch **0x1EE730** scrive il reset {+0=0, +1=4, +2=0} **solo se bit0xA di ctxA[+2] è attivo** (0x1EE810–0x1EE826) e poi chiama 0x25F338(0x54D8A8, record, ctrl, 0); l'hub **0x1EE148** scrive **direttamente nel record** i marker di risposta 0x55/0xAA a +6/+7/+0xB/+0xC e riempie record+0x10.. con 0xFF.

La revisione indipendente dell'agente `desc-writers-audit` (integrata con riverifica sui byte) allarga il censimento: **~20 siti statici writer/feeder del ctrl** in tutto il cluster (0x1ECBF4, 0x1ECE22, 0x1ECFD8, 0x1ED440, 0x1ED5E4, 0x1EDA10, 0x1EDB48, 0x1EDC10/78/9C, 0x1EDD2C, 0x1EDDB4, 0x1EDFDC, 0x1EE148, 0x1EE730, 0x1EEAEE, 0x1EEF6C, 0x1EF3E8, 0x1EF53C, 0x29E458/0x29E574, 0x29E682 — classificazione candidata su finestre allineate), con la famiglia descrittori genitore **0x36B244** (bit-table 0x50F190, indice [0x36B24C], stato [0x36B250]; ctrl = [0x36B244+0x10] scritto via 0x25C87C). **Negativo importante: nessun writer statico del bit0xA di ctxA[+2]** nel censimento di tutte le funzioni che chiamano i filler dei contesti (l'unico writer statico della word è 0x25D3AC, bit7 su fallimento della query stato): l'origine del flag è runtime/lato MCU. Nota metodologica: i limm ARC sono **middle-endian** (es. byte `50 00 40 e9` per 0x50E940 a 0x29E846, unico limm del record in payload0, qui assertito sui byte raw), quindi le scansioni word LE contano solo i pool pcl.

## 4-bis. CORREZIONE (iterazione 4, 21 ottobre 2026)

Il punto 4 sopra («la famiglia di wrapper accessor 0x25E7xx–0x25EAxx chiama band entry interne») è **sbagliato**: era un artefatto di decodifica. La finestra GNU allineata all'ingresso dell'accessor attraversa il pool word della `ld_s` (l'indirizzo del registro MMIO) e decodifica byte di pool + istruzioni reali come `st_s`/`bl`/`bln` mai eseguiti. I 12 accessor sono **getter bitfield del banco ausiliario 0x0FFCA084..0x0FFCA0BC** (`ldh.di` + `and`/limm + ritorno con shift nel delay slot); i 12 siti `bln` cadono tutti a g+0xE, dentro la `ldh.di` reale. Nessuna funzione del firmware chiama le band entry 0x29E85C..0x29EBC4; gli orchestratori restano senza chiamanti statici. Dettagli e verifiche: [Accessor MMIO e correzione band entry](S33_Obiettivo_Accessor_MMIO_Correzione_Band_Entry.md), script `s33_verify_lens_aux_mmio_accessors.py`. Il testo originale del punto 4 è conservato qui sopra come provenienza storica.

## 4. Orchestratori e template statico 0x3F6698 (novità principale)

**0x29E682** (e il gemello a 8 argomenti **0x29E9C6**, più il modulo intermedio 0x29E8F2) possiede l'area descrittori:

1. riempie i contesti (0x25CAEC→[sp+4], 0x25C020→[sp]), validatore 0x25BFB0, attenzione 0x25F28C;
2. copia un **template statico dai dati di payload1** con memcpy 0x128C20:
   - `memcpy(0x50F210, 0x3F6698, 528)` — **0x50F210+528 = 0x50F420 = inizio esatto del contesto B**;
   - `memcpy(0x50F310, 0x3F6698, 244)`; destinazioni ausiliarie 0x50F21A/0x50F31A via 0xAD920;
3. **dispatch su bit0xA di ctxA[+2]** (tre siti `btst r0,0xa`): 0x29E1A4 vs 0x29DF18, poi 0x29E458 vs 0x29E574, poi hub 0x1EE148 e record writer 0x25C1F0 vs 0x25C37C.

Il template a **0x3F6698** (payload1, 528 byte, 282 non zero, SHA-256 `46888e6e7a31146e3fc1d4b43a280c0b52bd963a167866197f0be16ac64014d4`, primi byte `02 04 da 02 ff 19 03 e0`) è il **primo inizializzatore statico trovato per una parte dell'area 0x50Fxxx**. I contesti 0x50F420/0x50F52C restano runtime-only (checkpoint precedente invariato). Il pool dell'hub 0x1EE148 (0x1EE594..0x1EE5B0) contiene l'intera famiglia: 0x50E940, 0x36C3E8, 0x3F6698, 0x50F210, 0x50F21A, 0x50F310, 0x50F31A, 0x54D8A8.

**Negativo verificato su tutti i 16 payload:** nessun `bl/b/jl` verso 0x29E682/0x29E8F2/0x29E9C6 e nessuna word-puntatore. Sono **moduli multi-ingresso**: la famiglia di wrapper accessor 0x25E7xx–0x25EAxx (`push_s blink`, es. 0x25E750) chiama **band entry interne** (0x29E85C, 0x29E8B0, 0x29E8D0, 0x29E958, 0x29E9AC, 0x29E9CC, 0x29EA54, 0x29EAA8, 0x29EAC8, 0x29EB50, 0x29EBA4, 0x29EBC4; censimento candidato su listato lineare, 0x25E750 riverificato allineato).

## 5. Provenienza di r57 (chiusa)

In 0x29DDD4 **r57 non è un argomento del chiamante**: è la metà del prodotto 64-bit del `muludw` calcolato dentro la funzione dopo `sr 0,[aux_macmode]` (arg0 è il ctrl stesso: tutti i chiamanti statici passano r0=0x36B254; su quale metà del prodotto vada r57 resta il caveat condizionale di `MULUDW_SEMANTICS.md` — l'agente legge la metà alta):

```
r13 = arg0 = ctrl                          ; r2 = byte [ctrl+0]
P1  = muludw( word [ctxA+6], [ctrl+0] )    ; r57 usato
r0  = [ctrl+2] + r57
P2  = muludw( byte [ctxA+5], r0 )          ; r57 = metà usata dal firmware
→ byte extb(r57) e byte (r57>>8) scritti su 0x0FF05000 via 0x25E078
```

Dopo la mossa il flag testato è il **bit8 di ctxA[+2]** (0x29DE38), non bit0xA. La posizione wire è quindi il prodotto comando×(offset + passo·contatore) determinato da ctxA[+5]/[+6] e dal ctrl; il packer 0x25CB54 usa lo stesso schema r57/muludw sul contesto 0x50F514.

## 6. Sintesi

```
wrapper accessor 0x25E7xx..0x25EAxx (push_s blink)
   └─ band entry interne dei moduli 0x29E682 / 0x29E8F2 / 0x29E9C6
        ├─ memcpy 0x128C20: template statico payload1 0x3F6698 → RAM 0x50F210/0x50F310
        ├─ dispatch bit0xA di ctxA[+2]:
        │    0x29E1A4 (ctrl writer + record 0x50E940, reinit 0x29DDD4) / 0x29DF18
        │    0x29E458 (0x25C1F0 ctrl) / 0x29E574 (0x25C37C ctrl, ctxB[+0xC4])
        └─ hub 0x1EE148 → switch 0x1EE730 (parametri 0xC4..0xDE) → transazione 0x25F338
ctrl 0x36B254: +0 conteggio · +1 comando (0x25F3F4) · +2 halfword (0 / ctxA[+0xE4])
r57 = muludw(ctxA[+5], [arg0+2] + muludw(ctxA[+6], [arg0+0]))
```

## 7. Limiti

- Statico, nessun hardware/esecuzione, NON_INSTALLARE; V1.1 analizzata vs macchina V1.0.
- Il lato chiamante degli accessor 0x25E7xx non è tracciato: il blocco AE/iris 0x1236BC **non risulta** fra i chiamanti di 0x1EE148/0x1EDFDC in un `bl` (censimento: solo 0x1EEA42 dallo switch e 0x29E7A8 dall'orchestratore) — l'aggancio AE→wire resta aperto.
- muludw decodificato da GNU, formula condizionale di `MULUDW_SEMANTICS.md` non modellata; su quale metà del prodotto vada r57 resta non provato sulla CPU.
- **limm middle-endian**: le scansioni word LE contano solo pool pcl; una ricerca separata trova un solo limm del record (0x29E846, assertito), ma riferimenti limm ad altri membri della famiglia descrittori non sono esclusi senza la stessa scansione middle-endian.
- Il bit0xA di ctxA[+2] **non ha writer statici** (censimento agente): la sua origine resta runtime/MCU; i contenuti dei contesti e del template restano runtime o non decodificati.
- Il censimento dei ~20 writer/feeder dell'agente è classificazione candidata su finestre allineate; il verificatore asserisce i siti chiave; il band-entry census è candidato sul listato lineare (solo 0x25E750 riverificato allineato); 0xAD90C/0xAD920 e 0x13A954 non dissezionati qui.
- Contenuto semantico del template 0x3F6698 (528 B) non decodificato; la sua mappatura su parametri OM (zoom/focus/iris) non è provata.

## 8. Prossimi passi

1. Risalire dai wrapper accessor 0x25E7xx–0x25EAxx ai loro chiamanti (sono funzioni con `push_s blink`, quindi hanno `bl` diretti o tabelle) per agganciare task/eventi e il blocco AE/iris 0x1236BC al modulo orchestratore.
2. Decodificare il template 0x3F6698 (528 B) campo per campo e confrontarlo con i parametri halfword ctxB[+0xC4..0xDE] dello switch 0x1EE730 per assegnare i record a zoom/focus/iris.
3. Con r57 risolto, il contratto CPU-lab del piano Av/Tv/M può modellare la primitiva di movimento in modo deterministico.
