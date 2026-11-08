# Correzione "band entry" e famiglia accessor MMIO del banco ausiliario 0x0FFCA0xx

**Data:** 21 ottobre 2026 (iterazione 4 del ciclo Vibe persistente) · **Tappe:** R0/R1 · **Esito:** PASS statico, correzione di una conclusione precedente, nessun hardware toccato · **Stima complessiva: circa 10% invariata**

- Script riproducibile: [Python_Trace_Scripts/s33_verify_lens_aux_mmio_accessors.py](../Python_Trace_Scripts/s33_verify_lens_aux_mmio_accessors.py)
- Evidenze: [Risultati/Lens_MCU_Interface/Aux_MMIO_Accessors/latest.json](../Risultati/Lens_MCU_Interface/Aux_MMIO_Accessors/latest.json) (12 finestre getter + 5 finestre contesti chiamanti allineate ai target dei `b_s`)
- Corregge il punto 4 di [Scrittori descrittori RAM, template statico e r57](S33_Obiettivo_Scrittori_Descrittori_RAM.md); il verificatore dell'iterazione 3 è stato aggiornato nell'interpretazione e rieseguito: PASS ([Descriptor_Writers/latest.json](../Risultati/Lens_MCU_Interface/Descriptor_Writers/latest.json)).
- Agente `lens-aux-mmio-audit` (revisione indipendente, configurazione ereditata): confronto in §7.

## 1. Domanda e metodo

Il prossimo passo del checkpoint iterazione 3: risalire dai wrapper accessor 0x25E7xx–0x25EAxx ai loro chiamanti per collegare task/eventi e il blocco AE/iris 0x1236BC al modulo orchestratore. Metodo: finestre GNU allineate **ai target dei `b_s`** (non più all'ingresso delle funzioni), decodifica halfword/limm middle-endian sui byte raw, censimento chiamanti su tutti i 16 payload con classificazione bl / word LE / limm middle-endian.

## 2. Correzione: i "bln verso band entry" erano artefatti di decodifica

La finestra GNU allineata **all'ingresso** di ogni accessor segue la catena di istruzioni a 2 byte attraversando il **pool word della `ld_s`** (che contiene l'indirizzo del registro MMIO): i byte del pool e le prime istruzioni reali vengono decodificati come `st_s`/`bl`/`bln` che non vengono mai eseguiti. Il flusso reale, allineato al target del `b_s` (g+0xC, byte-verificato su tutti i 12):

```
g+0x00: push_s blink
g+0x02: ld_s   r0,[pcl,0x8]   ; pool=(PC&~3)+u7*4 → indirizzo registro
g+0x04: b_s    +0xC           ; salta [pad 2B][pool word 4B]
g+0x0C: ldh.di r0,[r0]        ; lettura halfword bypass cache
g+0x10: and    r0,r0,0xMASK   ; opcode 32 bit + limm 4 byte (middle-endian)
g+0x18: pop_s  blink
g+0x1A: j_s.d  [blink]        ; delay slot:
g+0x1C: asr_s  r0,r0,SHIFT
g+0x1E: nop_s
```

I 12 siti `bln` del listato lineare (0x25E75E, 0x25E7B2, 0x25E7D2, 0x25E85A, 0x25E8AE, 0x25E8CE, 0x25E956, 0x25E9AA, 0x25E9CA, 0x25EA52, 0x25EAA6, 0x25EAC6) cadono **tutti esattamente a g+0xE, dentro la `ldh.di` reale** (g+0xC..g+0x10): i byte dell'artefatto sono la halfword alta della `ldh.di` (0x0900) seguita dalla halfword bassa della `and` (0x2004). Conseguenza byte-verificata: **nessuna funzione del firmware chiama le "band entry" 0x29E85C..0x29EBC4**; il censimento `bln` su tutti i 16 payload restituisce esattamente i 12 artefatti, tutti in payload0. Il collegamento "accessor → band entry → orchestratore" dell'iterazione 3 è **caduto**; gli orchestratori 0x29E682/0x29E8F2/0x29E9C6 restano **senza chiamanti statici noti** (il loro negativo di iterazione 3 resta valido, la rotta ipotizzata no).

## 3. I 12 accessor sono getter MMIO del banco ausiliario 0x0FFCA0xx

| Getter | Registro | Maschera | Shift |
|---|---|---|---|
| 0x25E750 | 0x0FFCA084 | 0x6000 | 13 |
| 0x25E7A4 | 0x0FFCA084 | 0x1FC0 | 6 |
| 0x25E7C4 | 0x0FFCA08C | 0xFF00 | 8 |
| 0x25E84C | 0x0FFCA094 | 0x6000 | 13 |
| 0x25E8A0 | 0x0FFCA094 | 0x1FC0 | 6 |
| 0x25E8C0 | 0x0FFCA09C | 0xFF00 | 8 |
| 0x25E948 | 0x0FFCA0A4 | 0x6000 | 13 |
| 0x25E99C | 0x0FFCA0A4 | 0x1FC0 | 6 |
| 0x25E9BC | 0x0FFCA0AC | 0xFF00 | 8 |
| 0x25EA44 | 0x0FFCA0B4 | 0x6000 | 13 |
| 0x25EA98 | 0x0FFCA0B4 | 0x1FC0 | 6 |
| 0x25EAB8 | 0x0FFCA0BC | 0xFF00 | 8 |

Struttura: 8 registri consecutivi a passo 8 (0x0FFCA084..0x0FFCA0BC); i registri a +4 mod 8 espongono due campi (bit 13–14 e bit 6–12), quelli a +0xC mod 8 un campo a 8 bit (bit 8–15). Il censimento LE del banco in payload0 (word-valore → siti pool, tutti byte-verificati) copre **47 registri 0x0FFCA004..0x0FFCA118** gestiti dalla famiglia 0x25E0xx–0x25ECxx, incluso il già noto ausiliario **0x0FFCA008** (8 siti pool). Le funzioni sorelle (es. 0x25E7E4, 0x25E818, 0x25E8E0) copiano campi del banco in strutture tramite `ldh.di`+shift+`stb_s`; non dissezionate qui.

## 4. Chiamanti: solo il getter 0x25E7A4 è usato, nei percorsi di errore

Censimento su 16 payload (bl/bl.d/bl_s, word LE puntatore, limm middle-endian):

- **Solo 0x25E7A4** (campo 7 bit di 0x0FFCA084) ha chiamanti: esattamente 5 siti, tutti in payload0: 0x168E5E (funzione 0x168DB0), 0x1694E2 (0x169350), 0x25F788 (0x25F724), 0x25F90E (0x25F8CC), 0x25FA32 (0x25F998).
- Gli altri 11 getter: zero chiamanti, zero word-puntatore. L'unica sequenza middle-endian di un indirizzo getter fuori da payload0 (0x25E8A0 in payload6 a 0x9b1619) è a indirizzo **dispari**: coincidenza in dati, non un limm.
- **Nessun chiamante nel blocco AE/iris 0x1236BC..0x126000**: l'aggancio AE resta aperto.

Tutti i 5 contesti sono percorsi di errore dei comandi obiettivo, con **nuovi codici errore** 0x1B00204, 0x1B00205 (siti 0x168E5E, 0x25F788, 0x25FA32), 0x1B00206 (0x25F90E e, per la verifica dell'agente, la guardia `cmp_s r13,0x1b00206` a 0x16949A del sito 0x1694E2), 0x1B00207 (0x25FA32). Uso del campo 7 bit (byte-verificato per sito):

- **0x168E5E**: risultato confrontato con 0x7F (`cmp_s r0,0x7f` a 0x168E64; l'`extb_s r0,r0` a 0x168E62 è delay slot su r0 vecchio) e usato su un contatore a 0x168FC8.
- **0x25FA32**: l'`extb_s r15,r0` del delay slot opera sul r0 **vecchio** (codice errore) e viene confrontato con 0x7F; il risultato del getter passa a 0x2600B4.
- **0x25F788**: risultato scartato; ritorno con errore 0x1B00212 (pool 0x25FB24).
- **0x25F90E**: segue `st_s r14,[0x36B284]` (pool 0x25FB28).
- **0x1694E2**: risultato non consumato localmente (r0 azzerato dopo la chiamata).

Il campo 7 bit è quindi il **codice di dettaglio MCU** letto dal banco ausiliario dopo un errore del comando obiettivo (0x7F = valore speciale testato).

## 5. Estensione della famiglia descrittori e nuove celle

I pool dei chiamanti 0x25FB18..0x25FB4C (byte-verificati) espongono: **0x36B270, 0x36B278, 0x36B280, 0x36B282, 0x36B284, 0x36B288, 0x36B290** — ulteriori membri della famiglia genitore **0x36B244** (il ctrl 0x36B254 = genitore+0x10, iterazione 3); la cella **0x50F540** (= ctxA 0x50F52C + 0x14); la nuova cella **0x50FD80**; e gli ID errore 0x1B00212, 0x1B0000F, 0x1B0000A, 0x1B00010, 0x1B00008. Tutte le celle sono RAM oltre la fine di payload0 (≥ 0x35BC00), senza contenuto statico.

## 6. Sintesi

```
funzioni di errore comandi obiettivo (0x168DB0, 0x169350, 0x25F724, 0x25F8CC, 0x25F998)
   └─ su errore 0x1B00204/05/06/07 → getter 0x25E7A4 = (ldh.di[0x0FFCA084] & 0x1FC0) >> 6
        ├─ dettaglio MCU (0x7F testato) → contatori / 0x2600B4 / scarto
        └─ stato famiglia 0x36B244 (0x36B270..0x36B290), 0x50F540, 0x50FD80
12 accessor 0x25E750..0x25EAB8 = getter bitfield del banco ausiliario 0x0FFCA084..0x0FFCA0BC
band entry 0x29E85C..0x29EBC4: NESSUN chiamante reale (i 12 bln erano artefatti a g+0xE)
orchestratori 0x29E682/0x29E8F2/0x29E9C6: chiamante statico ANCORA SCONOSCIUTO
```

## 7. Revisione indipendente (agente `lens-aux-mmio-audit`)

Agente figlio con configurazione ereditata, incaricato di verificare o contraddire i cinque punti chiave con finestre GNU allineate ai target dei `b_s` e byte raw (script in /tmp/s33_review, step1–step6, sola lettura). **Esito: tesi confermata su tutti e cinque i punti, nessuna controprova.** Contributi dell'agente integrati nel rapporto:

- il censimento branch-family a due allineamenti conferma che verso le band entry esistono solo i 12 artefatti `bln` più **due salti interni alla stessa regione** (0x29E954 `beq_s→0x29E958`, 0x29E9A4 `bne_s→0x29E9AC`): le band entry sono etichette interne del modulo orchestratore, raggiunte solo da rami intra-modulo, mai dai getter; zero word LE e zero limm middle-endian verso le band entry in tutti i 16 payload;
- il sito 0x1694E2 è presidiato da `cmp_s r13,0x1b00206` a 0x16949A (beq): il codice 0x1B00206 presidia due dei cinque siti;
- conferma la lettura di 0x25FA32: il risultato del getter (r0) è **passato come argomento** alla chiamata 0x2600B4, non memorizzato;
- la sequenza middle-endian in payload6 (`25 00 a0 e8` a 0x9B1619) cade a cavallo del `cmp r21,0` a 0x9B1618 e del `bhi` a 0x9B161C: coincidenza in byte di codice a offset dispari.

Le affermazioni chiave restano coperte dalle asserzioni del verificatore eseguito in questa sessione.

## 8. Limiti

- Statico, nessun hardware/esecuzione, NON_INSTALLARE; V1.1 analizzata vs V1.0.
- Gli 11 getter senza chiamanti potrebbero essere raggiunti da salti calcolati/tabelle invisibili al censimento, o codice morto: non si afferma nulla oltre il censimento.
- La semantica dei campi del banco ausiliario (cosa significano i valori 2/7/8 bit per la MCU) è inferenza dai siti d'uso; solo istruzioni, pool e siti di chiamata sono byte-verificati.
- Le celle 0x36B270..0x36B290/0x50F540/0x50FD80 sono localizzate e riferite ma il layout/ownership non è decodificato.
- **La domanda "chi raggiunge gli orchestratori" resta aperta**: la rotta band entry è chiusa dalla correzione, nessuna nuova rotta è reclamata.
- Effetti cache runtime di `ldh.di` non modellati.

## 9. Prossimi passi

1. Decodificare il layout della famiglia genitore 0x36B244 (0x36B244..0x36B290 + bit-table 0x50F190) e le celle 0x50F540/0x50FD80 a partire dai writer/lettori censiti, per capire dove viene deciso iris/zoom/focus prima del wire.
2. Per gli orchestratori senza chiamante: cercare salti calcolati/tabelle di funzione verso 0x29E682/0x29E8F2/0x29E9C6 (pattern `jl [r]` con caricamento da pool) prima di dichiarare il vicolo cieco.
3. In alternativa, proseguire la decodifica del template 0x3F6698 (528 B) campo per campo, rimasta aperta dall'iterazione 3.
