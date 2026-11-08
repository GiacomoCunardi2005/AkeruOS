# Chiamanti del modulo orchestratore comandi obiettivo: correzione off-by-two e rotta esterna payload4 → 0x301E1C → 0x29E8F0

**Correzione23ottobre2026:** [S33_Correzione_Identita_Cluster_25F338_NAND.md](S33_Correzione_Identita_Cluster_25F338_NAND.md). L’attribuzione di25F338/25CBxx–260Dxx al MCU dell’obiettivo è ritirata: percorsi originaliDEVNAND/updater verificati. Questo rapporto conserva byte/formule/provenienza storici; le relative etichette ottiche non sono conclusioni valide.

**Data:** 22 ottobre 2026 (iterazione 7 del ciclo Vibe persistente; completa e verifica il censimento lasciato incompleto dall'iterazione 6 interrotta) · **Tappe:** R0/R1 · **Esito:** PASS statico, correzione di una conclusione precedente, nessun hardware toccato · **Stima complessiva: circa 10% invariata**

- Script riproducibile: [Python_Trace_Scripts/s33_verify_lens_module_callers.py](../Python_Trace_Scripts/s33_verify_lens_module_callers.py)
- Evidenze: [Risultati/Lens_MCU_Interface/Module_Callers/latest.json](../Risultati/Lens_MCU_Interface/Module_Callers/latest.json) (12 finestre GNU allineate, censimenti bl/limm/word su 16 payload, snapshot script e hash sorgenti)
- Corregge il punto (b) dell'iterazione 4 ([Correzione band entry e getter MMIO](S33_Obiettivo_Accessor_MMIO_Correzione_Band_Entry.md)): il negativo «orchestratori senza chiamanti statici» era un artefatto di censimento, non un isolamento reale. La correzione accessor dell'iterazione 4 (bln artefatti) resta valida.
- Agente `module-callers-audit` (revisione indipendente, configurazione ereditata): confronto in §7.

## 1. Domanda e metodo

Punto aperto dell'iterazione 4: prima di dichiarare il vicolo cieco degli orchestratori 0x29E68x, cercare riferimenti calcolati (limm middle-endian, word LE) e chiamate dirette verso il modulo e il confine esterno del sottosistema comandi obiettivo. Metodo: ingressi byte-verificati con finestre GNU allineate, censimento `bl/bl_s/bl.d/bln` su tutti i 16 payload, censimento byte middle-endian `pack('<HH',V>>16,V&0xFFFF)` e word LE su tutti i 16 payload, scansione degli immediati operand-position dei 16 listati lineari (952.222 righe classificate nel solo payload0).

## 2. Correzione: gli ingressi reali sono 0x29E680/0x29E8F0/0x29E9C4, non +2

Ogni orchestratore inizia con `sub_s sp,sp,0x18` seguito da `push_s blink` e da una chiamata a thunk millicode (0x33412C/0x334130/0x334104):

```
0x29E680: sub_s sp,sp,0x18 ; push_s blink ; bl 0x33412C ...
0x29E8F0: sub_s sp,sp,0x18 ; push_s blink ; bl 0x334130 ...
0x29E9C4: sub_s sp,sp,0x18 ; push_s blink ; bl 0x334104 ; sub sp,sp,316 ...
```

Gli indirizzi usati dai censimenti negativi delle iterazioni 3–4 (0x29E682/0x29E8F2/0x29E9C6) sono il `push_s blink` **dentro il prologo**: un censimento `bl` verso di essi non poteva trovare i chiamanti reali, perché nessun compilatore genera call verso +2. Il negativo «nessun chiamante statico» era quindi un artefatto off-by-two. Conferme contestuali: 0x29E738 è un **multi-ingresso interno** di 0x29E680 (dopo i memcpy del template 528/244 byte: `st_s r14,[sp,8]`, fill ctxA 0x25CAEC, chiamata 0x25CFE4); 0x29E9C4 alloca un frame di 316 byte e specchia gli 8 argomenti con `st.as`.

## 3. Censimento delle chiamate dirette (16 payload, range [0x29E600,0x29EA00))

Esattamente 10 siti in payload0 e 1 in payload9; tutti gli altri payload: zero.

| Sito | Mnemonico | Target | Classificazione |
|---|---|---|---|
| 0x25E75E/0x25E7B2/0x25E7D2/0x25E85A/0x25E8AE/0x25E8CE | bln | band entry 0x29E85C..0x29E9CC | artefatti di allineamento noti (iterazione 4) |
| 0x29E99E | bl_s | 0x29E680 | intra-modulo (nel corpo di 0x29E8F0) |
| 0x29EC44 | bl_s | 0x29E680 | intra-modulo (regione band entry, 6 argomenti ricaricati dal frame) |
| 0x29F082 | bl_s | 0x29E9C4 | intra-modulo (wrapper 0x29EFC4) |
| **0x301E92** | **bl** | **0x29E8F0** | **primo chiamante esterno statico** |
| 0xC9E1E6 (payload9) | bl | 0x29E738 | coincidenza in dati risorsa (decodifica movbi.f/.word priva di senso) |

## 4. La rotta esterna: payload4 (tuning) → 0x301E1C (API stato) → 0x29E8F0

**0x301E1C** (payload0, strato API stato, già noto come strato dei validatori) è un ingresso secondario di una funzione multi-ingresso che condivide l'epilogo a 0x301E0E (`mov sp,fp; ld.ab fp,[sp,4]; b 0x334194`). Corpo byte-verificato:

1. azzera un **record di 22 byte** sul frame con `memcpy` dall'area zero **0x354DE4**, subito dopo le stringhe `BootNANDBase.bin`/`BootNANDBase.dmp` (pool 0x301EBC);
2. chiama **0x301EC0** (probabile riempimento del record: i 6 word poi passati all'orchestratore sono letti da [fp-0x18..fp-0x04], dentro il record);
3. valida con **0x3013A0, 0x30183C, (0x30026C se arg0==1 | 0x30144C altrimenti), 0x300D94** (uscita anticipata a 0x301EB2 su errore);
4. carica 6 word dal record in r0–r5 e pone **r6 = arg1 originale**, poi **bl 0x29E8F0** (7 argomenti r0–r6);
5. chiude con **0x16F200** e **0x30188C**.

L'orchestratore 0x29E8F0 copia il record di 22 byte (`memcpy` 0x128C20), fa il fill ctxA 0x25CAEC, spedisce sul bit0xA di ctxA[+2] e raggiunge gli scrittori ctrl/record (0x25C1F0/0x25C37C) e il wire — il collegamento mancante con le iterazioni 1–5.

**Chiamanti di 0x301E1C: esattamente 3, tutti in payload4 (blocco CCD_Tune_DVT del V1.1):**

- **0x7D470A** e **0x7D4734** nel blocco tuning 0x7D46F6, con argomenti scambiati: `(1, r16)` e `(r16, 1)`; il blocco chiama anche il servizio tuning 0xCDA24 e memorizza un byte con `stb r16,[r1,8]`;
- **0x80FAAE** dentro il **dispatcher 0x80F9C8**, che commuta su r14 ∈ [0x19,0x36) con jump table a byte-offset **0x80FA0C** (`ldb.x/add1_s/j_s [r12]`; `add1_s` scala il byte per 2, quindi il target del case è 0x80FA0C + 2×byte). **L'opcode 0x33** (byte 0x4F) seleziona il case **0x80FAAA** che chiama **0x301E1C(0,1)**; il case default 0x80FAC8 carica l'id errore condiviso **0xFFFF0009** dal pool 0x80FAF8 e confluisce nella coda comune (log 0x128844, 0x1290EC, 0x128F28).

Nessun altro payload chiama 0x301E1C.

## 5. Chiamanti intra-modulo e uscita calcolata del modulo

- wrapper **0x29EFC4** → `bl_s 0x29E9C4` (0x29F082): memcpy del record 22 byte, dispatch bit0xA di ctxA[+2], id errore 0x1B00001 via 0x1593AC/0x1594A4, `mov r7,r16` (ottavo argomento);
- la regione band entry esce con chiamata calcolata: carica **0x1ED11C** dal pool 0x29EB94 e salta con `jl_s.d [r15]` (0x29EAD0): 0x1ED11C è un helper condiviso del cluster usato dal modulo stesso (non un chiamante).

## 6. Censimenti limm middle-endian e word LE

- **Range modulo [0x29E600,0x29F200)**: solo 2 coincidenze byte, entrambe in payload dati: payload9 0xD6ADD6 → 0x29EF17 (**dispari**, risorse) e payload11 0x1099F60 → 0x29E680 (dentro la regione della stringa `1080p`). Zero coincidenze nei payload di codice.
- **Verso 0x301E1C**: zero pattern middle-endian su tutti i 16 payload.
- **Range cluster [0x1EC000,0x1F0000)**: le coincidenze byte esistono anche nei payload di codice (39 in payload0, 89 in payload6, 71 in payload9, 18 in payload12, 7 in payload4, 4 in payload2, 2 in payload10, 1 in payload1, 3 in payload11), ma **nessuna istruzione dei 16 listati lineari ha un immediato operand-position nel range modulo, cluster o chiamante** (scansione completa): nessuna di esse è un limm reale di un indirizzo del sottosistema.
- **Word LE**: nessuna word allineata a halfword in alcun payload uguaglia 0x29E680, 0x29E8F0, 0x29E9C4, 0x301E1C o 0x301EC0 (nessuna voce di tabella funzioni); le sole word LE nel range modulo sono 4 valori dispari nei dati di payload9 (0x29E81D×2, 0x29E91D, 0x29E751), non target di branch.

Conclusione: il sottosistema comandi obiettivo **non è staticamente isolato**; esiste la rotta statica completa payload4(tuning) → 0x301E1C(validazione API stato) → 0x29E8F0(orchestratore) → scrittori ctrl → wire.

## 7. Revisione indipendente (agente)

L'agente `module-callers-audit` era in esecuzione quando la sessione dell'iterazione 7 è stata interrotta; nessun output è stato integrato né recuperabile. Il verificatore è stato rieseguito indipendentemente nell'iterazione 8 (PASS, cartella 20261021T224729Z); una revisione indipendente aggiornata è demandata all'iterazione 8 insieme alla decodifica di 0x301EC0 (vedere [S33_Vibe_Offline_Checkpoint.md](S33_Vibe_Offline_Checkpoint.md)).

## 8. Limiti

- Statico: nessun MMIO, nessuna MCU obiettivo o fotocamera toccata, nessun firmware eseguito; NON_INSTALLARE.
- Il censimento copre `bl/bl_s/bl.d/bln` dei listati lineari GNU più finestre allineate per ogni sito accettato/rifiutato; le chiamate con target calcolato a runtime non da pool/limm non possono essere escluse (i siti `jl [reg]` con registro calcolato non sono censiti).
- Payload4 è il blocco tuning **CCD_Tune_DVT** del V1.1: **se il dispatcher 0x80F9C8 e il blocco 0x7D46F6 girano nel percorso fotografico normale resta aperto** (e con esso la frequenza reale della rotta).
- La semantica dei 7 argomenti di 0x29E8F0 e del record di 22 byte non è decodificata: il mapping a comandi zoom/focus/iris resta aperto.
- Il blocco AE/iris 0x1236BC resta non agganciato a questa rotta: nessun chiamante di 0x301E1C lì.
- V1.1 analizzato vs macchina V1.0: nessun trasferimento automatico di indirizzi.

## 9. Prossimo passo (non ripetitivo)

Salire dalla rotta ai **chiamanti del dispatcher 0x80F9C8 e del blocco tuning 0x7D46F6 in payload4** (bl/jl, pool, limm) per stabilire quale servizio/task del tuning invoca l'orchestratore e con quale significato dell'argomento r16; in parallelo decodificare il riempimento del record 22 byte in **0x301EC0** (i 6 word letti da [fp-0x18..fp-0x04]) per collegare gli argomenti ai campi comandi 0xC4..0xDE dei contesti 0x50F52C/0x50F420 già noti.
