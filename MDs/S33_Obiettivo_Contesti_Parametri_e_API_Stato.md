# Contesti dei parametri comandi obiettivo e strato API di stato sopra il dizionario wire

**Correzione23ottobre2026:** [S33_Correzione_Identita_Cluster_25F338_NAND.md](S33_Correzione_Identita_Cluster_25F338_NAND.md). L’attribuzione di25F338/25CBxx–260Dxx al MCU dell’obiettivo è ritirata: percorsi originaliDEVNAND/updater verificati. Questo rapporto conserva byte/formule/provenienza storici; le relative etichette ottiche non sono conclusioni valide.

**Data:** 21 ottobre 2026 (iterazione 1 completata dopo limite turni) · **Tappe:** R0/R1 · **Esito:** PASS statico, nessun hardware toccato · **Stima complessiva: circa 10% invariata**

- Script riproducibile: [Python_Trace_Scripts/s33_verify_lens_status_api.py](../Python_Trace_Scripts/s33_verify_lens_status_api.py)
- Evidenze: [Risultati/Lens_MCU_Interface/Status_API/latest.json](../Risultati/Lens_MCU_Interface/Status_API/latest.json), 12 finestre GNU allineate in `gnu_windows.txt` nella cartella datata.
- Continua [il protocollo wire](S33_Obiettivo_MCU_Formato_Wire_Decodificato.md), [la classificazione wrapper](S33_Vibe_Blocco_Riparazione_Wrapper_Obiettivo.md) e [il diaframma/iride](S33_Diaframma_Iride_Stati_Big_Small_e_Comando_BCIP.md); risponde ai punti 1 (dove vivono i parametri dei comandi) e 2 (consumatore del cluster) del prossimo passo del checkpoint wire.

## 1. Domanda e metodo

Il checkpoint wire lasciava due punti: quale wrapper fra i 33 chiamanti della transazione 0x25F338 trasporta il comando iris, e chi consuma davvero il cluster porta obiettivo 0x25CB00–0x260D00. Metodo consolidato: puntatori a stringhe byte-verificati, finestre GNU allineate a ingressi ricostruiti dall'halfword `push_s blink` (0xC0F1) sui byte raw, letterali riletti dai byte, censimento dei chiamanti; un agente indipendente (`lens-cmd-consumers`) ha risalito i chiamanti di tutte le funzioni con siti dizionario e le sue affermazioni chiave sono state riverificate sui byte in questa sessione.

## 2. Dove vivono i parametri dei comandi wire

I parametri halfword letti dallo switch a 7 casi 0x1EE730 (campi `[r3+0xC4..0xDE]`) e dalla query di stato 0x16F41C (campi `[r0+210+2i]`, cioè 0xD2..0xDE) sono campi dei **contesti RAM riempiti a runtime**:

- `0x25CAEC(dst)` memorizza in `[dst]` il puntatore **0x50F52C** (pool 0x25CEC4): contesto A, campi usati +2 (flag bit0xA), **+5 byte di comando**, +0x10 conteggio.
- `0x25C020(dst)` memorizza **0x50F420** (pool 0x25C3A0): contesto B con la tabella halfword dei parametri a +0xD2..0xDE.
- `0x25BFB8` valida contro la struct 0x50F4D4 (pool 0x25C39C).

**Conseguenza negativa verificata:** nessun inizializzatore statico di 0x50F420/0x50F52C esiste in payload0 — i riferimenti sono tutti interni al cluster. I byte di comando wire runtime (incluso quello dell'iride) **non sono derivabili staticamente**; l'ipotesi che arrivino dall'auto-descrizione del modulo ottico (cfr. GET_OM_CONFIGURATION) resta inferenza.

## 3. Strato API di stato (consumatore identificato)

Sopra il cluster esiste uno strato di interrogazione stato byte-verificato:

- **0x30183C** carica il puntatore a funzione **0x2FFFCC** (pool 0x301888) e lo chiama con `r0=1..5`, restituendo il primo risultato non nullo (aggregazione di stato).
- **0x2FFFCC(indice 0..6)**: jump table a 0x30000C (byte `04 08 0c 10 14 1f 26`) su campi della struct di payload0 **0x3548D8** (offset 0x1F, 0x23, 0x2D, 0x35, 0x4B, 0x9E, 0xAB), letti via 0x32DE00 con l'oggetto RAM 0x5A26BC, poi query sincronizzata 0x16F41C; indice fuori range → id evento 0x2900001 (pool 0x3000E4).
- **0x16F41C(indice, out)**: valida via 0x25BFB8, riempie i contesti, legge il parametro halfword a `0x50F420+0xD2+2*indice` e il risultato dai campi +5/+0x10 del contesto A. 20 chiamanti.

## 4. Semantica delle funzioni del dizionario wire (ingressi corretti)

L'agente ha ricostruito gli ingressi leggendo l'halfword `push_s blink` dai byte raw (il listato lineare attraversa i pool e nasconde ingressi, es. 0x25F6A4; il precedente 0x25F202 era un artefatto di allineamento). Semantica confermata dalle finestre allineate:

| Ingresso | Byte wire | Chiamanti | Ruolo |
|---|---|---|---|
| 0x25F28C | 0x00, 0xFF | 72 | attenzione/reset linea |
| 0x25F338 | 0x00, 0x30 | 35 | transazione principale (posizione) |
| 0x25F428 / 0x25F4EC / 0x25F5C8 | 0x30, 0x00 | 1 ciascuna | richieste senza blocchi / varianti record |
| **0x25F6A4** | **0x50** | 32 | **scrittura record parametro**: gate → 0x50 → sender 0x25CB54 → attesa 1000 → record 16B via 0x25F31C → byte 0x00; con flag bit0xA devia su 0x25F4EC/0x25F5C8 (multi-record) |
| 0x2608A8 | 0xFF, 0x50 | 4 | reset+scrittura senza enter |
| 0x260C6C | 0x70 | 25 | query stato: 0x70 → lettura porta 0x25E08C bit0 → 0x1B00007 su errore |
| 0x25D3AC | 0x70 | 8 | query con transazione (stato bit7) |
| 0x29DDD4 | 0x60, 0xD0 | 29 | **primitiva di movimento**: 0x60 → posizione calcolata (struct arg + r57, muludw) scritta direttamente sulla porta 0x0FF05000 via 0x25E078 → 0xD0 |
| 0x2606B4/0x2607B4/0x2608D0/0x2609DC/0x260AD0/0x260B74 | 0x80, 0x10 | 13/2/1/1/2/17 | upload bulk: 0x80 = inizio scrittura (descrittore + blocchi 512B + record 16B), 0x10 = fase/commit |

Loop centrale byte-verificato: **0x1EEF6C** (write-verify-reinit) chiama in sequenza 0x25F6A4 (0x50), 0x25F28C, 0x25CBF0 (verifica), 0x29DDD4 (reinit 0x60/0xD0), 0x260C6C (retry 0x70) usando **r15=0x50E940** (pool 0x1EF654) e **r14=0x36B254** (pool 0x1EF260): la stessa coppia record+ctrl dominante della transazione. Il writer di record 0x25C1F0 chiama 0x25F6A4 con r0=0x50E940 ed è raggiunto da 0x25C4B4 (`P1IDSTR`), dagli hub OM e da 0x16B698 («TV OUT Test Script»).

## 5. Ancore iris aggiunte (byte-verificate)

- **Blocco AE/iris di Main 0x1236BC–0x125xxx**: referenzia le stringhe di log AE di payload1 (tabelle di puntatori 0x123688–0x12480C), incluse **`Change Iris from MAX: %d  To MIN: %d`** (payload1 0x3860EE/0x38612C, parole 0x124F64/0x124F6C) e i fixture `FE_Para.txt`/`FlashColorModify.txt`.
- **Pannello diagnostico 0x2C5100**: stampa `Iris status: Big/Small` (stringhe payload1 0x406E89/0x406E9A, parole 0x2C51A8/0x2C51AC) in base a un getter `[r14]` con indici 8/9/0xA e draw 0x1564A8.
- **Tabella overlay liveview 0x323EE0–0x323F0C**: 12 formati, ultimo `Iris : %d (0:Big 1:Small)` (0x41DBAC).
- **Dump struct cattura 0x1DC3C0–0x1DC470**: `ucIrisIndex : %d` (parola 0x1DC42C) fra i campi della struct parametri di cattura.

## 6. Sintesi

> **CORREZIONE del 22 ottobre 2026 (iterazione 21):** la freccia
> «AE/iris (0x1236BC) ──▶ hub OM» qui sotto era INFERENZA, non un percorso
> statico: nessun `bl` dal blocco AE/iris 0x123000..0x126000 raggiunge alcun
> entry del cluster wire (censimento negativo byte-assertito). L'iride NON
> viaggia su 0x25F6A4 né su 0x29DDD4: è attuata da GPIO diretti (bit4 Big /
> bit3 Small di 0x0FF04024 + clear bit0/1 di 0x0FEF0388) dalla catena
> 0x149530→0x18B85C→0x235B0C→0x2358F4/0x235950. Vedi
> [attuazione GPIO iris](S33_Iride_Attuazione_GPIO_0FF04024_e_Chiusura_Wrapper.md).
> Il resto del tratto (record parametro, mossa, porta, stato) resta valido per
> zoom/focus/bulk.

```
AE/iris (0x1236BC, "Change Iris MAX→MIN") ──▶ hub OM (0x1EE148/0x1EDFDC/0x25C1F0/0x25C4B4…)
        │ record 0x50E940 + ctrl 0x36B254, parametri halfword dai contesti RAM
        ▼
0x25F6A4 (0x50 = scrivi record parametro) · 0x29DDD4 (0x60/0xD0 = mossa assoluta su porta)
        ▼
porta MCU 0x0FF05000                    stato: 0x260C6C/0x25D3AC (0x70) ← 0x16F41C ← 0x2FFFCC ← 0x30183C
```

L'iride Big/Small viaggia quasi certamente come **record parametro** via 0x25F6A4 o come mossa via 0x29DDD4, ma quale chiamante scriva il record iris resta da ancorare; i descrittori RAM e r57 decidono la destinazione a runtime.

## 7. Limiti

- Tutto statico: nessun MMIO/MCU/fotocamera toccata; nessuna esecuzione; NON_INSTALLARE.
- I contesti RAM 0x50F420/0x50F52C/0x50F514 e i descrittori 0x50E940/0x36B254/0x50E140/0x50E340 sono runtime; contenuto, provenienza e r57 non determinabili staticamente. La provenienza "auto-descrizione del modulo" è inferenza.
- La mappa ingressi/ruoli della tabella al §4 è collegamento statico + lettura corpo su finestre allineate; la BFS dell'agente segue solo `bl/bl.d` (jump table e dispatch calcolati esclusi); funzioni test-fabbrica iris (0x2C4EB4, 0x2876BC) e bounds AE (0x158088) non raggiungono il wire in ≤4 livelli.
- La struct 0x3548D8 e l'oggetto 0x5A26BC sono identificati solo dai pool literal; i loro scrittori non sono tracciati.
- muludw non modellato (caveat noto); helper 0x2E5658 non decodificato; V1.1 analizzato vs macchina V1.0.

## 8. Prossimi passi

1. **Scrittori dei descrittori RAM**: chi pone il flag bit0xA di [0x36B254+2]/[0x50F52C+2] e riempie i byte del descrittore 0x36B254 e i record 0x50E940 — è lì che si decide iris vs zoom/focus prima del wire; includere la provenienza di r57.
2. Agganciare il blocco AE/iris 0x1236BC ai chiamanti della transazione/record writer per chiudere il wrapper iris.
3. Con i parametri contesto noti, il contratto CPU-lab del piano Av/Tv/M può descrivere iris Big/Small come record parametro invece che solo ancore BCIP.
