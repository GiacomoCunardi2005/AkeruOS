# Protocollo wire MCU obiettivo decodificato: byte di comando, gate porta e transazione

**Correzione23ottobre2026:** [S33_Correzione_Identita_Cluster_25F338_NAND.md](S33_Correzione_Identita_Cluster_25F338_NAND.md). L’attribuzione di25F338/25CBxx–260Dxx al MCU dell’obiettivo è ritirata: percorsi originaliDEVNAND/updater verificati. Questo rapporto conserva byte/formule/provenienza storici; le relative etichette ottiche non sono conclusioni valide.

**Data:** 21 ottobre 2026 · **Tappe:** R0/R1 · **Esito:** PASS statico, nessun hardware toccato · **Stima complessiva: circa 10% invariata**

- Script riproducibile: [Python_Trace_Scripts/s33_verify_lens_wire_protocol.py](../Python_Trace_Scripts/s33_verify_lens_wire_protocol.py)
- Evidenze: [Risultati/Lens_MCU_Interface/Wire_Protocol/latest.json](../Risultati/Lens_MCU_Interface/Wire_Protocol/latest.json) (14 finestre GNU allineate, letterali riverificati sui byte, dizionario byte wire).
- Campione: firmware V1.1, SHA-256 `1d34e990…e62a39`; blocchi verificati via `verified_payloads`.
- Continua [il rapporto obiettivo/zoom](S33_Obiettivo_Zoom_MCU_Interface_e_BCIP.md) e [il rapporto iride](S33_Diaframma_Iride_Stati_Big_Small_e_Comando_BCIP.md), di cui chiude i punti aperti 1 e 2.

## 1. Domanda e metodo

Il checkpoint obiettivo/zoom lasciava aperto il **formato byte del protocollo porta** (0x0FF05000): chi manda quali byte, il ruolo del «pack 3 byte» e quali chiamanti usano la transazione. Metodo consolidato: finestre GNU ARC700 allineate a ingressi verificati, letterali riletti dai byte raw del payload, estrazione sistematica delle immediate nei delay slot dei `bl.d`, più due agenti indipendenti per la classificazione dei chiamanti di 0x25F338 e la ricerca dell'ingresso di `MCUCTRL_Task`.

## 2. Correzione strutturale: i «pool» 0x3341xx sono millicode GNU

`0x334124`/`0x334128` (push r13–r16) e `0x33418c`/`0x3341a4` (pop) sono **thunk del runtime GCC**, non funzioni del dialogo obiettivo. Le letture lineari precedenti potevano sembrare «chiamate di conversione descrittore»; in realtà il sender **usa direttamente il descrittore del chiamante**. Correzione analoga per il pack 3 byte `0x25CBBC`: non è un header wire, è il **logger della posizione MCU** (valore composto 0x0FF05108/0x0FF0510C impacchettato in 3 byte con tag 3) scritto nei contesti RAM durante le letture a blocchi.

## 3. I livelli del dialogo (byte verificati)

| Livello | Funzione | Contenuto verificato |
|---|---|---|
| Porta | `0x25E064`/`0x25E078` scrittura, `0x25E08C` lettura | halfword `.di` su **0x0FF05000**; stato bit7 di 0x0FF04024 (`0x25E0B8`) |
| Gate porta | `0x25DEAC` pulisce, `0x25DEE8` setta | **bit4 di 0x0FEF03A8** e **bit6 di 0x0FF04034** attorno a ogni transazione |
| Strobe | `0x25DF24` set bit9, `0x25DF74` set bit8, `0x25DF4C`/`0x25DF9C` clear | registro **0x0FF04020** bit 8/9, maschera -769 |
| Byte singolo | `0x25CB3C(byte)` | strobe + scrittura + strobe; 29 siti con **immediata nel delay slot** |
| Attenzione | `0x25CB0C` | `0xFF` + poll pronto fino a `0xF4240` iterazioni |
| Sender | `0x25CB54(desc)` | wire = `[00]`(se flag bit0xA di [0x50F514+0x1a]) `00 lo/hi(desc[1]+r57) [desc[0]]`(se bit8), scritture grezze via 0x25E078 |
| Transazione | `0x25F338(buf512, buf16, desc)` | gate → `0x00` → sender → `[0x30]`(flag bit0xA di [0x50F52C+2]) → attesa ready `0x25D0D0` → retry con attenzione 0xFF → fase dati |
| Fase dati | `0x25F2B8` (2×256 byte) e `0x25F31C` (16 byte) | `[0x50F52C+0x10]` iterazioni; buffer 512B stride 0x200, record 16B stride 0x10; posizione loggata in 0x50F514+2·idx e 0x50F520+2·idx |
| Attesa ready | `0x25D0D0` | poll fino a 1.000.000; timeout → codice **0x01B00003** (letterale 0x25D128) |
| Risposta | `0x25CBF0` | buffer `[0] ≥ 7`; tipo in `[5]`: 0xF0 richiede `[1]=0x55 [2]=0xAA [6]=0x55 [7]=0xAA`; 255 e 1–4 accettati; 0 rifiutato |

Il **dizionario dei byte di comando letterali** (immediate byte-verificate nei 29 delay slot): `0x00, 0x10, 0x30, 0x50, 0x60, 0x70, 0x80, 0xD0, 0xFF`. La **variante** `0x29DDD4(desc)` è un comando completo già leggibile: invia `0x60`, poi `lo/hi(r57)` diretti, `desc[0]` se flag bit8, poi `0xD0`, attesa e retry con 0xFF (constante 400000 nel pool 0x29DE78).

## 4. Descrittori e chiamanti (agente indipendente)

Firma reale della transazione confermata dall'agente su tutti i siti: `0x25F338(r0 = base blocchi 512B, r1 = base record 16B, r2 = descrittore controllo {byte0, byte1=cmd, halfword2, [0x10]=count})`. Il wrapper `0x25F3F4` inietta il comando da un puntatore in `[r2+1]/[r2+2]` e lo ripristina dopo l'invio.

- **33 chiamanti reali**, non 34: `0x232B4A` è un falso positivo della decodifica lineare (pool letterali 0x0036A3B0/0x0FF20054 saltato dal `b_s` a 0x232B42; byte riverificati).
- Costanti dominanti: **r1 = 0x50E940** (16 siti), **r2 = 0x36B254** descrittore controllo globale (13 siti; campi scritti subito prima della chiamata, es. 0x1EE826 pone `{0,4,0}`), **r0** = base 512B variabile (0x50E140, 0x50F540, 0x50D940, 0x54D8A8, 0x511F00, stack o calcolata con stride 528 = 512+16).
- Il gruppo `0x29E0D0–0x29E414` (zoom, descrittori 0x50E140 + ctrl 0x36B254) è il candidato naturale per il comando iris/BCIP da isolare nel prossimo passo.

## 5bis. Agente MCUCTRL_Task: ingresso trovato, legame col dialogo obiettivo NON stabilito

L'agente indipendente ha risolto l'ingresso del task (byte riverificati in questa sessione):

- Stringa `MCUCTRL_Task` nel **payload1** a VA 0x3764A7 (non nel Main); copia a offset contenitore 0x4264B solo plaintext dell'updater.
- Record template **0x372508** nella tabella task 0x372388 (53 record × 0x20, formato già noto dal FlashChargerTask): id **0x3200001**, entry **0x15A80C**, stack **0x800**, priorità **6**, nome → 0x3764A7.
- Ingresso 0x15A80C (Main): registra le sorgenti evento 0x3200002/0x3200003, contesto RAM **0x391B38** con ring a 8 slot × 0x24 (coda comandi, celle 0x391B70–0x391C90); dispatch per bit evento verso la banda 0x2416F8–0x242300. Creatore 0xC5D88 → 0x140568 → 0x15A978 → 0x158E78 (id dal letterale 0x15AB08 = 0x3200001).

**Risultato negativo rilevante:** la banda handler è satura di letterali 0x0FE704xx/0x0FE706xx e usa stub halfword `.di` su **0x0FED6820/0x0FED6C20/0x0FED7020/0x0FED7420**: il task MCUCTRL governa quei domini, **non** la porta obiettivo 0x0FF05000. La BFS inversa dal cluster 0x25CB00–0x260D00 (181 funzioni, 564 antenati) **non** contiene il sottoalbero MCUCTRL né LensCtrl 0x14661C. Quindi il diagramma architetturale del rapporto obiettivo/zoom precedente («UI Tele/Wide → LensCtrl/MCUCTRL_Task → cluster 0x25CB00») **non è sostenuto dai byte**: il consumatore effettivo del dialogo obiettivo resta da identificare, e il nome «MCUCTRL» va attribuito con cautela (può riferirsi a un MCU diverso dall'unità ottica).



## 5. Nota metodologica pcl

Le annotazioni `;0x…` di objdump per **`ld_s [pcl,u6]` sono corrette (non scalate)**; la formula `(PC & ~3) + off*4` vale invece per i **`ld.as [pcl,s12]`** (come già per l'agente: i casi ambigui risolvono tutti a 0x50E940/0x36B244). Statistica su 48.412 siti `ld_s pcl` nel Main: lettura non scalata nettamente più plausibile. Tutti i letterali qui affermati sono riverificati dai byte raw del payload.

## 6. Limiti

- Tutto statico: nessun MMIO/MCU/fotocamera toccati; nessuna esecuzione; NON_INSTALLARE.
- **r57** è un registro-core globale vivo (2.261 usi; init a 0xB2EBA ecc.): il suo valore runtime e il contenuto dei descrittori RAM (0x36B254, 0x50E940, 0x50E140) non sono determinabili staticamente.
- Semantica MCU dei byte del dizionario = inferenza (i byte sono verificati, il loro significato lato MCU no); il vocabolario BCIP 0x92xx resta documentazione, non protocollo wire.
- Aritmetica `muludw` dei tempi (PPS) non modellata (caveat muludw noto del codebase); helper `0x2E5658` pre-invio non decodificato; argomenti 1000/0 passati a `0x25D0D0` non usati dal corpo decodificato.
- Versioni separate: V1.1 analizzato, macchina V1.0.

## 7. Prossimi passi

1. Isolare quale dei 33 chiamanti è il wrapper iris (candidati: gruppo 0x50E140/0x50E940 con ctrl 0x36B254) e leggere il campo `[ctrl+1]` (cmd) scritto prima di ogni chiamata, confrontandolo col dizionario `{00,10,30,50,60,70,80,D0,FF}`.
2. Identificare il **consumatore** del cluster 0x25CB00–0x260D00 (la BFS inversa esclude MCUCTRL_Task e LensCtrl 0x14661C): risalire dai 33 chiamanti verso i task/eventi che li invocano, per collegare i tasti Tele/Wide alle transazioni senza attribuirle al task sbagliato.
3. Con il wire noto, il contratto CPU-lab del piano Av/Tv/M può usare direttamente i byte di comando invece delle sole ancore BCIP.
