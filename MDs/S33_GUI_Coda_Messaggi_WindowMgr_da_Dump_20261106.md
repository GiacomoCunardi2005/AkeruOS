# Coda dei messaggi di WindowMgr e flusso evento → task → finestra (dump hardware)

6 novembre 2026. Seconda attività del [piano GUI](S33_GUI_Stato_Reale_da_Dump_Hardware_20261106.md): ricostruire il percorso reale di un evento fino alla finestra, dal `MEMDUMP.BIN` (SHA-256 `c91888b2…6107`). Metodo: lettura della RAM e disassemblaggio GNU ARC700 delle routine dal dump; nessun firmware creato, dump intatto, nessun accesso alla fotocamera. Certezza: **A** osservato in RAM e coerente col codice, **B** ruolo dedotto dal codice, **C** ipotesi. Istantanea non atomica di `[0, 0x0104074C)`.

## Invio di un messaggio (`0x17BC7C`)

| Elemento | Valore | Evidenza | Certezza |
|---|---|---|---|
| Funzione di invio `post(arg, msg_id, param)` | `0x17BC7C` | disassemblata: salva `arg`, `msg` (halfword), `param`, entra in sezione critica `0x1786E8`, aggiorna l'indice, esce `0x179354` | A |
| Anello circolare | 64 voci da 12 byte `{arg: u32, msg: u16, param: u32@+8}` | maschera a 6 bit nel codice | A |
| Base delle voci | `0x47A848` (da `[0x17C000]`) | RAM | A |
| Controllo coda | `0x367BBC`: halfword +0 = **testa 19**, halfword +2 = **coda 21** | RAM | A |
| Segnale al task | oggetto/handle `0x300004` (da `[0x17BFFC]`), svegliato dopo l'inserimento solo se la coda era in uso | codice | B |
| Consumo | `WindowMgr` → `0x17BD4C` → `0x169E1C` | disassemblato | A |

Al momento del dump i messaggi pendenti sono **2** (voci 19 e 20): il consumatore ne aveva elaborati 19. La coda non è mai arrivata a 64 voci: le voci 21–63 sono vuote, quindi in RAM c'è lo **storico completo dei 21 messaggi inviati dal boot** (ipotesi: nessun azzeramento successivo, **B**).

## Storico dei 21 messaggi (arg, id, param)

| Voce | arg | id | param | Note |
|---:|---|---|---|---|
| 0 | `0` | `0x440F` | `0x55` | gestito direttamente da `0x1453E4` |
| 1–3 | `0` | `0x7C00`, `0x7C09`, `0x7C02` | `0` | avvio (ipotesi **C**) |
| 4, 16 | `0x783AE8` | `0x0000` | `0` | finestra attiva |
| 5–9, 14, 18 | `0x783AE8` | `0x440E` | `8` | tick di timer UI verso la finestra attiva (invio visto in `UITimer`) |
| 10, 20 | `0x783AE8` | `0x440E` | `1` | idem, altro parametro |
| 11 | `0` | `0x4112` | `0` | |
| 12, 13 | `0` | `0x4104` | `0` | gestore nella tabella della finestra attiva (`0x65BA40`) |
| 15 | `0` | `0x4001` | `2` | gestore `0x65C928` |
| 17 | `0` | `0x4101` | `0` | |
| **19 (pendente)** | `0x783AE8` | `0x4409` | `0` | gestore `0x65A4A4` |
| **20 (pendente)** | `0x783AE8` | `0x440E` | `1` | gestore `0x659FA0` |

Il `0x440E` è il messaggio che `UITimer` invia quando scade un timer (chiamata a `0x17BE80`/`0x17BC7C` con `0x440E`, disassemblata). Certezza **A** per l'invio, **B** per il significato dei parametri (8 e 1 sono gli id/slot timer della finestra).

## Percorso completo, con tutti i punti osservati

1. **Sorgente:** un task o una callback chiama `post(arg, msg, param)` (`0x17BC7C`); per i timer lo fa `UITimer`.
2. **Coda:** voce in `0x47A848 + 12·indice`, indice 6 bit.
3. **Risveglio:** `WindowMgr` (sem `'mswl'` `0x374120`) riceve (`0x17BD4C`) la voce nel buffer da 12 byte.
4. **Dispatcher** `0x169E1C(arg, msg, param)`: hook pre `[0x367800]`; messaggi `0x440F` → `0x1453E4`; con `arg = 0` e id in `0x4400–0x47FF` la finestra diventa quella attiva (`0x783AE8`).
5. **Procedura di finestra** `0x169D78`: hook intermedio `[0x16A12C]` → tabella `0x367808` (funzione `0x159264`); casi speciali `0x5401–0x5403`; id `0x4401–0x4409` tramite tabella a salti; gli altri cercati nella tabella messaggi→gestore dell'oggetto finestra.
6. **Gestore** (per esempio `0x659FA0` per `0x440E`): modifica lo stato o disegna.
7. **Hook post** `[0x367804]` = `0x159230`.

## UIAux

Il ciclo di `UIAux` chiama la funzione in `[0x367408]` = `0x12F9B8`: sono tre istruzioni (`r0 = 1`, `r1 = 0`, salto a `0x1334EC`), un trampolino che chiama `0x1334EC(1, 0)`. Cosa faccia `0x1334EC` non è stato letto. Un'altra funzione adiacente (`0x12F9C0`) legge flag a `[0x12FA30]+130/157/158`: non è provato che sia legata a questa callback. **B**.

## Cosa serve ad AkeruOS

- Per **inviare un evento** alla propria schermata AkeruOS può chiamare `post(finestra, id, param)` (`0x17BC7C`): è la via usata da tutti, con coda a 64 voci.
- Per **ricevere** deve avere un oggetto finestra con tabella messaggi→gestore oppure agganciarsi all'hook post/pre. Entrambe le modalità sono candidate, **non** provate.
- Gli id `0x4400–0x47FF` sono instradati alla **finestra attiva** quando `arg = 0`: un cambio di finestra attiva (cella `[0x14579C]`→`0x366EA4`) sposta i messaggi.

## Limiti

- Un istante; nessuna temporizzazione. Non si può dire quanto sia durato il periodo di 21 messaggi.
- Il significato di molti id (`0x7C00`, `0x4112`, `0x4101`, …) non è attribuito.
- Il corpo di `0x1334EC` e i gestori `0x65xxxx` non sono stati letti qui.
- `0x169D78` è stata letta solo nella prima parte (fino al salto a tabella).

**Prossimo:** leggere `0x1334EC`, la tabella a salti di `0x169D78`, e il gestore `0x659FA0` del `0x440E`; poi la catena grafica (fase 3). Nessuna modifica al firmware della S33.

## Aggiornamento (stessa data): tabella a salti e gestore del timer

- **Procedura di finestra `0x169D78`:** per gli id `0x4401–0x4409` usa una tabella di 9 byte a `0x169DDC` (valori `05 07 19 19 09 0B 0F 11 0D`); ogni byte è un offset in unità da 2 byte dalla base `0x169DDC`: i rami sono `0x169DE6` (0x4401), `0x169DEA` (0x4402), `0x169E0E` (0x4403 e 0x4404: ramo comune/non gestito), `0x169DEE` (0x4405), `0x169DF2` (0x4406), `0x169DFA` (0x4407), `0x169DFE` (0x4408), `0x169DF6` (0x4409). Certezza **A** per la tabella (letta nel dump), **B** per i nomi dei rami (non disassemblati uno per uno).
- **Gestore del timer `0x659FA0` (messaggio `0x440E`):** fa `switch(param − 1)` su 22 casi (`param` da 1 a 22, tabella di halfword subito dopo il prologo, salto di default a `0x65A48E`). Quindi il parametro di `0x440E` è l'**id di uno dei 22 timer** della finestra di ripresa, e nello storico dei 21 messaggi compaiono i timer 8 e 1. Certezza **A** per lo switch, **B** per l'interpretazione "id timer" (coerente con l'invio da `UITimer`).
- **`0x1334EC(1, 0)`** (callback `UIAux`): legge un blocco di stato a `0x366A44`; il campo `+0x1C` vale `255` nel dump, usato in confronti con 6, 7 e 9 (stati di modo). Il significato dello stato non è attribuito. **C**.

Prossimo: catena grafica (fase 3): puntatori di destinazione del disegno nelle funzioni `0x186D08 → 0x186C40 → 0x186B14`.

Catena grafica del testo: [dettaglio](S33_GUI_Catena_Grafica_Testo_da_Dump_20261106.md).

**Correzione (stessa data):** vale quanto sopra: con finestra 0 sono instradati alla finestra attiva gli id fuori da `0x4400–0x47FF`. Vedi [integrazione manager](S33_GUI_Integrazione_Manager_Nikon_e_Validazione_muludw_20261106.md).
