# Come il software parla con lo zoom e l'obiettivo: porta MCU 0x0FF05000, handshake e tabella comandi BCIP

**Correzione23ottobre2026:** [S33_Correzione_Identita_Cluster_25F338_NAND.md](S33_Correzione_Identita_Cluster_25F338_NAND.md). L’attribuzione di25F338/25CBxx–260Dxx al MCU dell’obiettivo è ritirata: percorsi originaliDEVNAND/updater verificati. Questo rapporto conserva byte/formule/provenienza storici; le relative etichette ottiche non sono conclusioni valide.

**Data:** 21 ottobre 2026 · **Tappe:** R0/R1 · **Esito:** PASS statico, nessun hardware toccato · **Stima complessiva: circa 10% invariata**

- Script riproducibile: [Python_Trace_Scripts/s33_verify_lens_mcu_dialog.py](../Python_Trace_Scripts/s33_verify_lens_mcu_dialog.py)
- Evidenze: [Risultati/Lens_MCU_Interface/latest.json](../Risultati/Lens_MCU_Interface/latest.json), finestre GNU `gnu_windows.txt` nella stessa cartella datata.
- Campione: firmware V1.1, SHA-256 `1d34e990…e62a39`; blocchi verificati via `verified_payloads`.

## 1. Domanda e metodo

Volevamo capire **come il firmware dialoga con lo zoom e l'obiettivo** (zoom/focus/iride/otturatore, pilotati dal MCU dell'unità ottica). Il metodo replica la sessione sul sensore: inventario dei pool MMIO `ld [pcl]` nel Main, finestre GNU ridisassemble con allineamento verificato agli ingressi di funzione, stringhe di conferma a offset fissi.

Punto di partenza noto: la mappa RAM registrava `0x25E070/0x25E0B0` con `r1=0x0FF05000` come «porto MMIO per comandi/dati; chip non identificato». Questa sessione lo identifica come la **porta del MCU dell'obiettivo** e ricostruisce il dialogo attorno.

## 2. Livello basso: il blocco porta 0x0FF05xxx (Main)

Il cluster di funzioni in Main `0x25DF00–0x25E120` è il driver di porta, tutti accessi halfword `.di`:

| Registro | Uso verificato | Funzione |
|---|---|---|
| `0x0FF05000` | porta dati comandi/risposte (scrittura/lettura halfword) | `0x25E064`/`0x25E078` scrivono; `0x25E08C`/`0x25E0A4` leggono |
| `0x0FF04024` bit 7 | stato «pronto» (letto con `lsr 7` + `bmsk 0`) | `0x25E0B8` |
| `0x0FF05108` + `0x0FF0510C` | ingressi di posizione: `([108] & 0x1F) << 16 \| ([10C] & 0x1F)` | `0x25E038` |
| `0x0FF05110` bit 0 | impulso reset (bset+bclr) | `0x25E00C` |
| `0x0FFCA008` | bit di controllo RMW condizionale | `0x25E0D4` |
| `0x0FF04020` bit 8, `0x0FF04000` bit 6 | set/clear (alimentazione/abilitazione, semantica non attribuita) | `0x25DF74/9C`, `0x25DFC4/E8` |

La porta 0x0FF05000 non è caricata da pool in nessun altro payload scansionato (2, 4): il dialogo con l'obiettivo è **esclusivo del Main**.

## 3. Handshake e transazione

- **Attenzione `0x25CB0C`:** scrive `0xFF` sulla porta, poi polla lo stato (`0x25E0B8`) fino a `0xF4240` = 1.000.000 iterazioni di timeout. È la sequenza di risveglio/retry del MCU.
- **Invio byte `0x25CB3C`:** wrapper che scrive il valore e chiama il servizio di attesa; **`0x25CB54`** è il mittente completo (aritmetica `muludw` per i tempi PPS, test dei bit 8/10 del pacchetto, chiamate indirette per l'esito).
- **Impacco 3 byte `0x25CBBC`:** `b0 = v`, `b1 = v>>8`, `b2 = (v>>14)|3` — header con tag.
- **Lettura blocchi `0x25F2B8`:** due letture di 256 byte dalla porta (memorizzate con `stb.ab`), con lettura della posizione e impacco 3 byte fra le due: lettura dei dati/calibrazione del modulo ottico. `0x25F31C` legge 16 byte.
- **Transazione comando `0x25F338`:** invia il comando via `0x25CB54`, esamina il **bit 0xA** del risultato, invia opzionalmente `0x30`, attende un ritardo di **1000** e, se lo stato non è zero, ripete l'attenzione `0x25CB0C`. Questa è la forma generale «comando → risposta → retry».

Il formato dei byte sul filo (opcode, checksum, lunghezze) non è ancora decodificato; le finestre ne danno la struttura, non il dizionario.

## 4. La tabella comandi BCIP del modulo ottico (payload2)

Nel payload2 (stesso blocco del driver sensore) è incorporata la documentazione del protocollo comandi del modulo ottico: gruppo `[BCIP] NAME=OM`, con **codici operazione** e parametri:

| Comando | Opcode | Parametri documentati |
|---|---|---|
| BCIP_Get_OM_Property | 0x9200 | Data Phase 1: Device to PC |
| BCIP_Lens_Off | 0x9203 | DP1=ErrCode |
| BCIP_ZOOM_MOVE | 0x9204 | P1=Physical Pos.; risposta: Zoom time (hi/lo), PI Value, ErrCode |
| BCIP_FOCUS_MOVE | 0x9205 | P1=Physical Pos.; DP1=ErrorCode |
| BCIP_FOCUS_Status | 0x9206 | SP1=0~3; DP1=Status |
| BCIP_FOCUS_Reset | 0x9207 | DP1=ErrorCode |
| BCIP_Aperture | 0x9208 | SP1=0:Set 1:Get; SP2=1:Big 9:Small (iride grande/piccola) |
| BCIP_Shutter | 0x9209 | SP1=0:Set 1:Get; SP2=0:Close 1:Open (otturatore) |
| BCIP_LensInitial | 0x920A | DP1=Err Code |
| BCIP_GET_OM_CONFIGURATION | 0x9211 | DP1=Lens ID, DP2/3=Zoom UML/LML, DP4=Zoom Position, DP5=Aperture Range |

Le 19 stringhe di comando/opcode sono verificate a offset fissi (evidenza JSON). Nota critica: **nessuna immediate 0x92xx appare nel codice Main**: la tabella BCIP è il vocabolario documentato dei comandi (con il suo formato «Operation Container»/«Response Container»), mentre il protocollo runtime che il Main manda sulla porta 0x0FF05000 usa una codifica byte propria non ancora decodificata. Le due cose non vanno fuse senza prova. Un secondo gruppo `[BCIP] NAME=EE` (0x91xx) riguarda EEPROM/registro e resta fuori da questa sessione.

Il contesto applicativo è confermato dalle stringhe di flusso: `MCUCTRL_Task` (Main, VA 0xEFC4B), `Tele button Press`/`Wide button press`/`Lens Zoom Stop` (payload1), `Lens start`/`Lens end`/`Lens Watchdog Time out` (payload1). I comandi di collaudo MCU del menu di servizio (`MCUGetByte/MCUGetData/MCUSetByte/MCUSetData`, payload6) usano la stessa porta attraverso il livello Main.

## 5. Architettura complessiva del dialogo

```
UI Tele/Wide (payload1) ──▶ LensCtrl/MCUCTRL_Task (Main) ──▶ cluster protocollo 0x25CB00–0x260D (Main)
                                   │ comando → handshake → risposta → retry(0xFF attention)
                                   ▼
                          porta MMIO 0x0FF05000 (halfword .di) + stato 0x0FF04024 bit7
                          posizione 0x0FF05108/0x0FF0510C · reset 0x0FF05110 · ausiliari 0x0FFCA008
                                   ▼
                          MCU dell'obiettivo (zoom, focus, iride, otturatore)
```

Rispetto alla sessione sensore: iride (BCIP_Aperture) e otturatore (BCIP_Shutter) sono nel modulo ottico, quindi l'esposizione combinata sensore+iride+otturatore attraversa entrambi i dialoghi (MMIO 0x0FF98xxx da un lato, porta MCU dall'altro).

## 6. Limiti

- Tutto statico: nessun MMIO/MCU/fotocamera toccata; nessuna esecuzione; NON_INSTALLARE.
- Il formato dei byte sul filo non è decodificato; le finestre ne mostrano la struttura (attenzione, timeout 1e6, blocchi 256 byte, bit 0xA, suffisso 0x30, ritardo 1000), non il dizionario.
- L'ingresso e la coda di `MCUCTRL_Task` (nome a VA 0xEFC4B) non sono risaliti; il collegamento tasto Tele/Wide → byte di comando è aperto.
- La tabella BCIP è documentazione dati, non prova del protocollo runtime.
- Versioni separate: V1.1 analizzato, macchina V1.0; indirizzi non portabili senza prova.

## 7. Prossimi passi

1. Decodificare il formato byte del protocollo porta (chi manda quali byte; ruolo del tag 3 nell'header 3 byte) partendo dalle chiamate di `0x25CB54` e dei sender in 0x25D000–0x260D.
2. Risalire all'ingresso di `MCUCTRL_Task` e alla coda comandi (tabella nomi task in Main) per collegare i tasti zoom a transazioni specifiche.
3. Collegare la posizione composta 0x0FF05108/0510C alle letture `Zoom Position`/`FocusPosition` delle stringhe applicative.
4. Cross-check con il dialogo iride/otturatore del modulo BCIP e il gate esposizione sensore (0x0FE800F4) della sessione precedente.
