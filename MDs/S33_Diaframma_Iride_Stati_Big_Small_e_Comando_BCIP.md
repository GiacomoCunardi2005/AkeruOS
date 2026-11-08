# Come il software parla con il diaframma: iride a due stati, comando BCIP_Aperture e trasporto OM

**Data:** 21 ottobre 2026 · **Tappe:** R0/R1 · **Esito:** PASS statico, nessun hardware toccato · **Stima complessiva: circa 10% invariata**

- Script riproducibile: [Python_Trace_Scripts/s33_verify_iris_aperture_dialog.py](../Python_Trace_Scripts/s33_verify_iris_aperture_dialog.py)
- Evidenze: [Risultati/Lens_MCU_Interface/Iris/latest.json](../Risultati/Lens_MCU_Interface/Iris/latest.json), finestra GNU `gnu_windows.txt` nella cartella datata.
- Continua direttamente [il rapporto obiettivo/zoom](S33_Obiettivo_Zoom_MCU_Interface_e_BCIP.md) (porta MCU 0x0FF05000 e transazione 0x25F338).

## 1. Domanda e metodo

Volevamo capire **come il firmware parla con il diaframma (iride)** dell'obiettivo. Metodo consolidato delle sessioni precedenti: stringhe a offset verificati, finestre GNU allineate, inventari dei pool e riuso delle evidenze di trasporto già verificate.

## 2. Il diaframma è a due stati: Big/Small

Le stringhe verificano un modello semplice, ripetuto su tre livelli diversi del firmware:

- **Runtime applicativo:** `Iris : %d (0:Big 1:Small)` (payload2) e `Iris status: Big/Small` (payload6): l'iride è un indice **binario 0/1**.
- **Comando documentato:** `BCIP_Aperture`, opcode **0x9208**, con `SP1=0:Set 1:Get` e `SP2=1:Big 9:Small` (Operation Container 20, Response Container 16, `DP1= Value`).
- **Tuning di fabbrica:** opzioni `Big Iris`/`Small Iris`, `Iris Switch`; nei test compaiono rapporti `small+ND`, quindi esiste una **variante ND** citata solo nei test di fabbrica, non nelle opzioni runtime.

L'iride entra nell'esposizione come indice accanto a tempo, guadagno e zoom: `ExpTime:%d Iris:%d Zoom:%d AdGain_LV@%d:%d`, `Set Iris:%d`, `Get Iris:%d`, `ucIrisIndex : %d` (tutte verificate). I comandi diagnostici `SetIrisIndex` e `ImgCap_SetAperture` permettono di imporre l'indice da script.

## 3. Il percorso: comando OM sulla porta MCU del'obiettivo

> **CORREZIONE del 22 ottobre 2026 (iterazione 21):** il paragrafo seguente è
> SUPERATO per la parte iris. Il diaframma **ha GPIO propri**: bit4 (Big) e bit3
> (Small) di **0x0FF04024**, con pulizia bit0/1 di **0x0FEF0388**, attuati dalla
> request 0x235B0C (percorsi 0x2358F4/0x235950) sotto l'API 0x149530→0x18B85C.
> L'iride NON viaggia sulla transazione 0x25F338/porta 0x0FF05000: la ricerca
> del «wrapper iris fra i 35 chiamanti» è chiusa NEGATIVAMENTE. Vedi
> [attuazione GPIO iris](S33_Iride_Attuazione_GPIO_0FF04024_e_Chiusura_Wrapper.md).
> La codifica 1:Big 9:Small di BCIP_Aperture SP2 è confermata al livello
> attuazione (`cmp idx,0x9`). Le parti di questo rapporto su calibrazione
> IRIS 1/2, variante ND e vocabolario BCIP restano valide.

Il diaframma **non ha un GPIO proprio**: nessun MMIO iris-specifico fuori dal cluster porta dell'obiettivo (0x0FF05000, sessione precedente). Il comando documentato viaggia nel gruppo OM (optical module) del protocollo BCIP, cioè attraverso il MCU dell'obiettivo, come zoom/focus/otturatore:

- **Trasporto runtime condiviso:** la transazione `0x25F338` del Main ha **35 chiamanti** (inventario verificato), ognuno parametrizzato da un **descrittore in RAM** caricato da pool PC-relativo (es. `0x50E140` a 0x29E2BC, `0x50E340` a 0x29E74C — parole del payload verificate). La finestra allineata `0x29E0A4–0x29E0DC` mostra il ciclo: carica descrittore → `r2` buffer → chiama `0x25F338` con `r3=0` → ripete finché la posizione richiesta non è raggiunta.
- Nessuna immediata 0x9208 nel codice (Main, payload2, payload9): come già registrato per gli altri comandi OM, **BCIP è il vocabolario documentato**, la codifica byte runtime sulla porta resta da decodificare.

## 4. Calibrazione: due tabelle IRIS con checksum

Le voci di menu `IRIS 1`/`IRIS 2` (payload6) e le etichette `LENS IRIS 1 DATA`/`LENS IRIS 2 DATA` con esiti `ReadError`/`CheckSumError` mostrano che l'unità ottica conserva **due tabelle di calibrazione iride con checksum**, lette e validate dal firmware (compatibili con le letture a blocchi di 256 byte dalla porta documentate nella sessione obiettivo, anche se il legame specifico non è provato). A queste si aggiungono i valori per posizione `EFAIRISBIG`/`EFAIRISSMALL` e i vincoli di calibrazione otturatore `Small/Big Iris Upper/Lower Bound`. Durante l'aggiustamento del guadagno, un errore lente è riportato per apertura: `Aperture[%d],Lens NG in AdjustADGain`.

## 5. Sintesi del dialogo col diaframma

```
3A (payload1: indice iris 0/1) ──▶ API ottica (Main, cluster 0x1EC–0x2FF/0x29E)
        │ descrittore comando in RAM (0x50E140/0x50E340…)
        ▼
transazione 0x25F338 ── porta MCU 0x0FF05000 ──▶ MCU obiettivo ──▶ iride Big/Small (+ND solo fabbrica)
calibrazione: tabelle LENS IRIS 1/2 con checksum + EFAIRISBIG/SMALL (lette dall'ottica)
```

In pratica: il software **non modula un'apertura continua**; sceglie uno dei due stati dell'iride, lo invia come comando del modulo ottico sulla porta MCU condivisa e ne verifica esito e calibrazione. L'apertura numerica (Fno) e i rapporti wide/tele compaiono solo nei dati di tuning.

## 6. Limiti

- Tutto statico: nessun MMIO/MCU/fotocamera toccata; NON_INSTALLARE.
- Quale dei 35 chiamanti della transazione sia il wrapper iris specifico non è ancora individuato; la codifica byte del comando runtime resta da decodificare.
- Il legame fra le letture a blocchi 256 byte e le tabelle LENS IRIS è suggerito dalle stringhe di checksum, non provato.
- Nessuna misura fisica di tempi/posizioni; ND runtime non osservato.

## 7. Prossimi passi

1. Decodificare i descrittori RAM dei comandi (inizializzati a runtime: serve il tratto di init in Main che riempie 0x50E140/0x50E340) per distinguere il comando iris da zoom/focus/otturatore.
2. Decodifica wire della porta (iniziata nella sessione obiettivo) e identificazione del byte di comando iris.
3. Collegare l'indice 3A (payload1) al wrapper iris di Main attraverso l'API `CAPCTRL`/LensCtrl.
