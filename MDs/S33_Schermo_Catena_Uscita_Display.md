# S33 — schermo: catena di uscita display, primo dossier statico

Analisi statica del 21 ottobre 2026 sul firmware V1.1. Nessuna esecuzione del firmware, nessun accesso USB o alla fotocamera, nessuna scrittura. Continuazione naturale del [backend di ingresso dei pulsanti](S33_Pulsanti_Hardware_Backend_Ingresso.md): qui si studia il lato uscita, cioè come il software porta qualcosa sullo schermo. La macchina osservata resta V1.0: gli indirizzi non sono portabili senza prova.

## Risultato

Non esiste un singolo oggetto «Display» nella tabella oggetti (197 voci): la catena schermo è un servizio a strati. Questo primo dossier ne delimita cinque, tutti con evidenza byte-verificata e finestre GNU radicate:

```text
oggetto UI (0x1453E4 apre; risorse classe 7/4/0A)   [già documentato]
  → libreria font/contesto grafico 0x298000..0x29D000 (blocco 0)
  → driver LCD: timing/TG CLK (blocco 2), test TV/LCD (blocco 0), V_COM (blocco 0)
  → pannello: tipi GPT/WTK/TNA selezionabili e salvati in calibrazione
  → dizionario comandi script LCDOn/LCDOff/ClearOSD (blocco 5)
  → comandi BCIP di produzione: LCD_PLAY_IMAGE, SET_LCD_BACK_LIGHT (blocco 1)
```

Il collegamento oggetto→pixel **non è ancora eseguito**: la catena si ferma come già documentato al muludw `0x3342B4` durante l'inizializzazione della risorsa. «Apre sullo schermo» resta da dimostrare; qui si aggiunge la mappa dei servizi a valle. Avanzamento complessivo invariato: circa 10%.

## 1. Libreria font/contesto grafico (blocco 0)

Il tratto `0x1EB2C0..0x1EB410` costruisce un contesto grafico passo-passo: `0x2981A4` (creazione), `0x29AF40` (font, con il nome da `[fp,-52]`), `0x2983DC` (attach), `0x2986B0` (bind font), `0x298740`, `0x298408`, `0x298DC8` (finale). Ogni fallimento registra via `0x156890(0x50, 0x50, 2, stringa)` con i testi letterali:

- `hfFontCreate Fail` (0x3BB256, letterale a 0x1EB3A8)
- `hfContextBindFont Fail` (0x3BB280, letterale a 0x1EB3B0)

Un secondo ingresso `0x1EB3B8` rifà il bind del contesto (`0xC588C`, `0xC7E04`, `0x32DE80`, `0x1EBDE0`, `0x1EBE20`) e usa il logger `0xAD90C` con linea `0x4B<<9`. Il cluster completo `0x298000..0x29D000` non è ancora disassemblato: dati glifo e destinazione dei pixel restano aperti.

## 2. Driver LCD: timing e test

| Tratto | Evidenza |
|---|---|
| `0x651EC0` (blocco 2) | Logger `0x1567F8(0x14, riga, stringa)` con predicati di prontezza `0x65208C`/`0x6520A8`; stringa `Load LCD TG CLK OK` (0x782172, letterale a 0x651F1C) |
| `0x16C3xx` (blocco 0) | Test modalità TV/LCD: stringhe `Set TV NTSC Mode : LEFT`, `Set LCD Mode : OK` (0x392CBF, letterale a 0x16C3F4); legge il livello del tasto via `0x210BC8` (lo stesso lettore bit 0 di `0x0FF04020` del backend pulsanti) e usa il getter `0x16F920`; **MMIO letterali `0x0FEB1000` e `0x90A1100`** nel pool 0x16C3E4..0x16C410 |
| `0x1DF300` (blocco 0) | Test V_COM del pannello: itera una tabella di parametri halfword, chiama `0x32E180` e `0x12DE3C`, registra `LCD V_COM = 1 %d` / `LCD V_COM = 0 %d` (0x3BA713/0x3BA725, letterali a 0x1DF3AC/0x1DF3B0) |

Altri nomi di log del dominio display in blocco 1: `S1 display`, `QV display`, `REV display`, `Display start`, `Display end`, `Set Display Path Start/End`, `LCD Will be turn off`.

## 3. Pannello: tipi e calibrazione

In blocco 5 esistono le etichette `LCD : GPT/WTK/TNA 640x480 | 960x240 | 960x480` e `LCD : Default` (da 0x982E9F): tipi di pannello candidati con dimensioni. Il puntatore d'etichetta a 0x7CCE1C (blocco 4) conferme l'uso da parte del menu `LCD Select` (DebugMode). I comandi di servizio `LCD_TypeSelect`, `LCD_TypeSetup`, `LCD_TypeGet` compaiono nel dizionario script e la stringa `save LCD type in calibration fail` (0x988799) indica che il tipo scelto viene **salvato nei dati di calibrazione**: la selezione pannello è una scelta persistente, non un semplice settaggio runtime.

## 4. Dizionario comandi dello script di servizio (blocco 5)

Nella regione `0x9A0C00..0x9A2000` c'è un dizionario ordinato di parole chiave con record `nome + NUL + 0x07 + flag`. Oltre a decine di comandi `Key*` simulati (KeyOK, KeyLeft, KeyMenu…), contiene i comandi LCD:

`ClearOSD`, `LCDOff`, `LCDOn`, `LCDRedrawEnable`, `LCDScript_SetFixedBrightness`, `SetBrightnessValue`, `ResetLCDPwrSave`, `SetFontColor`, `VFSetFontColor`, `LCD_TypeSelect/Setup/Get`.

Esiste quindi un linguaggio di script di collaudo che accende/spegne e ridisegna l'LCD in modo esplicito; il suo parser non è ancora localizzato (i riferimenti alle stringhe non usano puntatori allineati). Le stringhe `ScreenString`, `ScreenInt32`, `ScreenFloat32` (blocco 1) suggeriscono variabili tipizzate dello stesso ambiente.

## 5. Comandi BCIP di produzione (blocco 1)

Inventario di 30 comandi `BCIP_*`, tra cui due direttamente display:

- `BCIP_LCD_PLAY_IMAGE` — descrizione con dimensione/posizione immagine e pattern `PS=1:1|R:G:B:4|B:Black:5|White`;
- `BCIP_SET_LCD_BACK_LIGHT` — `Command Code=0x29a2`, `Command Size=1`, `Value 0-255`.

Gli handler non sono attribuiti in questo passaggio: le stringhe documentano l'interfaccia, non il flusso eseguito. BCIP include anche `BCIP_ENABLE_LIVE_VIEW` e `BCIP_Take_Picture`: l'ambiente di collaudo produce può pilotare il display senza l'applicazione normale.

## Cosa manca per «aprire sullo schermo»

1. Il passaggio oggetto→disegno: dalla callback di inizializzazione (es. 0x7CC714 per la radice HiddenMenu) ai servizi di questa mappa; l'arresto al muludw `0x3342B4` va superato con la semantica corretta, non aggirato.
2. Il cluster `0x298000..0x29D000`: primitive di disegno, dati glifo, destinazione pixel (framebuffer non ancora identificato).
3. I registri del controller display: `0x0FEB1000` compare nel test TV/LCD; la famiglia `0x0FEBxxxx` è nuova nella mappa MMIO.
4. Parser del dizionario script e handler BCIP.

## Riproduzione

```bash
python3 Python_Trace_Scripts/s33_trace_display_output_chain.py
```

Lo script verifica hash e dimensioni dei 16 blocchi, i letterali dei pool, le stringhe display byte per byte, il dizionario script (12 parole chiave LCD + comandi Key*), l'inventario BCIP (30) e conserva **8 finestre radicate GNU ARC700** in [gnu_verified.txt](../Ghidra_Results/ghidra_reports/display_output/gnu_verified.txt); il [JSON](../Ghidra_Results/ghidra_reports/display_output/verified_evidence.json) registra hash, finestre, livelli e limiti. Nessun firmware eseguito.

## Limiti

- Statico V1.1: nessuna esecuzione; equivalenza V1.0 non provata.
- Nessun pixel prodotto o osservato: il rapporto mappa servizi, non un rendering riuscito.
- `0x0FEB1000`/`0x90A1100` attribuiti solo come letterali del test TV/LCD; il registro display effettivo e il framebuffer restano sconosciuti.
- Dizionario script: struttura del record 0x07+flag osservata, semantica dei flag non attribuita.
- Circa 10% invariato, candidato firmware NON_INSTALLARE, nessuna azione hardware.
