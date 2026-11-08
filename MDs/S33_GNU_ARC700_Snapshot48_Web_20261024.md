# GNU ARC700 — registro FED2018 nel monitor web

24 ottobre 2026. Implementata la richiesta utente di modellare il registro
halfword `0x0FED2018` nel monitor locale <http://127.0.0.1:8700>.

## Contratto limitato e fonti

Il disassemblato originale V1.1 di `0x169A74…0x169AE8` imposta bit0 del controllo,
legge high/middle/low a `FED2024/FED2020/FED201C`, poi azzera bit0. Il lettore
combina i tre halfword e restituisce r1:r0. Non attribuisce una frequenza fisica.
Verificati byte e pool nell'ELF Main già fissato per hash.

Il precedente `Python_Trace_Scripts/s33_verify_gnu_snapshot48.py` conteneva un
contratto statico e casi di prova, ma l'evidenza storica
`outputs/gnu_arc700/20261020T125650Z_9e6c0252/verified_evidence.json` è **FAIL**:
si fermava al budget_check prima dei32casi. Non è stata usata come provaPASS.

## Modifica

Frontend esterno `AkeruOS/tools/arc700_web/bridge.c`: inizializza quattro celle
MMIO distinte di2byte con `sim_write`; controlloR/W, tre valori dati fissi.
Nessun avanzamento temporale, latch hardware, W1C o frequenza aggiunti.
Il profilo web `main-snapshot48`, ora predefinito, usa quattro halfwordzero.
`main` conserva il limite precedente; `tbib` resta disponibile.
La pagina espone controllo, bit0, valore48bit e l'indicazione statico.

GNU `cgen_rtx_error` segnala anche gli arresti di provenienza con SIGTRAP,
come i passi. Aggiunto linker `--wrap=cgen_rtx_error` nel solo frontend:
imposta il flagterminal e richiama la funzioneGNU originale, senza modificare
motore o firmware e senza saltare l'istruzione. Corregge il timeout/retry cieco
che il nuovo percorso aveva esposto nel monitor precedente.

## Verifiche

- `outputs/arc700_web/tests_snapshot48.log`: **6test d'integrazione PASS**.
  Baseline, TBIB, validazioni/origini e nuovo modello con GNU reale.
- `outputs/arc700_web/snapshot48_20261024T154325Z/verified_evidence.json`:
  **32casi CPU PASS**, 8triplette comprese condizioni bit15/FFFF e4controlli
  iniziali0/1/A5A5/FFFF. Codiceoriginale a indirizzi originali incluso nel solo
  ELFtest, intatto. Ritorno48bit, SP/r13–r17, controllo finale e altre bit
  verificati. Tracce:5siti distinti di lettura halfword e2di scrittura;
  righe duplicate GNU single-step non contate come eventi hardware.
- **3configurazioni malformate rifiutate** dal frontend; halfword adiacente
  `FED201A` resta unmapped e ferma laCPU: nessuna mappatura dell'intera pagina.
- Main: a579742passi PC169A84;3passi portano a169A90/control1;
  altri15 a169ACA/control0. Il lettore ritorna e Main prosegue.
- Nuovo arresto: **579921chiamate single-step**, PC `0x0016C99A`, segnale5,
  `S33_UNDEFINED address=00000970 size=2 first=00000970 operation=data_read`.
  Nessuna RAM sconosciuta è stata dichiarata per aggirarlo.
- UI verificata nella scheda locale: selezione modello/baseline, indicatore
  controllo/valore statico, passo10, filtroSP, run/pausa; nessun erroreconsole.
  Diagnostica esplicita `LIMITE DEL MODELLO` sullo stop di provenienza.

## Limiti

Modello di laboratorio statico, non periferica temporale fisica convalidata.
RAM128MiB sintetica e DSPprovvisorio invariati; il prossimo blocco richiede
indagare provenienza del puntatore/data `0x970`, non aggiungere RAMzero.
Sorgenti/build/installazioni/copielabGNU e firmware restanoRO. Nessun accesso
hardware, USB/NAND/vendor/flash/dumper/SD. Nessun bootcompleto dimostrato.
**NON_INSTALLARE** resta invariato.
