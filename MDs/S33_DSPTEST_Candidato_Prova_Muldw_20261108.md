# DSPTEST: candidato per misurare muldw/muludw/macdw/macudw sulla CPU reale

8 novembre 2026. Obiettivo: portare al 99% la semantica di `muldw` ([studio statico](S33_Muldw_Famiglia_Studio_Statico_20261108.md)) con un'osservazione hardware. Il dump v5 esistente non conteneva osservazioni utili. Il test su fotocamera è **autorizzato dall'utente in questa data** ("Prepara e autorizzo test"); l'installazione la esegue l'utente.

## Candidato

`Risultati/Firmware_sperimentali/MEMDUMP/DSPTEST_OFFLINE_NON_INSTALLARE_20261108T103625759247Z/firmware.bin`, SHA-256 `32e39bb1a06c171148ddc5252e090447861c5db0059ce6413992e32645b22c99`, 1618 byte cambiati (hook `0xC58EE`, 2 siti `0x16ED84`/`0x16ED98`, guard `0x35BB20`, risorsa 1708 byte a `0xE99E00`); il rollback ricostruisce l'originale.

È il v5 provato sull'hardware il 6 novembre (stessi guard/held/site, firma versione 5). Cambia solo il worker [`nikon_v11_memdump_worker_dsptest.c`](../AkeruOS/nikon_v11_memdump_worker_dsptest.c):
1. Esegue 608 operazioni DSP e registra `{tag, mode, b, c, r56, r57}` in una tabella `DSPT`/`TEND` sullo stack del task (frame 15.388 byte su 0x8000; sul v5 erano usati 1584 byte, stack a `0x52A28`):
   - `muldw`/`muludw` su 12×12 bordi (0, 1, 2, 0x7FFF, 0x8000, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF, 0x12345678) con MACMODE 0;
   - 8×8 bordi con MACMODE 8 (bit 3 del ridimensionatore);
   - 32 coppie LCG;
   - 64 coppie seme `mul*dw` + `mac*dw`.
   MACMODE originale letto prima e ripristinato dopo.
2. Poi esegue il dump v5 invariato `[0, 0x0104074C)` in **`B:\DSPTEST.BIN`** (nome nuovo, nessuna collisione con `MEMDUMP.BIN`).

Builder: `python3 Python_Trace_Scripts/s33_build_memdump_held_offline.py --dsptest`. Regressione: la build senza flag dà ancora `a0e4a4ee…6948`, cioè il v5 hardware.

## Verifiche offline

- Disassemblato: ogni `mul*dw`/`mac*dw` (`2c0c/2c0d/2c10/2c11 017e`) è seguita da `mov r13,r56; mov r12,r57`. Encodings identici a quelli del firmware.
- P-code/FAT: `python3 Python_Trace_Scripts/s33_verify_memdump_held_v5.py --dsptest` → `Risultati/Runtime_Kernel/MEMDUMP_DSPTEST_Hook_FAT/20261108T104344304313Z`: hook, task, 608 operazioni, file `DSPTEST BIN` di 17.041.228 byte, 1 close, fsck PASS. La tabella letta dal frame del task ha 608 record con ingressi identici alla sequenza attesa. In questo modello i risultati DSP sono un **modello dichiarato** (le istruzioni sono CALLOTHER in SLEIGH), quindi la prova riguarda flusso e tabella, non la semantica. Nel modello lo stack sta a `0x10D715C`, fuori dal dump, e la tabella è stata letta dalla finestra salvata. Sull'hardware v5 lo stack era dentro l'intervallo.
- Regressione `--hook` v5 PASS. Autotest dell'analizzatore PASS (rileva corsie scambiate, segno sbagliato, tabella assente).

## Procedura (utente)

1. Copiare `firmware.bin` del candidato in `firmware/firmware.bin` sulla SD, come per il v5, e aggiornare/riaccendere.
2. Attendere la comparsa di `DSPTEST.BIN` di 17.041.228 byte (fino a ~30 s di attesa volume, poi la scrittura).
3. Copiare il file in `Risultati/Dump_fotocamera/DSPTEST_<data>/` e reinstallare il firmware originale V1.1.
4. Analisi: `python3 Python_Trace_Scripts/s33_dsptest_analyze.py <DSPTEST.BIN> <out.json>`, che confronta per categoria con H1 (r56 = corsia alta, r57 = corsia bassa, con/senza segno, mac accumula).

## Limiti e rischi

Il posizionamento dello stack sull'hardware non è garantito (l'analizzatore cerca la tabella in tutto il file). Effetti di MACMODE 8 sconosciuti per costruzione: è appunto ciò che si misura. Durata e persistenza come per il v5. Un solo dispositivo; flag/stato non `.f` non misurati.
