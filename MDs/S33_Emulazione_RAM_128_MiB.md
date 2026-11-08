# RAM da 128 MiB nel simulatore

20 ottobre 2026, R3/R4. **Configurata e provata una banca RAM di laboratorio da 128 MiB**, seguendo la stima proposta dall'utente. Non è una misura della memoria installata nella Nikon e non viene promossa a ipotesi hardware più probabile sulla base dei soli requisiti fotografici.

Nel modello interpretiamo «128 MB» come **128 MiB = 134.217.728 byte**, intervallo `[0x00000000, 0x08000000)`: ultimo byte `0x07FFFFFF`. Base zero e contiguità sono ipotesi esplicite, non una mappa fisica ricavata dal chip.

## Configurazione e controllo del contenuto

Il probe conserva i tre blocchi già caricati: MainCode, corpo TBIB e payload dati1. Verifica l'hash di ciascun blocco prima e dopo l'aggiunta della RAM. Lo stack di laboratorio resta nella propria posizione; vengono aggiunti cinque intervalli per coprire i buchi, complessivamente 130.241.092 byte. La copertura finale dei 128 MiB è controllata senza buchi e con confine esatto.

Sono confrontati due profili, mantenuti distinti:

| Profilo | Contenuto dei nuovi intervalli | Uso |
|---|---|---|
| `unknown` | Sconosciuto; la lettura prima di inizializzazione arresta il test | Profilo prudente da usare come riferimento per proseguire |
| `zero` | Esplicitamente azzerato, compreso lo stack prima delle fixture | Esperimento separato sulla dipendenza dai valori iniziali |

Il secondo profilo può nascondere letture di variabili non inizializzate o puntatori errati: non è un'immagine della RAM reale. Né esso né il primo fanno comparire i payload non caricati, driver completi o servizi Nikon; per un avvio completo serve ancora il caricamento corretto delle varie sezioni e delle loro fasi/overlay. Non si certifica una protezione generale da accessi fuori banco.

I registri hardware `0x0FE800F8`, `0x0FE80050`, `0x0FE80064` restano **fuori dalla banca RAM**. Solo il primo riceve ancora gli input costanti0/128 già dichiarati nel [test bit7](S33_Registro_Hardware_Bit7_e_Avvio.md); gli altri provocano il fault. Le finestre workspace alte, fra cui le basi fino a `0x0F7B0000`, non sono automaticamente incluse o rese alias della RAM bassa: la loro natura fisica rimane aperta.

## Prove riproducibili eseguite

```bash
python3 S33-sections/safety_audit_codex/verify_ram128.py
```

[Runner](../S33-sections/safety_audit_codex/verify_ram128.py), [probe RAM](../S33-sections/analysis_ghidra/scripts/ProbeRam128.java), [probe hardware riusato](../S33-sections/analysis_ghidra/scripts/ProbeHardwareBit.java), [helper avvio riusato](../S33-sections/analysis_ghidra/scripts/ProbeStatusRead.java), [manifest](../S33-sections/safety_audit_codex/ram128_verified.json), [log](../S33-sections/safety_audit_codex/evidence/ram128_run.log).

**32 tentativi limitati di avvio e72 casi isolati del selettore**: due contenuti iniziali RAM ×due campioni ×i casi del probe precedente. Le istruzioni non sono cambiate, nessun nuovo decoder introdotto; si usa `ARCompact:LE:32:loopfix`. Il runner verifica l'identità dei firmware e gli hash di tutti i file della baseline hardware prima/dopo. Non riesegue gli altri vecchi runner.

Dopo aver escluso la sola nuova riga descrittiva `RAM128`, le tracce registrate coincidono **esattamente** con la baseline hardware, comprese tutte le righe caso, i riepiloghi e i conteggi BSS. Non è un confronto dell'intera RAM: per costruzione gli intervalli disponibili differiscono. Dimostra che nei tratti eseguiti i due contenuti RAM aggiunti non cambiano il percorso osservato.

| Bit7 fornito a0FE800F8 | TBIB: confine / passi riusciti | MainCode: confine / passi riusciti | Lettura sconosciuta successiva |
|---|---|---|---|
|0 |010095FA /10.714 |17A01E /444.299 |halfword0FE80064 |
|1 |010095FA /10.715 |17A01E /444.300 |halfword0FE80050 |

Tutti i casi MainCode ricontrollano l'azzeramento firmware di1.758.364byte daA5 a0 dopo439.690passi. I profiliSTATUS32nonflag0/6, la base vettori0 e i registri core iniziali rimangono contesti sintetici. Ingressi TBIB eMainCode sono prove separate, non una catena ROM→TBIB→MainCode completa. Fault segnalati arrestano il test anche se `step()` restituiscevero.

## Conseguenza per il prossimo lavoro

**128 MiB è ora una scelta concreta e riproducibile del laboratorio. Aumentare o azzerare la RAM non ha superato il limite attuale**, che riguarda le risposte dei registri hardware successivi. Proseguire dai record12/13 e dai calcoli/consumatori relativi mantenendo come riferimento il profilo `unknown`; ogni nuova risposta hardware simulata va dichiarata separatamente. La dimensione fisica della RAM della Nikon rimane non determinata.

Restano writer indiretti dello statoHiddenMenu, concorrenza del3temporaneo, CPU/DSP e interrupt completi, avvio/UI completi e recupero dopo un aggiornamento interrotto. Nessuna RAM è assegnata adAkeruOS. Firmware originali, immagini di confronto e decoder precedenti preservati; nessuna operazione hardware. **NO-GO flash e circa10% funzionale invariati.**

## Continuazione: dimensione configurata decodificata — 20 ottobre 2026

Il [consumatore nel BootNAND](S33_BootNAND_DDR_ID_Dimensione_e_Checksum.md) ora chiarisce il significato software dell’ID: byte basso ×8 MiB, quindi256 MiB configurati per0120; bit8 distinto nel controller. Verificati12casi aritmeticiCPU e2checksum originali. Questo supera «ID ancora non decodificato», senza certificare RAM fisica o una banca contigua utilizzabile. Checksum BFN5A97D e test RAM sparso ricostruiti; profilo128MiB del laboratorio non modificato. Prossimo: loader e dati NAND successivi ai primi512byte.
