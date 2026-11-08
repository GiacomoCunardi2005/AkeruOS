# AkeruUSB — configurazione originale del controller

26 ottobre 2026. Stato **NON_INSTALLARE**; ricerca offline verso il dump RAM.

La catena originale V1.1 `278F30 → 27864C/2792D0 → 2DBCF8`, seguita
da `278854/279658 → 2DBFB8` nei casi bulk senza scatter/gather,
è stata eseguita su CPU GNU ARC700. `2DBCF8` contiene i byte originali:
la configurazione endpoint non è più una fixture in questo nuovo banco.
Allocatore, lock, accessi ai registri, template e contesti restano modellati.
Questo risultato non costituisce un trasferimento USB né un dump RAM fisico.

## Prova riproducibile

```sh
PYTHONDONTWRITEBYTECODE=1 make -C AkeruOS usb-ram-controller-config-verify
```

- Verificatore: [s33_verify_akeru_usb_controller_config.py](../Python_Trace_Scripts/s33_verify_akeru_usb_controller_config.py).
- Banco: [usb_controller_config_gnu_test.c](../AkeruOS/tests/usb_controller_config_gnu_test.c),
  che riusa il banco apertura/buffer senza modificarlo.
- Esito finale: [verified_evidence.json](../Risultati/AkeruUSB_RAM_Debug/Controller_Config/20261026T174636Z/verified_evidence.json).
- Directory prove: `Risultati/AkeruUSB_RAM_Debug/Controller_Config/20261026T174636Z/`.

**576 scenari PASS**, 96 invii integrati, **5.422.368 istruzioni**, uscita 0,
nessun fault CPU. Compilazione con `-Wall -Wextra -Werror`; sezioni originali
estratte dal firmware verificato e confrontate byte per byte con l'ELF.
La traccia conserva hash sia del contenuto sia del file gzip.

| Dimensione | Valori del banco |
|---|---|
| Direzione, bit8 del record | 0 OUT / 1 IN |
| Numero endpoint | 1, 3, 15 |
| Maxpacket | 64, 512 |
| Flag scatter/gather `CTRL+99` | 0, 1 |
| Selezione configurazione `CTRL+101` | 0, 1 |
| Bit15 del controllo endpoint letto | 0, 1 |
| Tipo descrittore | 1, 2, 3 |
| Pattern template/controllo | zero e pattern con altri bit impostati |

Le 96 submit riguardano tipo2, scatter/gather0 e preparazione DMA lineare;
il buffer sintetico possiede 1024 byte. Non si deduce da questo la capacità
del futuro adapter dispositivo. Il payload rimane identico al pattern iniziale.

## Comportamento osservato nella CPU emulata

1. `2DBCF8` viene raggiunta 576 volte dall'apertura originale. Legge il
   controllo endpoint tramite la tabella sintetica del controller.
   Con bit15=0 esegue 288 volte il ramo `2DBD7C`: aggiorna maxpacket
   nei bit0..10, tipo nei bit18..19, campo del descrittore10..13 nei
   bit22..25 e imposta bit28 e bit15, conservando gli altri bit.
   Con bit15=1 salta quella riscrittura: 288 casi. Questo salto riguarda
   una parte della funzione, non tutta la configurazione.
2. Per endpoint1 la funzione imposta il campo descrittore10..13 a1;
   per endpoint3 a2. Per endpoint15 il campo resta0 nei contesti provati.
   Non è una verifica del dominio completo né delle risorse fisiche.
3. Con `CTRL+101=1` scrive una parola per endpoint derivata dal template:
   ramo IN `2DBDC2` 144 volte, ramo OUT `2DBDF8` 144 volte. Nel banco
   l'indirizzo richiesto è `BASE+0x40+4*numero` per IN e
   `BASE+0x80+4*numero` per OUT. I percorsi impostano rispettivamente
   i bit0,1,2,3,5,8 e i bit0,1,2. Con `CTRL+99!=0` impostano anche bit9;
   con flag0 non cancellano un bit9 già presente nel template.
4. Aggiorna sempre una maschera usando il template `3533EC`:
   sostituisce la metà bassa a16 bit con `1<<numero` per IN,
   la metà alta per OUT, conservando l'altra metà. L'helper riceve
   `clear_mask=0` e la parola così costruita come valore da impostare,
   su `BASE+0x1C` con flag101=0 oppure `BASE+0x3C` con flag101=1.
   Queste sono richieste agli helper, non misure di registri fisici.
5. Il punto `2DBE40` viene eseguito 576 volte e invoca l'helper originale
   che azzera i19 bit bassi del campo record+52. Il conteggio del solo
   helper generico non isolerebbe questa operazione: è condiviso con altri
   percorsi. Allocazioni ausiliarie: 192 aperture richiedono512 byte;
   le 96 submit richiedono un nodo32 byte, senza cambiare il payload.

Il successo dell'apertura non prova una riscrittura completa del controllo
endpoint. Inoltre non è corretto assumere template neutri o bit9 cancellato
dal flag scatter/gather0: la CPU conserva il bit del template nel dominio provato.

## Provenienza dei template e ricerca residua

La funzione legge parole a `3533EC/3533F0/3533F4`, tramite il puntatore
`3533A0` presente nei literal pool. I byte originali `3533A0..3533F7`
sono zero nel payload estratto; questo non prova lo stato al momento
dell'apertura. Il banco inietta esplicitamente due pattern e non esegue
l'inizializzazione runtime di queste parole.

Una ricerca letterale nei16 payload verificati trova `3533A0` in block0
alle posizioni candidate `2DA2D4`, `2DA6E8`, `2DAAA4`, `2DBD60`, `2DC16C`.
Non trova literal diretti delle tre parole singole. È una ricerca di byte,
non un censimento completo di riferimenti calcolati o una prova dei writer.
Le finestre esplorative che attraversavano dati/literal sono state respinte
dal controllo del disassemblatore; non sono usate come prova di codice.
Prossimo passo: seguire gli inizializzatori originali e la costruzione della
tabella, poi integrare configurazione e completamento nello stesso banco.

## Raccordo con il checkpoint precedente

La tappa già presente
`IRQ_Dispatch/20261026T133220Z/verified_evidence.json` è stata ricontrollata:
95 artefatti,22 input e hash del contenuto della traccia corrispondevano
prima dell'aggiunta del nuovo target Makefile. Contiene28 scenari CPU PASS,
323.548 istruzioni,12 ammissioni al consumatore e8 completamenti.
Quella tappa conserva la configurazione simulata; il nuovo banco conserva
gli accessi ai registri simulati e non integra ancora il dispatcher IRQ.
Non si sommano i due risultati per dichiarare provata l'intera catena.

La prima esecuzione della nuova matrice, `174316Z`, era PASS. La ripetizione
`174429Z` è terminata per il limite10s del runner; non era un processo
ancora vivo. `174526Z` ha completato correttamente la CPU ma ha respinto
un conteggio della traccia che includeva chiamate condivise dell'helper.
Il banco finale usa un timeout locale45s e il PC chiamante specifico:
GNU, firmware e runner condivisi non sono stati modificati. Le prove
precedenti, compresi gli esiti respinti, sono conservate.

## Limiti e stato del dumper

Le vtable, la tabella dei registri, gli stati letti, i template e le risorse
sono sintetici. Nessuna prova di DMA, PIO, cache coerente, IRQ consegnato,
W1C, scheduling, rilascio fisico, enumerazione o traffico USB.
I128MiB del simulatore non costituiscono una mappa RAM della Nikon.
La whitelist fisica, la capacità/lifetime del buffer adapter, il binding,
la residenza, il boot e il recupero restano da dimostrare. Originali,
calibrazioni, foto e GNU preservati; nessun dumper, flash, comando vendor,
NAND, reset USB o scrittura SD eseguito. **NON_INSTALLARE** invariato.
