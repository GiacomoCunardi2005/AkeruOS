# AkeruUSB — close, cancel, evento e flush del controller

27 ottobre 2026. Ricerca offline verso il dump RAM via software.
**NON_INSTALLARE**. Nessun accesso alla fotocamera.

La catena originale `278B0C → 19199C → 1910C4` è ora eseguita sulla CPU
GNU ARC700: **68 scenari PASS**, insieme alla regressione dei 36 scambi
AkeruRAM. Totale **7.565.162 istruzioni**, uscita 0, nessun fault.
La prova verifica l'ordine software callback/nodo/evento nei casi modellati;
resta aperta la cessazione fisica del DMA prima del riuso dei buffer.

Il limite decisivo è riprodotto in due scenari: mantenendo il bit di flush
asserto nelle risposte MMIO della fixture, il firmware effettua **10.001
letture**, prosegue la chiusura e arriva comunque alla pubblicazione
dell'evento. Ritorno 0 ed evento non certificano quindi la quiescenza
fisica richiesta dal futuro binding AkeruRAM.

## Prove e riproduzione

```sh
PYTHONDONTWRITEBYTECODE=1 make -C AkeruOS usb-ram-class-close-verify
```

- [Banco C](../AkeruOS/tests/usb_class_close_gnu_test.c).
- [Verificatore esistente](../Python_Trace_Scripts/s33_verify_akeru_usb_class_close.py).
- [Manifest CPU, contatori e limiti](../Risultati/AkeruUSB_RAM_Debug/Class_Close/20261027T104920Z/verified_evidence.json).
- [Controllo successivo di integrità e ripartizione flush](../Risultati/AkeruUSB_RAM_Debug/Class_Close_Audit/20261027T104920Z/postcheck.json).
- [Confine evento originale, analisi solo statica](../Risultati/AkeruUSB_RAM_Debug/Class_Close_Audit/20261027T104920Z/event_boundary_static.txt).

SHA256 manifest CPU:
`c63fa916d85fb0bcccc1135378d0d88e06badb093096a96f45c4b54ffb547972`.
Ricontrollati 180 artefatti e 37 input; verificato anche l'hash della
traccia decompressa. Le sezioni originali dell'ELF sono confrontate con
i payload V1.1 dal verificatore. GNU, firmware e sorgenti dei banchi
preesistenti non sono stati modificati in questa ripresa.

I tentativi del 26 ottobre `191526Z` e `191639Z` restano conservati come
FAIL. Nel secondo l'esecuzione CPU terminava a uscita 0, ma il verificatore
attendeva 34 ingressi al flush contro 194 osservati. Lo script corrente
conteneva già la correzione, ancora da eseguire. La nuova traccia conferma
separatamente i callsite originali: **160 da `2DA4FA` durante la preparazione,
34 da `2795E4` durante la chiusura**. Nessuna istruzione Nikon è stata
alterata per ottenere PASS.

## Ordine ricostruito

`278B0C` invoca il callback della classe a tabella+0x14, cioè `19199C`,
con interfaccia pubblico+4; il wrapper ritorna comunque 0. `19199C`:

1. Recupera il contesto da interfaccia+0x3C.
2. Se il byte `423C24` è nonzero e l'endpoint a contesto+0x14 esiste,
   tenta prima cancel della richiesta fissa `47DA4C` via slot+0x14.
3. Chiama `1910C4` sul contesto.
4. Passa a `158CBC` l'identificatore evento `02200001` e il bit `00010000`.

`1910C4` agisce solo se il byte contesto+0x0C è nonzero. Per ciascuno dei
tre slot endpoint +0x10/+0x14/+0x18 nonnulli chiama close e azzera il
puntatore senza controllarne l'esito; infine azzera il byte +0x0C.
Se il byte era zero salta questa pulizia; cancel precedente ed evento
possono comunque avvenire.

Close attraversa `278770 → 27958C`: per endpoint valido `279568` drena
la coda tramite `2794D0`, poi `2DBE4C` esegue la parte di disabilitazione
controller. Seguono azzeramento associazione, eventuale flush IN `2DA218`
e pulizia dei bit software. Gli errori inferiori non vengono propagati
dalla sequenza di classe provata.

## Matrice CPU e proprietà degli oggetti

Per ciascun maxpacket 64/512 il banco prova 32 combinazioni: otto maschere
dei tre endpoint, close abilitata/disabilitata e pre-cancel abilitato/
disabilitato. Aggiunge endpoint non aperto e flush IN bloccato:
**34 × 2 = 68 scenari**. I tre endpoint sono IN1, OUT1 e IN2, con un nodo
per endpoint presente.

| Osservazione | Risultato nel banco |
|---|---|
| Notifica classe | 68 ingressi a `19199C` e 68 a `1910C4` |
| API close | 54 chiamate, di cui 4 su endpoint non aperto |
| Close che raggiungono drain/controller | 50 |
| Completamenti della nuova sequenza | 58: 16 da cancel, 42 da drain |
| Rilascio nodi | 58, ciascuno dopo il proprio callback |
| Evento fixture | Uno per scenario, dopo i drain eventualmente eseguiti |
| Event-set fixture restituisce -9 | 34 scenari; wrapper pubblico ritorna comunque 0 |
| Flush IN bloccato | Due scenari; 10.001 letture e 10.001 delay richiesti ciascuno |

Durante i callback il lock modellato è rilasciato, il nodo è ancora
posseduto, count dispositivo non ancora decrementato e bit di abilitazione
endpoint nel registro fixture ancora asserto. Al free del nodo il lock è
acquisito e count già decrementato. Solo dopo il drain close disabilita
l'endpoint. L'evento avviene a lock rilasciato, con contesto e richiesta
di classe ancora vivi.

Con close disabilitata, endpoint e nodi non cancellati restano pendenti
anche dopo l'evento. Il banco li mantiene vivi e separa gli scenari con
reset delle fixture: questo reset non prova cancellazione Nikon. Con close
abilitata, dopo il drain segue anche deregistrazione/shutdown originale
con count zero. La regressione conserva i due precedenti casi avversi
di free di richiesta pendente e li ferma prima di altri IRQ.

## `actual` nei completamenti di errore

I callback ricevono status -54 per cancel e -58 per drain. Nei 58 casi
richiesta+36 diventa `A5A5A5A5`, mentre era stata azzerata prima del submit.
È il seed dello storage del nodo allocato: `2794D0` carica nodo+16 e lo
passa al bridge `278AA4`, che lo scrive in richiesta+36 anche su errore.

Non è conservazione del precedente `actual` della richiesta né un conteggio
DMA misurato. A5 è deliberatamente sintetico: prova che nei percorsi testati
**con status nonzero non si può usare `actual` come numero di byte
trasferiti**. Il trasporto AkeruRAM già arresta il riuso dei buffer sugli
errori; il binding deve ancora stabilire quando l'hardware cessi di usarli.

## Primo confine del passaggio evento/task

L'esecuzione CPU usa ancora una fixture per `158CBC`. Un controllo statico
separato dei byte V1.1 mostra il percorso originale:

- `158C8C` cerca l'ID in record da 0x38 byte a partire da `372A48`,
  controlla magic `45564E4C` e bit 31 del campo +8. I due errori locali
  sono `00200307` e `00200304`.
- `158CBC`, su lookup riuscito, passa record+0x0C e bit a `23C758`, poi
  chiama `17B770` per trattare il risultato.
- `23C758` combina i bit con il campo +0x18 dell'oggetto e contiene anche
  percorsi che elaborano liste di attesa e stato scheduler tramite `369348`.

È analisi statica, non esecuzione del lookup/setter o risveglio di task.
Il -9 iniettato nei 34 scenari non rappresenta uno specifico errore
dell'API originale. Prossimo passo: sostituire questo confine con lookup/
event-set originali, poi seguire il consumatore, distinguendo aggiornamento
bit, risveglio, ritorno dal callback e quiescenza controller.

## Regressione e limiti

PASS host ASan/UBSan e 36 vettori di guardia GNU, oltre ai 36 scambi
integrati con risposte identiche a Python. Totali dell'intero eseguibile:
172 submit iniziali, 130 completamenti/free, 233 chiamate del callback
device registrato. La regressione del protocollo è separata dai nuovi
scenari close: non è ancora un servizio AkeruRAM avviato dal normale ciclo
della classe Nikon.

Sono fixture allocator/free, lock, MMIO/flush, capability/residui, delay,
registrazione/consegna IRQ, event-set e callback applicativi delle richieste.
Modello DSP GNU preesistente provvisorio; 128 MiB sintetici non sono una
mappa RAM fisica. Non provati callback rientranti durante close, più nodi
per endpoint nei nuovi scenari, SG/PIO in chiusura, scheduler reale,
cache/barriere o arresto DMA su disconnessione fisica.

Restano binding evento/task e USB, whitelist fisica, residenza, boot e
recupero. Nessun dumper, flash, reset USB o comando NAND/vendor/SD eseguito.
**NON_INSTALLARE** invariato; obiettivo dump RAM aperto.
