# S33 — oggetto di trasferimento e rilascio comune

Analisi statica V1.1, 18 ottobre 2026. Continuazione dei [percorsi dati SD](S33_SD_Registri_Comando_e_Percorsi_Dati.md). Nessuna esecuzione hardware.

## Risultato

Il servizio **`0x2C0E70`**, chiamato dal percorso dati dopo le notifiche selezionate, è un **salto diretto a `0x2C0C84`**, la routine usata anche sui rami d'errore. Non è una verifica di persistenza separata: entra nello stesso percorso di disattivazione e rilascio dell'oggetto.

Ricostruiti la pubblicazione dell'oggetto, il ramo di rilascio del primo oggetto fisso e l'azzeramento della cella handle del chiamante. Queste operazioni dimostrano il passaggio software di proprietà, ma non bastano ancora a dimostrare che ogni errore lasci il motore fermo e il buffer riutilizzabile. Circa 10% funzionale invariato.

## 1. Pubblicazione dell'oggetto

Nel tratto finale **`0x2BFF26..0x2BFF34`** del servizio `0x2BFE88`, il codice inizializza l'oggetto selezionato in r2:

| Campo | Valore osservato |
|---|---|
| +0 | `0x000F4240`, dal pool `0x2C00BC`; significato ancora non attribuito |
| +4 | Parametro conservato in r15, derivato dal quarto argomento del servizio |
| +8 | Parametro conservato in r14 |
| +`0x0C` | Parametro conservato in r13 |

Poi salva **il puntatore all'oggetto nella cella di uscita** ricevuta dal chiamante. Non è una copia dell'intero oggetto sullo stack.

I pool del selettore di risorse comprendono gli indirizzi **`0x512C5C`, `0x512C80`, `0x512CA4`**, separati da `0x24`. La presenza di questi tre indirizzi non viene presentata come prova di una capacità universale del motore; la selezione completa dell'allocatore resta aperta.

## 2. Alias di rilascio e argomento indiretto

**`0x2C0E70`** contiene soltanto un salto a **`0x2C0C84`**. Quest'ultima conserva il primo argomento in r15 e legge **`r13 = [argomento]`**. Il chiamante deve quindi passare **l'indirizzo della propria cella handle**.

Nel percorso SD quel parametro è l'indirizzo della cella sullo stack, come già verificato nei siti `0x3041EC`, `0x3041F4` e `0x30427A`. È distinto dal buffer dati e dall'indirizzo della porta MMIO. La stessa routine può essere raggiunta da un'uscita di completamento oppure da un tentativo di interruzione.

## 3. Ramo del primo oggetto fisso

`0x2C0C84` confronta il puntatore dell'oggetto con **`0x512C5C`**. Il ramo corrispondente compie operazioni halfword `.di` sui seguenti indirizzi:

| Indirizzo | Operazione locale ricostruita |
|---|---|
| `0x0FEE0038` | Lettura, impostazione del bit 8, riscrittura |
| `0x0FF00020` | Lettura, cancellazione bit 1 e riscrittura, nel ramo in cui campo oggetto+4 è diverso da `0x10209` |
| `0x0FEE0034` | Scrittura di `0x100`, seguita da chiamata `0x267BC4` |
| `0x0FF00028` | Lettura, impostazione del bit 8 e riscrittura, se campo +4 è diverso da `0x10209` |
| `0x0FEE0508` | Lettura, impostazione bit 0 e riscrittura |

Dopo queste operazioni azzera un flag software attraverso il pool `0x2C0D44` e salta alla coda comune **`0x2C0E58`**. La semantica fisica ufficiale dei registri e il tempo necessario perché il motore si fermi non sono dedotti dalle sole scritture. I rami per gli altri oggetti non sono ancora ricostruiti completamente in questa verifica.

## 4. Coda comune e invalidazione dell'handle

La coda comune usa campo oggetto+4 per chiamare **`0x2C0AFC`**, chiama **`0x179354`**, poi **`0x2C0B84(oggetto)`**. Nei siti osservati non confronta i risultati intermedi prima di continuare.

Alla fine imposta r1=0 e, nel delay slot del salto di uscita, esegue:

```text
0x2C0E6E: [cella_handle_del_chiamante] = 0
```

L'azzeramento non dipende da un confronto locale con il risultato di `0x2C0B84`. Questo non implica che tale helper fallisca: il suo contratto completo resta da analizzare.

Il tratto interno **`0x2C0C7A..0x2C0C84`** azzera **oggetto+4**. La verifica ampliata della sezione 5 collega a questa coda i tre oggetti fissi; il caso con campo già zero esce prima.

Una cella handle nulla indica quindi che il chiamante ha perso quell'associazione. Per considerare il buffer sicuramente riutilizzabile occorre ancora provare il contratto di arresto del servizio e la gestione degli errori; la sola invalidazione della cella non lo dimostra.

## 5. Rilascio interno dei tre oggetti

La continuazione ha ricostruito il corpo di **`0x2C0B84`**, chiamato dalla coda comune. Legge campo **oggetto+4**: se già zero esce con zero. Negli altri casi confronta l'indirizzo dell'oggetto e tratta tre istanze fisse:

| Oggetto | Registro halfword `.di` modificato |
|---|---|
| `0x512C5C` | `0x0FF00028` |
| `0x512C80` | `0x0FF00008` |
| `0x512CA4` | `0x0FF00048` |

Per ognuna la trasformazione è **`nuovo = (precedente & ~7) | 7`**, con troncamento a halfword. Dopo la scrittura, i rami convergono verso **`0x2C0C7C`**, che azzera oggetto+4 nel delay slot prima dell'uscita. Anche l'indirizzo non corrispondente alle tre istanze può raggiungere l'azzeramento; non c'è qui una validazione completa di un puntatore arbitrario.

I primi due oggetti hanno ulteriori decisioni basate su un record globale a **`0x406AF4`**: byte +8 e parola +0 confrontata con il selettore dell'oggetto. Alcuni rami chiamano **`0x1594A4`** con costanti dai pool (`0x01E00001`, `0x01E00002`). Il terzo considera anche selettore **`0x10208`** e può usare `0x01E03D70`. Il loro significato completo non è assegnato in questa verifica.

Il risultato di `0x1594A4` non viene confrontato prima di azzerare campo +4. Non viene affermato un ritorno zero universale: i rami senza quella chiamata e quelli che la attraversano possono lasciare valori diversi nel registro di ritorno. La coda esterna, già verificata, azzera comunque la cella handle senza un confronto locale.

Nel corpo di questo rilascio non compare polling di completamento né una rilettura del registro modificato dopo la scrittura finale. La scrittura può avere una semantica hardware di comando/riscontro ancora da attribuire: l'assenza di polling non dimostra un guasto né prova da sola l'arresto fisico.

## 6. Le chiamate attorno alle scritture sono una sezione critica

Le routine **`0x1786E8`** e **`0x179354`** usano il contesto kernel pubblicato a **`0x369348`**. La prima incrementa un contatore nella struttura letta da kernel+`0x1C`, campo +`0x68`; se entra dal livello zero carica una halfword di configurazione ed esegue **`flag`**. Conserva inoltre il punto di chiamata in un ramo condizionale.

La seconda decrementa lo stesso contatore; soltanto quando arriva a zero esegue **`flag`** con una halfword selezionata dallo stato kernel. Non interroga i registri del controller dati. Le istruzioni dimostrano un protocollo di **sezione critica annidata e ripristino dei flag CPU**, non un'attesa dell'arresto del motore.

Questo restringe il punto aperto: il rilascio serializza le modifiche software/MMIO e invalida l'associazione, ma la garanzia di arresto deve derivare dal contratto hardware di quelle scritture o da altre verifiche del chiamante. Restano da analizzare il servizio avvio/completamento e gli altri rami della routine esterna `0x2C0C84`.

## Evidenze e continuazione

[Script](../Python_Trace_Scripts/s33_trace_transfer_release.py), [JSON](../Ghidra_Results/ghidra_reports/transfer_release/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/transfer_release/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_transfer_release.py`.

Verificati **16 SHA-256**, roundtrip ELF del blocco 00, **17 finestre, 17 collegamenti e 36 istruzioni chiave**, oltre ai pool dell'oggetto e MMIO. Le finestre escludono i pool non eseguibili e ripartono dai target di controllo verificati.

Prossimo: completare gli altri rami della disattivazione esterna, attribuire `0x1594A4` in questo contesto e ricostruire avvio/avanzamento/completamento del servizio `0x2C00E4`. Nessuna prova di persistenza fisica o modifica della fotocamera.

## Continuazione — oggetti di ricezione originali

[S33_Dumper_RAM_SD_Oggetti_Ricezione_Acquisizione_e_Rilascio.md](S33_Dumper_RAM_SD_Oggetti_Ricezione_Acquisizione_e_Rilascio.md):18casi2801F0/27FCD4/281158/281064 e21caller25A83C collegati all'oggetto512CC8,regressione21PASS. Tre oggetti receive512CC8/512CEC/512D10 distinti dai precedenti oggetti write512C5C/512C80/512CA4;release consumaid+4 ehandle anche con errorepost. Le releasefixture precedenti non descrivono questo contratto reale. Earlycallback-error lasciarecord nonripulito,senza prova di leakglobale o avviofisico. Avvio28080C/progress266E9C,semafori/eventi e hookstop restano daeseguire. NON_INSTALLARE,nessunhardware.

## Continuazione — primo oggetto write eseguito

La [verifica write da36casi](S33_Dumper_RAM_SD_Scrittura_Asincrona_e_PIO_Originali.md) esegue2BFE88/2BFAF8/2C00E4 e2C0C84/2C0B84 per512C5C. Nel percorso ordinario provato questo primo oggetto usa **1E00000**,record374300;acquiredecrementa iltoken e releaseconpostlo ripristina1,azzera oggetto+4 ehandle. La menzione storica dei pool1E00001/2 non era un elenco completo delle risorse. Il gruppo esegue anche il callbackB tramite36B3D8/2689FC. Non dimostra arresto elettrico o persistenzafisica.
