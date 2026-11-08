# S33 — acquisizione corrente, trasferimenti e reset della configurazione

Analisi statica del 18 ottobre 2026, V1.1. Continuazione degli [errori di acquisizione](S33_Errori_Acquisizione_e_Recupero.md). Non è stato eseguito codice sulla fotocamera.

## Risultato

Il campo **`0x368040`**, acquisizione corrente, viene azzerato nel reset del contesto e nella pubblicazione verso la coda B. È stato collegato un percorso di riconfigurazione **`0x1435FC → 0x18E41C`** all'ingresso AutoScene: offre un possibile raccordo dopo il ritorno da CaptureQV, ma soltanto se configurazione e guardie lo consentono. Se la configurazione richiesta coincide con quella corrente, il reset viene saltato.

Sono inoltre distinti alcuni falsi alias: le scritture a `r14+0x1C` nei preparatori/finalizzatori ImgMgr possono riferirsi al **contesto del worker ricevuto in argomento**, non al globale risorse. Non sono quindi prove di restituzione dell'acquisizione corrente.

Il recupero completo dell'errore «buffer estratto, descrittore non disponibile» rimane aperto. Non si deduce una perdita di risorse, né che il cambio di configurazione costituisca una procedura da chiamare liberamente. R2 parziale; avanzamento funzionale circa 10%, invariato.

## 1. Scritture verificate al campo corrente

La base risorse `C = 0x368024` compare in sette letterali LE32 del blocco 00, verificati a `0x18E4AC`, `0x18E5D8`, `0x18EA4C`, `0x18EE48`, `0x18F220`, `0x18F30C`, `0x18F7A4`. Il campo corrente è `C+0x1C`.

| Sito | Provenienza ed effetto locale |
|---|---|
| `0x18E452` | Nel reset `0x18E41C`: base caricata in `r14` dal letterale `0x18E4AC`, valore zero in `r13`; azzera corrente, elaborazione corrente, pool attivo e altri campi |
| `0x18E592`, `0x18E5AA` | Nel preparatore pool `0x18E4B4`: rami finali con stato zero e conteggio buffer nonzero azzerano i due puntatori correnti; il ramo iniziale pool già attivo salta questi reset |
| `0x18E94E` | In `0x18E8FC`: azzera corrente soltanto dopo un'estrazione da A fallita; l'estrazione viene tentata soltanto se corrente era già nullo |
| `0x18EA38` | In `0x18EA10`: dopo un tentativo di pubblicazione del nodo corrente in B, azzera corrente anche se il servizio di pubblicazione restituisce errore |
| `0x18EE6A` | In `0x18EE50`: se memoria esterna nulla e corrente presente, tenta la pubblicazione in B e azzera corrente senza condizionare l'azzeramento al risultato |

L'estrazione in `0x18ED60` scrive anche il campo tramite un puntatore di uscita: `0x18EDB6` costruisce `&C->current`, poi `0x18EDBC` lo passa a `0x18E8B4`. Analogamente `0x18E942/46` passa l'indirizzo del campo direttamente al servizio coda. La tabella delle sei scritture dirette non esaurisce quindi gli scrittori indiretti.

**Limite di `0x18E8FC`:** quando trova un corrente nonzero lo restituisce senza sostituirlo. Il suo azzeramento su errore di estrazione non spiega il recupero del corrente già conservato dopo riserva descrittore fallita.

## 2. Pubblicazione e ritorno del buffer sono passaggi differenti

`0x18EA10` sincronizza con `0x40100001`, verifica pool attivo e corrente nonzero, invia il nodo alla coda **B** tramite `0x27722C`, azzera il corrente e restituisce il risultato conservato della pubblicazione. La presenza di una sincronizzazione non prova che ogni chiamata abbia acquisito con successo il lock: il suo risultato non viene usato come guardia locale.

`0x18EE50` realizza il passaggio già associato alla fine dell'acquisizione, mediante il wrapper `0x18E9D0`. In entrambe le routine, l'azzeramento da solo non certifica che il nodo sia entrato nella coda destinazione.

Il riciclo **`0x18F66C`** è invece un altro flusso:

```text
0x18F68A: estrae dalla coda B in C+0x20 (elaborazione corrente)
0x18F698: pubblica quel nodo nella coda A
0x18F6A4: solo dopo successo azzera C+0x20
0x18F6AA: richiede evento risorse, maschera 16
0x18F6B2: tenta chiusura ordinaria tramite 0x141D80
```

Non azzera `C+0x1C` nel corpo esaminato. Non è un recupero già dimostrato dell'acquisizione corrente. L'inventario di chiamate dirette descritto sotto non ne individua chiamanti: non viene interpretato come prova di codice inutilizzato.

## 3. Reset collegato al cambio di configurazione

Il corpo **`0x1435FC..0x1436A2`** conserva la configurazione richiesta in `r13` e legge quella corrente dal campo +8 di un altro contesto. La sequenza è:

1. `0x143614/16`: se richiesta e corrente sono uguali, salta a `0x143696`, evitando attesa, scarto e reset.
2. `0x143618 → 0x15A5C8`: attesa ImgMgr. Il ritorno non viene confrontato prima del seguito.
3. `0x143620 → 0x141DD0`: tentativo di scarto, con indirizzo di un byte locale di uscita. Nel seguito locale non vengono confrontati né il ritorno né quel byte.
4. `0x143624`: scrive la nuova configurazione nel campo +8.
5. Dopo un ramo aggiuntivo con servizi non ricostruiti per intero, seleziona il conteggio descrittori, lo scrive tramite `0x18E1AC` e chiama **`0x18E41C`** con regione 8, `0x5C` oppure `0x50`.

`0x18E41C` azzera corrente e gli altri campi **prima** delle successive richieste relative alla regione. Non conserva il vecchio puntatore come transazione di rollback nel corpo esaminato. Questo descrive l'ordine originale e non autorizza a forzarlo su un sistema ancora occupato.

### Conteggi dei descrittori

| Configurazione nel ramo di riconfigurazione | Helper costante | Conteggio | Regione passata al reset |
|---|---|---:|---|
| 0 | `0xC6440` | 12 | 8 |
| 2 | `0xC6448` | 9 | `0x5C` |
| Altra | `0xC6444` | 11 | `0x50` |

Non sono capacità universali. Il sito del blocco 02 **`0x655330`** scrive anche **20** quando il secondo discriminante restituito da `0xCA38C(1)` vale 2; negli altri rami sceglie 12 o 11. Un altro sito `0x65AD96` seleziona 12 o 11. Le chiamate e i valori sono verificati nelle finestre dedicate.

Il limite di 20 elementi della coda buffer e il conteggio descrittori sono variabili distinte. Questi risultati non provano un'uguaglianza, né un invariante sufficiente a escludere riserva fallita dopo estrazione.

## 4. Collegamento con AutoScene e con l'errore `0x7CE2`

Il [rapporto CaptureImage, sezioni 8–9](S33_CaptureImage_Completamento_e_ImgMgr.md) collega condizionalmente l'errore nello stato 0 a CaptureQV e poi, tramite timer, alla richiesta di AutoScene. Nell'ingresso AutoScene sono ora verificati due siti ulteriori:

- **`0x659734 → 0x1435FC(2)`**, nel ramo modalità `0x2C`, flag letto da `0xD0924` nonzero e primo discriminante diverso da 7. Precedono l'attesa `0x659728 → 0x15A5C8` e una chiamata a `0x2019C0(1)`, i cui effetti completi non sono stati ricostruiti qui.
- **`0x659800 → 0x1435FC(0 oppure 1)`**: il valore è normalizzato dal risultato di `0xCFE18`, con 1 solo quando quel risultato vale 1. Il ritorno della riconfigurazione viene poi sovrascritto con zero a `0x659804`.

Questo fornisce un **possibile percorso condizionale di reset dopo il ritorno alla ripresa**, non un recupero universale: se configurazione richiesta e corrente coincidono, `0x1435FC` non esegue quel reset. Restano inoltre guardie, servizi intermedi, consegna eventi e risultati non controllati. La sola transizione all'oggetto AutoScene non prova disponibilità di un nuovo scatto.

## 5. Alias da non confondere con il globale

In `0x18EE98`, `r14` riceve il **primo argomento del preparatore ImgMgr**, mentre i riferimenti al globale risorse vengono caricati separatamente dai letterali. Le scritture `0x18EF2E` e `0x18EF6A` a `r14+0x1C` aggiornano quindi il contesto di elaborazione ricevuto. La stessa distinzione vale per `0x18F29C`, nel finalizzatore `0x18F260`.

Non si può attribuire una scrittura al globale soltanto perché l'offset è `0x1C` o il registro base si chiama `r14`. Questa correzione impedisce di chiudere erroneamente il recupero di `0x368040` con un'operazione su un'altra struttura.

## 6. Indirizzo della configurazione e predicato 0/1

La continuazione risolve il contesto della configurazione a **`0x366E24`** e il campo parola +8 a **`0x366E2C`**. Il caricamento scalato `0x14360E` usa il letterale `(PC & ~3) - 130*4 = 0x143404`; il getter **`0x1436A4`** usa invece il puntatore diretto conservato a `0x1436AC`. La scrittura del valore richiesto avviene a `0x143624`, prima del reset. Il campione del blocco 01 contiene inizialmente zero a `0x366E2C`: è un dato dell'immagine, non una lettura della RAM sulla macchina.

La ricerca delle parole LE32 nei 16 payload trova cinque letterali con base `0x366E24` e uno con l'indirizzo diretto `0x366E2C`. Non costituisce una prova di unicità dello scrittore: indirizzi calcolati, copie e scritture indirette restano fuori da quel criterio di ricerca.

Il predicato **`0xCFE18`**, usato dai chiamanti che richiedono configurazione 0/1, restituisce zero quando il byte letto da `0x15AD44` a **`0x367390`** vale 1 oppure quando il controllo logico `0x66`, letto tramite `0x16F920`, è nonzero. Il secondo accesso legge precisamente il byte **`0x446808 + 4*0x66 = 0x4469A0`**, nel delay slot del ritorno; non viene attribuito a un pulsante fisico.

Altrimenti confronta la modalità con `0x2C`, `0x6D` e `0x7D`, restituendo 1 nei rami corrispondenti e zero negli altri. Le letture della modalità sono ripetute: una formula equivalente basata su una sola lettura richiederebbe stabilità durante la chiamata.

| Chiamante verificato di `0x1435FC` | Argomento osservato |
|---|---|
| `0x13902C` | 0 |
| `0x6528E8` | 1 se `0xCFE18()` restituisce 1, altrimenti 0 |
| `0x659734` | 2 nel ramo AutoScene speciale |
| `0x659800` | 1 se `0xCFE18()` restituisce 1, altrimenti 0, nell'altro ramo AutoScene |
| `0x664C76` | 2, dopo richieste con valore modalità `0x21`; nome della modalità non attribuito qui |
| `0x7C9448` | 0, dopo un altro tentativo di scarto |

I sei siti, prima candidati della scansione lineare, sono ora verificati nelle finestre ancorate. I servizi intermedi possono ancora cambiare stato o imporre condizioni ulteriori.

## 7. I due rami AutoScene non garantiscono due reset successivi

Il ramo che raggiunge **`0x659734`** procede attraverso servizi e controlli fino a uscite verso `0x659804`, `0x659B14` oppure `0x659EE0`; il tratto locale esaminato non cade nel ramo `0x6597C2..0x659800`. Quest'ultimo è invece selezionato quando le guardie precedenti evitano il ramo speciale.

In particolare, sono controllati i salti da `0x659764`, `0x659770`, `0x6597A2` e `0x6597B4` verso `0x659804`, e il ritorno interno `0x6597C0 → 0x659758`. Questo esclude l'interpretazione locale «richiede 2 e poi sicuramente richiede 0/1». Non è un'analisi completa dei cicli esterni dell'oggetto.

La conseguenza resta concreta: un ingresso speciale con configurazione già 2 può evitare il reset; un ingresso nell'altro ramo con configurazione già uguale al predicato può fare lo stesso. Non è provato che tali combinazioni coincidano con l'errore di esaurimento; occorre seguire gli invarianti di ammissione allo scatto.

## 8. `0x2019C0` non restituisce il buffer nel suo corpo

La routine completa **`0x2019C0..0x2019DC`** non contiene chiamate e scrive soltanto:

```text
byte[0x369634] = byte basso dell'argomento r0
byte[0x369635] = 0xFF
```

Il letterale scalato è a `0x20188C = 0x369624`; il getter `0x2019DC` legge direttamente `0x369634`. I byte iniziali nel payload sono `00 FF`.

AutoScene chiama questa routine con 1 prima della richiesta configurazione 2 e con 0 nell'altro ramo. Il setter non azzera `0x368040`, non tocca le code e non invoca un'altra routine di pulizia nel corpo completo verificato. Rimangono da attribuire consumatori e significato dei due byte: eventuali effetti successivi tramite altri task non sono esclusi.

Verifica aggiuntiva: [script configurazione](../Python_Trace_Scripts/s33_trace_resource_configuration.py), [JSON](../Ghidra_Results/ghidra_reports/resource_configuration/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/resource_configuration/gnu_verified.txt). **16 hash, 3 roundtrip ELF, 13 finestre, 13 chiamate e 13 istruzioni selezionate controllate**. La conclusione negativa sul setter riguarda l'intero corpo, non un campione.

## Evidenze, copertura e prossimo passo

[Script](../Python_Trace_Scripts/s33_trace_current_acquisition.py), [JSON verificato](../Ghidra_Results/ghidra_reports/current_acquisition/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/current_acquisition/gnu_verified.txt), [candidati di chiamata](../Ghidra_Results/ghidra_reports/current_acquisition/branch_candidates.json), [ricerca puntatori](../Ghidra_Results/ghidra_reports/current_acquisition/pointer_candidates.json).

Riproduzione: `python3 Python_Trace_Scripts/s33_trace_current_acquisition.py`. Verificati dimensioni/SHA-256 dei **16 blocchi**, roundtrip ELF identico per **11 blocchi (00–10)**, **17 finestre mirate**, sei scritture dirette e chiamate selezionate. La scansione lineare conserva **19 candidati** verso sette ingressi selezionati. Soltanto i siti riesaminati nelle finestre dedicate sono promossi a collegamenti verificati. I blocchi overlay 11–15 sono esclusi dalla scansione delle chiamate; non vengono sovrapposti. La ricerca dei sette indirizzi come parole LE32 e ordine mezze parole ARC non trova occorrenze nei 16 payload: non esclude chiamate indirette o puntatori costruiti.

**Prossima verifica:** ricostruire gli invarianti di ammissione allo scatto che evitano corrente già occupato o descrittori esauriti; attribuire i consumatori dei byte `0x369634/35`. Il setter `0x2019C0` è stato escluso come restituzione diretta del buffer nel proprio corpo. Completare esiti worker/scrittura/chiusura e il raccordo con il pronto. In parallelo logico resta aperto il contratto esiti worker/scrittura/close. Le conoscenze statiche non sono ancora un'interfaccia completa per AkeruOS; campione V1.1 e log hardware V1.0 restano distinti.
