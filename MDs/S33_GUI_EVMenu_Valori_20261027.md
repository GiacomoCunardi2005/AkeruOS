# S33 V1.1 — EVMenu: eventi, indici e scritture candidate

27 ottobre 2026. Analisi statica offline dei payload originali e confronto con
`DUMPS/MainCode.dmp`. Gli indirizzi usano la mappa candidata V1.1 del progetto;
non attribuirli alla V1.0 fisica. Nessuna operazione su fotocamera o SD.

Il descrittore `EVMenu` (ID `0x06`) usa il wrapper `0x7C7B7C` e la tabella
`0x980598`. L'evento `0x4401` chiama `0x7C7BB4`, che scrive `r2` nella
parola `0x8997C4`. Le tre voci di `ChangeColorMenu` individuate nella
[precedente analisi](S33_GUI_ChangeColorMenu_Voci_20261027.md) possono
richiedere `EVMenu` con argomenti 0, 1 e 2. Il seguente collegamento vale
**se** il gestore recapita l'argomento invariato come `r2` e la parola non
viene cambiata prima della gestione dell'evento.

| Modo / testo candidato | Indice GUI | Effetto staticamente ricostruito sul percorso di aggiornamento |
| --- | --- | --- |
| 0 — Più chiaro/più scuro | halfword `0x8997CC` | `0x7C8104` → `0xCC7DC` legge la tabella signed a `0x3788B0`: indici 0–4 → 2000, 1000, 0, -1000, -2000. `0xCE1EC` scrive il risultato come halfword a `0xC8EC52` e chiama altri servizi. Unità fisica e uso finale non verificati. |
| 1 — Più vivace/meno vivace | halfword `0x8997D0` | `0x7C8150` → `0x1316F8` mappa indici 0–4 ai codici 10, 6, 0, 5, 9. `0x17E36C` scrive il codice come byte a `0x367C06`; dopo il ritorno `0x1FCE58` scrive 1 a `0x3695CE`. Le successive chiamate possono avere altri effetti. |
| 2 — Seleziona colore | halfword `0x8997D4` | `0x7C8190` → `0xD1138` scrive il byte basso dell'indice a `0xC8EB5A`. Il codice lo rilegge, chiama `0x1421AC`, lo rilegge ancora e passa a `0x191B58` zero se il valore letto è zero, altrimenti il valore letto più uno; `0x191B58` lo scrive come word a `0x3681DC`. Non si assume che il valore sia rimasto invariato attraverso i servizi. |

La tabella eventi associa `0x0480` a `0x7C7EF8` e `0x0500` a `0x7C7F70`.
Per i modi 0 e 1, nell'intervallo iniziale 0–4, la prima routine incrementa
con ritorno a 0 dopo 4; la seconda decrementa con ritorno a 4 da 0. Per il modo
2 la seconda passa da 0 a 12, altrimenti decrementa; la prima invoca
`0x3341E4` con indice + 1 e divisore candidato 13 e salva `r1`. Non si afferma
qui la semantica dell'helper o il comportamento di incremento del modo 2.
Questi sono handler di eventi interni: l'associazione a un tasto fisico e
il loro recapito non sono dimostrati da questa verifica.

Il percorso modo 0 scrive un valore numerico collegato al testo candidato di
luminosità, ma non dimostra che quel numero rappresenti EV in un'unità nota.
Il percorso modo 1 usa codici discreti: non dimostra un interruttore standard/
monocromatico RAW. Per modo 2 la parola scritta non dimostra il colore
visibile o il trattamento dei dati del sensore. Non sono provati effetti su
preview, JPEG, RAW, persistenza o i valori effettivamente mostrati.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_gui_evmenu_values.py`.
**PASS_STATIC_BOUNDED**: [istruzioni GNU](../Risultati/GUI_S33/evmenu_values_20261027T213833Z/disassembly.txt),
[risultati e intervalli verificati](../Risultati/GUI_S33/evmenu_values_20261027T213833Z/evidence.json),
[verificatore](../Python_Trace_Scripts/s33_verify_gui_evmenu_values.py). Le
istruzioni e i dati sono confrontati col dump; non sono stati eseguiti gli
handler né osservate le scritture su hardware. I candidati restano
**NON_INSTALLARE**.
