# S33 V1.1 — eventi e guardie di HintMessage

Analisi statica offline del 27 ottobre 2026. L'oggetto `HintMessage`, ID `0x9E`, usa la tabella eventi a `0x9819C8`. I record seguenti sono confrontati con `MainCode.dmp`; il record finale con chiave zero punta a `0x20E814`.

| Evento | Handler | Comportamento locale osservato |
| --- | --- | --- |
| `0x4405` | `0x7C97A4` | Può raggiungere la selezione dell'indice JPEG 14, con le guardie sotto. |
| `0x4406` | `0x7C9A9C` | Chiama `0x15B044`; se restituisce zero chiama `0x15B024`, poi altri servizi. |
| `0x440E` | `0x7C9ADC` | Ritorna senza altre chiamate. |
| `0x0300` | `0x7C9B04` | Legge la proprietà `0x12`: se vale 7 chiama `0x1453E4(7,0)`; se anche il byte `0x89980D` è 1, prima chiama `0xCAFF8(3)` e `0xCAD38(1)`. |
| `0x0600` | `0x7C9B44` | Chiama `0x136284(1)` e inoltra i tre argomenti originali a `0x20E814`. |
| `0x4005` | `0x7C9B6C` | Chiama `0xCAD30`: se ritorna 3 seleziona `0x7E`; altrimenti lo richiama e seleziona `0x87` se ritorna `0x2C`, o 1 negli altri casi. Passa l'ID a `0x1453E4` e poi a `0x169F40`. |
| `0x5000` | `0x7C9AF0` | Ritorna senza altre chiamate. |

Per `0x4405`, se `0x12845C` restituisce un valore diverso da zero, il codice salta all'uscita senza chiamare `0x7C9BBC`. Altrimenti compie le operazioni intermedie sui componenti e interroga `0x14504C` con il contesto e parametro `0x12`: se ottiene 7 chiama `0x7C9BBC`, che passa l'indice costante 14 a `0x7C9BF0`. Se la prima lettura non è 7, il codice interroga **nuovamente** la stessa proprietà e, se questa seconda lettura vale `0x58`, segue un percorso distinto senza quella chiamata. Non assumiamo che le due letture diano lo stesso risultato.

L'ID selezionato nell'evento `0x4005` è un argomento per i servizi `0x1453E4` e `0x169F40`, non un indice JPEG dimostrato. Non è stata ricostruita una mappatura degli altri 17 JPEG a eventi o schermate; il codice locale verificato qui dimostra soltanto il percorso condizionale dell'indice 14. Base della sorgente, recapito degli eventi, esito dei servizi, lettura effettiva e visualizzazione restano ignoti.

Il [verificatore](../Python_Trace_Scripts/s33_verify_gui_hint_events.py) confronta la tabella e le finestre di codice originali col dump e verifica le principali istruzioni dei rami. [Esito e disassemblati](../Risultati/GUI_S33/hint_events_20261027T171534Z/). È una verifica statica circoscritta, non un'esecuzione degli handler né una prova di assenza di chiamate indirette.
