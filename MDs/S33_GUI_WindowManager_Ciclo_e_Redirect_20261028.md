# S33 V1.1 — ciclo WindowManager e deviazioni

28 ottobre 2026. L'analisi statica confronta i byte di 11 finestre GNU e dei letterali con `DUMPS/MainCode.dmp`. Le conclusioni riguardano il firmware V1.1 e i rami descritti: non è stata eseguita una transizione reale.

`0x1453E4(id, arg)` risolve l'ID mediante `0x14507C` e passa il descrittore e l'argomento a `0x145180`. Quest'ultimo può terminare subito, fra l'altro se il descrittore è nullo, ha il bit 0 del primo campo impostato o il byte di guardia a `0x366E94 + 39` è nonzero. I due puntatori alle posizioni `0x366E94 + 0x10` e `+ 0x14` sono usati e modificati in rami distinti. Il primo viene letto come oggetto precedente all'inizio e può ricevere il nuovo descrittore; il secondo viene consultato e aggiornato condizionalmente. Queste evidenze **non dimostrano una pila generale di schermate** né che il precedente sia sempre il menu da recuperare.

Le chiamate a `0x169D78` nella routine, in base ai flag e ai percorsi, includono:

| Evento | Destinatario e argomento osservati nel ramo | Nota |
| --- | --- | --- |
| `0x4403` | Nuovo descrittore, argomento = precedente | La risposta può determinare una deviazione prima delle ulteriori notifiche. |
| `0x4404` | Precedente, argomento = nuovo | In un ramo il risultato `-1` interrompe la transizione. |
| `0x4406` | Precedente, argomento = nuovo | Dipende dai flag; altre chiamate allo stesso evento hanno condizioni proprie. |
| `0x4402` | Precedente, argomento zero | Chiamata condizionata dal bit 8 del primo campo. |
| `0x4401` | Nuovo, argomento = valore passato a `0x1453E4` | In quel ramo il nuovo descrittore viene poi scritto a `+0x10`. |
| `0x4405` | Nuovo, argomento = precedente o puntatore `+0x14`, secondo flag | La risposta può determinare un'altra deviazione. |

Non si tratta di una sequenza universale: i rami dipendono dai bit 7, 8 e 9 dei descrittori, dai puntatori e dai ritorni dei destinatari. Il ciclo può anche inviare `0x4414` o `0x4415` e gestire una deviazione dopo `0x4405` con ulteriori notifiche `0x4406` e `0x4402`. Ordine effettivo, filtri di `0x169D78` e stato concorrente non sono osservati.

## Interpretazione delle risposte

Dopo le chiamate `0x4403` e `0x4405`, `0x14510C` interpreta la word di ritorno. Se è diversa da `-1`, usa i 16 bit bassi con segno come ID per `0x14507C` e la metà alta con segno come argomento; un descrittore risolto può diventare una destinazione successiva. Se la risposta è `-1`, il descrittore precedente viene proposto con argomento zero **solo se è non nullo e il suo bit 9 è zero**; altrimenti la destinazione prodotta rimane nulla. I successivi salti dipendono anche dall'esito della risoluzione. La presenza di questo meccanismo non prova che i callback delle schermate desiderate lo usino, né che sia disponibile un punto sicuro per introdurre un nuovo callback.

Le schermate diagnostiche ISO e tempo, nelle prove già svolte, chiedono esplicitamente `0x1453E4(0x36,0)` in uscita; l'oggetto `0x36` è `DEBUG MODE MENU`. Il meccanismo di redirect qui individuato **non sostituisce automaticamente** quella richiesta: servirebbe verificare i callback e i flag effettivi della transizione prima di scegliere un percorso di ritorno per un nuovo menu. Vedi [uscita diagnostica](S33_GUI_Debug_Esposizione_Uscita_20261027.md).

## Riproduzione e limiti

`python3 Python_Trace_Scripts/s33_verify_gui_window_lifecycle_static.py` ha prodotto [risultato PASS e hash](../Risultati/GUI_S33/window_lifecycle_static_20261028T090124Z/evidence.json) e [disassemblaggio](../Risultati/GUI_S33/window_lifecycle_static_20261028T090124Z/gnu_windows.txt). Il [verificatore](../Python_Trace_Scripts/s33_verify_gui_window_lifecycle_static.py) verifica 35 istruzioni e i letterali; l'interpretazione dei rami è statica e non costituisce una prova del comportamento in esecuzione. Non sono verificati registrazione della tabella runtime, visualizzazione, callback reali, concorrenza o hardware. Nessuna modifica a firmware, GNU, fotocamera o SD. **NON_INSTALLARE**.
