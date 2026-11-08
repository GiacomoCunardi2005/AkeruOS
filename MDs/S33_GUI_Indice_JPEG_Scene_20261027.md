# S33 — indice e lettore delle immagini illustrate

Nel firmware V1.1 ho trovato una tabella a `0x981734` che corrisponde esattamente alle 18 immagini da 160×96 della [tavola illustrata](../Risultati/GUI_S33/embedded_jpeg_20261027T113806Z/160x96_contact.png). I record 1–18 contengono coppie di parole **offset relativo, lunghezza**, con passo di 8 byte. Il primo record e il record 19 sono zero. Le 18 immagini sono consecutive nel contenitore e ogni coppia coincide con l'offset relativo alla prima e con la lunghezza del relativo JPEG.

Esempio: indice 1 → offset `0`, lunghezza `2688`; indice 2 → offset `2688`, lunghezza `2914`. Il confronto è stato eseguito su tutte le 18 immagini, sui byte del firmware e della tabella in `MainCode.dmp`.

## Il codice che consulta la tabella

**Seguito:** un percorso condizionale dall'oggetto `HintMessage` raggiunge la routine con indice 14: [analisi del percorso](S33_GUI_HintMessage_JPEG_20261027.md).

La routine originale a `0x7C9E38` controlla l'indice nell'intervallo `0..19`, usa 0 per quelli fuori intervallo e richiede due puntatori non nulli. Carica il puntatore alla tabella dal pool `0x7C9ECC`, calcola il record con passo 8 e scrive la lunghezza nel primo puntatore. Dopo aver ottenuto una sincronizzazione, passa offset, lunghezza e secondo puntatore al lettore `0x159558`, quindi rilascia la sincronizzazione. I casi di errore vengono trattati nel codice; l'intera routine non è stata eseguita in questa verifica.

Il [rapporto precedente sul lettore](S33_Gruppi_C2_C3_C4_Risorse_e_Segnali_Caricamento.md) mostra che `0x159558` usa una base configurabile e può leggere tramite backend differenti. Per affermare che questa routine carichi le immagini illustrate a runtime bisogna ancora dimostrare quale base le venga configurata e chi invochi la routine: la corrispondenza fra tabella e JPEG è una forte evidenza statica, non una prova dell'effettiva visualizzazione o del menu chiamante.

## Evidenze

- [Verificatore della tabella e del lettore](../Python_Trace_Scripts/s33_verify_jpeg_scene_index.py), [18 record](../Risultati/GUI_S33/jpeg_index_20261027T114041Z/evidence.json), [codice originale disassemblato](../Risultati/GUI_S33/jpeg_index_20261027T114041Z/gnu_window.txt).
- [Verifica della sequenza](../Risultati/GUI_S33/jpeg_sequence_20261027T113942Z/evidence.json): i JPEG sono contigui e, nei payload esaminati, i loro indirizzi di caricamento candidati non hanno occorrenze letterali LE32 o ARC LIMM. Non sono escluse altre forme di riferimento.

Nessun test della fotocamera, del backend di lettura o del rendering; nessun firmware modificato o installato. Il passo successivo è risalire ai chiamanti di `0x7C9E38` e alla base usata da `0x159558`.
