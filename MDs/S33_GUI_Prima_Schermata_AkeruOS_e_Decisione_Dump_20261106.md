# Prima schermata AkeruOS nel profilo da dump e decisione sul nuovo dump (fasi 5 e 6)

6 novembre 2026. Fasi 5 e 6 del piano (`goal.txt`). Collegato dal [profilo di emulazione](S33_GUI_Profilo_Emulatore_da_Dump_e_Primo_Disegno_20261106.md). Nessun firmware creato, dump originale intatto (hash controllato prima e dopo), nessun accesso alla fotocamera. Certezza **A** osservato ed eseguito, **B** dedotto, **C** ipotesi.

## Come è fatta una finestra Nikon (nuovo, dal codice del dump)

`0x14505C(finestra)` legge il flag a `+0`: con il bit 0 a zero restituisce la **procedura di finestra a `+0xC`**; con il bit 0 a uno usa una tabella di classe (`0x145020`). `0x16A028(finestra, msg, param)` chiama quella procedura (con un hook `[0x16A134]` prima). `0x169E1C` → `0x169D78` smista gli id `0x4401–0x4409` su gestori predefiniti (pool `0x16A138…0x16A160`) e gli altri id sulla procedura della finestra. La finestra attiva è la cella `0x366EA4`. **A** (disassemblato ed eseguito).

## La prima schermata AkeruOS (fase 5)

`Python_Trace_Scripts/s33_verify_akeru_window_profile.py` costruisce un oggetto finestra AkeruOS (procedura a `+0xC`, flag `+0x40` aperta, `+0x44` selezione, `+0x48` finestra precedente, `+0x4C` rifiuti) e lo fa girare nel profilo con la RAM reale del dump. La procedura gestisce tre messaggi: `0x7001` apri, `0x7002` avanti, `0x7003` chiudi. Il disegno usa il percorso testo Nikon originale `0x186D08` (motore font incluso). Evidenza: `Risultati/Runtime_Kernel/Akeru_Window_Profile/20261106T175735633216Z/` (PASS).

| Prova | Esito | Certezza |
|---|---|---|
| Apertura dal dispatcher originale `0x169E1C` | flag aperta = 1; **la finestra attiva `0x366EA4` diventa AkeruOS**; 4884 pixel scritti | A |
| Riapertura mentre è aperta | **rifiutata** (contatore rifiuti = 1, stato invariato) | A |
| Pressione «avanti» | selezione 0 → 1; marcatore `>` ridisegnato (differenza di 76 pixel; il piano non viene cancellato, quindi il vecchio `>` resta) | A |
| Chiusura | flag = 0; **la finestra attiva torna a `0x783AE8`** (AutoScene LiveView) | A |
| Pila | si ritorna sempre al chiamante, uscita 0 del simulatore in tutte e tre le fasi | A |
| Oggetto kernel `0x1800–0x1C00` | 6 parole cambiano identiche nelle tre fasi (`0x188C`, `0x1890`, `0x1898`, `0x189C`, `0x18A4`, `0x1B94`): puntatori del pool di memoria usati dal motore font quando alloca; nessun campo di scheduler/task toccato | B |

**Buffer grafico interpretabile:** il piano OSD risulta a **8 bit per pixel, 640 byte per riga**; `y` conta mezze righe (per 100 unità di `y` l'indirizzo avanza di 32000 byte = 50 righe da 640) e `x` un pixel per unità (+80 → +80 byte). **Correzione:** il rapporto del profilo stimava 320 byte per riga: era sbagliato (le «righe alternate» erano un'illusione di quel passo). L'origine delle colonne dipende dalla base ignota del piano. Il PNG `Risultati/Runtime_Kernel/Akeru_Window_Profile/20261106T175735633216Z//stage2/menu.png` mostra **«Esposizione», «Colore / Mono RAW», «Impostazioni»** con i marcatori `>`; le tre voci sono distanti 16 righe e le righe quasi si toccano (spaziatura da rivedere).

## Cosa NON è ancora dimostrato

- **Apertura e chiusura dal sistema finestre Nikon:** qui le fa la procedura AkeruOS che imposta e ripristina direttamente la cella `0x366EA4`; non è stata usata un'API del manager (apertura menu/transizione) né il percorso evento `WindowMgr`. Quindi «aperto e chiuso attraverso il sistema di finestre Nikon» è **parziale**: il dispatcher e il percorso di disegno sono Nikon, l'ingresso/uscita no.
- **Eventi reali:** i tasti sono messaggi sintetici (`0x7002`), non `post()` `0x17BC7C` da un task né i messaggi `0x4401…` dei pulsanti.
- `muludw` provvisorio; MMIO, interrupt e scheduler non emulati; la palette dei colori non è decodificata (i valori `1, 2, 35, 161` sono indici); il colore non cambia l'indice scritto, quindi l'evidenziazione è un marcatore e non un colore.
- Il piano pixel è ricostruito da zeri (RAM alta non nel dump); il refresh del display non è emulato.

## Fase 6: decisione sul nuovo dump

**Decisione motivata: sì, un secondo dump mirato, no a 256 MiB.** Serve la regione del piano OSD e dei buffer grafici, **`[0x0F600000, 0x0F700000)` (1 MiB)**, per leggere: base e dimensioni del piano, palette, e confermare l'organizzazione a 640 byte per riga. Evidenze a favore della sicurezza di leggerla: (1) il firmware stesso **scrive** quei byte (il piano è a `0x0F68B39E…`); (2) il test memoria del boot scrive fino a `0x0F700000` (`[0x0F801018]`, 247 punti); (3) non include la riserva alta MMIO da `0x0FE00000`. Prima di costruirlo: cambiare `0x0104064C` (lunghezza) in una v6 e un offset di partenza non fanno parte di `0x16ED40`, che parte da `0x100`; **serve un percorso di dump con intervallo scelto** (adapter nuovo) e il file sarebbe di 1 MiB. L'installazione sulla S33 richiede il consenso esplicito dell'utente e una procedura di recupero; **non fatta**.

## Prossimo

1. Usare `post()` `0x17BC7C` e un messaggio `0x4401…` per far arrivare i tasti, e un'API Nikon per aprire/chiudere (dal rapporto sulla coda messaggi).
2. Cancellare il rettangolo prima di ridisegnare (funzione di riempimento Nikon da trovare).
3. v6 mirata `[0x0F600000, 0x0F700000)` solo con consenso.

Integrazione con il manager Nikon e validazione di muludw: [dettaglio](S33_GUI_Integrazione_Manager_Nikon_e_Validazione_muludw_20261106.md).
