# S33 — tasti GUI e bit dello stato di ingresso

Analisi statica del firmware V1.1, 27 ottobre 2026. La tabella inizializzata a `0x392F04` contiene 16 record da 20 byte. Il record 7, a `0x392F90`, contiene maschera `0x80`, posizione 7 e indice logico 14. È quindi una pista concreta verso l'origine dell'evento Menu già seguito nella GUI.

Il codice originale `0x16F86C`, quando il suo gate è abilitato e rileva una variazione della maschera di un record, estrae il bit della nuova coppia di stato e chiama `0x16F72C` con indice e valore. Per gli indici inferiori a `0x61`, quando l'emissione è abilitata, quest'ultimo costruisce `indice << 7` per un valore non nullo e aggiunge 1 per zero. I nomi nella tabella seguente provengono dai comandi diagnostici, verificati separatamente; non identificano il pulsante fisico.

| Comando diagnostico | Indice logico | Bit nella coppia di stato | Evento nonzero / zero |
| --- | ---: | ---: | --- |
| KeyLeft | 9 | 21 | `0x480` / `0x481` |
| KeyRight | 10 | 15 | `0x500` / `0x501` |
| KeyOK | 11 | 12 | `0x580` / `0x581` |
| KeyMenu | 14 | 7 | `0x700` / `0x701` |

Il collegamento fra record e generatore è statico; l'esecuzione del comando diagnostico e il successivo percorso dell'evento `0x700` nel wrapper della GUI sono prove CPU **separate**, con fixture. Non è stata eseguita in continuità l'intera catena dal bit all'apertura, né si sa ancora chi imposti il bit 7, quale interruttore fisico corrisponda o quale sia il contenuto runtime della tabella.

Il nuovo [inventario verificabile](../Python_Trace_Scripts/s33_inventory_gui_input_bits.py) confronta tutti i 320 byte della tabella estratta dai payload verificati con `MainCode.dmp` e controlla le 16 maschere: [risultati](../Risultati/GUI_S33/input_bits_20261027T113500Z/records.json). La logica del consumatore è riportata nel [disassemblaggio GNU precedente](../Risultati/Lens_MCU_Interface/Iris_Shadow/20261022T014758Z/gnu_windows.txt) e nella correzione della semantica del bit nel [rapporto Iris, sezione 9](S33_Iride_Shadow_0x446808_Scrittore_e_Servizio_Diagnostico.md). Le associazioni dei comandi sono in [S33_GUI_Tasti_Comandi_Eventi_20261027.md](S33_GUI_Tasti_Comandi_Eventi_20261027.md); il percorso della schermata è in [S33_GUI_Wrapper_Filtro_Menu_20261027.md](S33_GUI_Wrapper_Filtro_Menu_20261027.md).

Nessuna modifica o installazione firmware e nessun accesso alla fotocamera. Prossimo passo: seguire l'origine della coppia di stato e testare il consumatore con variazioni controllate, distinguendo la simulazione dall'hardware reale.
