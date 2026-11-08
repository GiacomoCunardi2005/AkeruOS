# USB Bulk-Only: transazione RAW e adattatore Nikon offline

**Continuazione corrente21ottobre:** [S33_NAND_PC_Parser_Buffer_Privato_e_Contenitore_Offline.md](S33_NAND_PC_Parser_Buffer_Privato_e_Contenitore_Offline.md). Parser e bufferprivato integrati, contenitoreoffline NON INSTALLARE; Nikondevice033 nuovamenteMSDC22MiB alle08:55UTC. Le condizioni di assenza e i limiti del prototipo descritti sotto sono checkpoint precedenti.

21 ottobre 2026 — R0/R3/R4. **Obiettivo ancora attivo:** nessun accesso hardware oltre il volume da22MiB e nessun nuovo aggiornamento installabile. Questo checkpoint supera il precedente limite «oggetto C compilato ma non eseguito»: il nucleo ora esegue su ARC700 dentro una transazione Bulk-Only originale, con servizi esterni simulati.

## Verifica richiesta sulla fotocamera

L’installazione MSDC è confermata dall’utente e il suo funzionamento era stato [osservato direttamente in10campioni](../Risultati/Hardware/MSDC_Default/20261020T225849Z/observation.json): Nikon04b0:035d, classe08/06/50, usb-storage, disco45056settori/22MiB e partizionevfat. Questa evidenza resta valida per quella connessione; non è readback della flash.

Nel [nuovo controllo del21ottobre alle08:20UTC](../Risultati/Hardware/MSDC_Default/20261021T082028Z/observation.json), tutti i10campioni hanno listaNikon vuota, `lsusb -d 04b0:` esce1 e `lsblk` non elenca sda. [Revisione esplicita dell’esito](../Risultati/Hardware/MSDC_Default/20261021T082028Z/review.json). Il generico `OBSERVATION_REQUIRES_REVIEW` del collettore significa qui **nessuna Nikon rilevata**, non PTP o guasto dimostrati. Collegamento, alimentazione e causa non sono distinguibili dai soli dati. Non invalidare la precedente provaMSDC né presentarla come connessione corrente.

Nessun settore, file sulla fotocamera, comando vendor o scrittura del dispositivo è stato eseguito in questa verifica.

## Correzione:820E26 non è una whitelist IN da ampliare

La lettura precedente nel [checkpoint del nucleo](S33_Accesso_NAND_PC_Inizializzazione_Buffer_e_Nucleo_Sola_Lettura.md) interpretava erroneamente820E26..4C come lista degli opcode ammessi in lettura. Il parser820C00 scrive `(CBW[12]&80h)>>7` al byte passato inr5; il chiamante lo legge da`sp+1C`. **1 significaIN**,0 significaOUT.

| Percorso originale | Effetto |
|---|---|
| LunghezzaCBW dichiaratazero |820DBC→820E4E, dispatcher senza controllo direzione |
| IN, opcode diverso da2A |820DC2→820DC8→820DCC: r13=1 e dispatcher820E4E |
| OUT, opcode03/12/1A/23/25/9E/08/28/5A |820E26..4A→820EC2: stall eCSWphase-error, senza dispatcher |
| OUT, altro opcode |820E4C pone r13=2, poi dispatcher |

Il ramo820EC2 costruisceCSWstatus2 e gestisce gli stall: non esegue un invio dati normale. **Per il comandoFF IN del prototipo non serve modificare queste istruzioni.** Nessuna patch alla lista è stata prodotta. Il rifiuto diOUT/flagriservati/lunghezza è compito del nuovo handler, perchéFF non è riconosciuto dalla logica direzione originale.

Il baselineFF originale attraversa l’intero820D04, chiama820B2C e invia soltantoCSWsuccesso con residuo2112: il semplice successo non prova una lettura. La variante di laboratorio cambia il solo targetFF a9A3460 verso il codiceC collegato; i servizi USB/eventi sono sostituiti da registratori nelle copieRAM dei payload. Le istruzioniBOT originali restano intatte.

## Diciassette transazioni CPU complete

[Script riproducibile](../Python_Trace_Scripts/s33_verify_usb_bot_readonly.py), [evidenza](../Risultati/USB_SCSI/Accesso_NAND_PC/bot_cpu_20261021T082509Z/verified_evidence.json), [casi eCSW](../Risultati/USB_SCSI/Accesso_NAND_PC/bot_cpu_20261021T082509Z/cases.json), [disassemblato originale](../Risultati/USB_SCSI/Accesso_NAND_PC/bot_cpu_20261021T082509Z/original_bot_gnu.txt).

Ingresso esplicito820D04, ricezione1906B4 simulata, parser820C00, dispatcher81F89C, targetFF, nucleo`akrn_read_page` compilatoARC700, invio1908DC simulato, costruttoreCSW820C9C e ritorno. I byte delle regioni originali sono confrontati conMainCode fornito; hash firmware e strumenti controllati prima/dopo. Il linker usa `-mno-sdata`; codice a500000 è **collocazione di laboratorio**, non RAM concessa sul dispositivo. La copia aggregata generata dal compilatore usa memcpy originaleAD920.

| Casi | Risultato verificato |
|---|---|
| BaselineFF originale |soloCSWsuccesso, residuo2112, nessuna lettura |
| Prima e ultima pagina della geometriafixture |2112byte esatti, contenuto confrontato, CSW0/residuo0 |
| OUT, flag81h, lunghezza2111/2113/0 |lettore mai chiamato, CSW1 |
| CDB15byte, riservato nonzero, chip/blocco fuori range |lettore mai chiamato, CSW1 |
| Errore lettore |nessun invio dati, CSW1/residuo2112 |
| ErroreUSB |CSW1, residuo2112 nel casoactual0 |
| InvioUSB2111byte |CSW1/residuo1; mai successo per una pagina incompleta |
| Errore ricezione |ritorno errore, nessun dispatcher/invio |
| CBW30byte |CSW2 contag0, perché il parser rifiuta prima di copiare iltag |

SP è conservato in tutti i17casi. La geometria1chip/512blocchi/64pagine/2048+64 è **fixture dichiarata**; il lettore genera un pattern deterministico e non chiama il controllerNAND. Il test non prova taskUSB, tempi, endpoint fisici, proprietà del buffer o avvio. CDB con lunghezza maggiore16 sono esclusi: il parser originale copia la lunghezza mascherata senza un limite16 verificato; un handler chiamato dopo la copia non può correggere retroattivamente quel limite. Nessun tentativo di sfruttarlo è stato fatto.

## Adattatore al servizioNikon: controllo e test separati

[Header](../S33-sections/usb_nand_readonly/nikon_raw_read.h), [sorgente](../S33-sections/usb_nand_readonly/nikon_raw_read.c), [test](../S33-sections/usb_nand_readonly/test_nikon_raw_read.c), [verificatore](../Python_Trace_Scripts/s33_verify_nikon_raw_adapter.py), [evidenza](../Risultati/USB_SCSI/Accesso_NAND_PC/raw_adapter_20261021T082705Z/verified_evidence.json).

Il wrapper riusa come simboli ancora da collegare: mutex1593AC/1594A4 con oggetto01B00001, ready25BFB8, getter25CAEC e lettore25F428. Acquisisce il mutex, rilegge geometria/pronto, valida coordinate/lunghezza e rilascia dopo ogni acquisizione riuscita. In caso di errorelettura più errorerilascio conserva il primo; un errorerilascio isolato impedisce il successo. Coordinate consegnate al servizio: chip,page,bloccoLE16.

La geometria distingueu16G+6, usato come stridechip, dau16G+8, capacitàutilizzabile. **Non è ancora stabilito indipendentemente cheG+6 sia il conteggio fisico leggibile**. Il contesto richiede perciò un limiteblocco già confermato:0 rifiuta ogni accesso. Nei test vale512 esplicitamente comefixture. Sono rifiutati profili con bit100h inG+2 e prodotti chip×blocchi×pagine oltre65536, per non assumere cicliindirizzo aggiuntivi o ignorare il troncamento16bit osservato nel percorsoNikon. La moltiplicazione resta32bit senza overflow grazie ai campibyte/word; il caso massimo255×65535×255 è provato come rifiuto.

Test nativi conASan/UBSan e lo stesso sorgente eseguitoARC700 superati: geometria, prima/ultima coordinata, canarini, limiti, servizi nonpronti, mutexfallito, rilasciofallito, precedenzaerrori e conteggichiamata. Le cinque funzioniNikon sono **recorder del test**, non corpi originali; questo esito è distinto dalle17transazioniBOT. Il piccolo memset nel testARC è un supporto di laboratorio e non una funzione già collegata sul firmware.

## Collegamento successivo: BOT → adattatoreC →25F428 originale

Dopo la prima pubblicazione sono state completate altre due verifiche:

- [Dieci casi del corpoRAW](../Risultati/USB_SCSI/Accesso_NAND_PC/raw_body_latest.json), [script](../Python_Trace_Scripts/s33_verify_nikon_raw_body.py): wrapperC→ready25BFB8/getter25CAEC→25F428 originale. Prima/ultima pagina del primo blocco, blocco1, blocco511/pagina63, chip1/blocco0, attesafallita in due layout, nonpronto, acquisizionefallita e rilasciofallito. SP e canarini conservati. Primo blocco delchip0 interleaved512+16; gli altri2048dati+64spare. I quattro passi dati/spare sono confrontati byte perbyte con i recorder. AttesaNAND nonzero produce01B00004, non il valoreiniettato7; errorelock123 e release124 conservati dal wrapper. Il ready0 del wrapper è invece−2: non confonderli.
- [Diciassette transazioni integrate](../Risultati/USB_SCSI/Accesso_NAND_PC/bot_raw_cpu_latest.json), con `python3 Python_Trace_Scripts/s33_verify_usb_bot_readonly.py --original-raw-body`: CBW→parser/dispatcher originali→nucleoC→wrapperC→25F428 originale→invio/CSW. Gli stessi casi validi ed errori della matriceBOT passano. Il test controlla nella traccia anche25F428, entrambi i cicli di layout, ready egetter. La variantepattern precedente è stata rieseguita dopo l’aggiunta di questo modo ed è ancoraPASS17casi.

Restano simulati mutex, controller, attesa e trasferimenti512/16byte, oltre aUSB/eventi. **I byte di pagina sono fixture**, non nuovi dati dellaNAND. Il collegamento è ora unico nella CPU di laboratorio, ma non prova trasferimenti fisici, ECC, attese reali o schedulazione. Il contesto confermato512 è dichiarato nelbridge del test e non inserito in un firmwareinstallabile. Gli indirizzi500000 e2060000 sono esclusivamente di laboratorio.

La routine25F428 controlla l’esito dell’attesa prima dei cicli e ritorna lo stato preservato; non c’è un nuovo controllo d’integrità dei dati a valle dei recorder. Questo test non deve diventare una garanzia di lettura fisica corretta soltanto perché il ritorno è0.

## Continuazione concreta

1. Il collegamentoCPU è ora verificato come sopra. Proseguire su semantica/integrità dei trasferimenti inferiori e stati reali, senza promuovere il pattern dei recorder a datoNAND.
2. Risolvere geometria fisica da evidenze indipendenti e il limite del parser prima dellaCDB; non trasformare512fixture in misurahardware.
3. Collegare buffer alla risorsa1E acquisita e provarne durata/sincronizzazione; ora il test usa buffer privato di laboratorio.
4. Dimostrare collocazione/residenza/ABI, costruzione contenitore, compatibilitàupdater e recupero prima di dichiarare un nuovo aggiornamento installabile. Nessuna scrittura nelle directoryGNU, nei firmware originali o sulla fotocamera.

L’applicazioneAkeruOS resta circa10% funzionale: questi risultati non sono un suo boot o una fotografia.
