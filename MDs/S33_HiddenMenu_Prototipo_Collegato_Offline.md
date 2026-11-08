# HiddenMenu su SD: programma collegato per prove offline

**Continuazione hardware,20 ottobre 2026:** [foto dell’utente e stato corrente](S33_HiddenMenu_Hardware_Foto_e_Versioni.md) confermano GUIINFO e pagine informative; utente conferma installazione del candidatoSD e riferisce avvio normale senzaSD. Le precedenti frasi “rendering mai visto” e “nessun hardware” descrivono la fase di analisi. Marcatore all’apertura sconosciuto,USB/uscita/recupero non certificati.

**Continuazione 20 ottobre 2026:** ora esiste un [BIN candidato completo](S33_HiddenMenu_BIN_Candidato.md), con collocazione sperimentale distinta dall’indirizzo laboratorio di questo ELF. Integrità e60scenari controllati; NON_INSTALLARE/NO-GO flash invariato. Questo rapporto conserva i risultati del prototipo precedente.

20 ottobre2026 — R3/R4. **Creato un programma ELF di laboratorio con il salto aggiunto al punto reale del selettore.** Il codice non è più provato soltanto entrando direttamente nella routine nuova. È un passo verso il software richiesto, ma non è ancora un pacchetto Nikon installabile via SD: la collocazione del nuovo codice sulla fotocamera non è dimostrata.

## File prodotto e riproduzione

[Programma SD_MARKER_OFFLINE_TEST_ONLY.elf](../outputs/sd_marker_offline/20261020T124207Z_ad206518/SD_MARKER_OFFLINE_TEST_ONLY.elf), [builder e verificatore](../S33-sections/safety_audit_codex/build_sd_marker_offline.py), [assembly compatto](../S33-sections/safety_audit_codex/sd_marker_gate_compact.s), [manifest](../outputs/sd_marker_offline/20261020T124207Z_ad206518/verified_evidence.json), [disassemblato del collegamento](../outputs/sd_marker_offline/20261020T124207Z_ad206518/hook_gnu.txt), [disassemblato della routine](../outputs/sd_marker_offline/20261020T124207Z_ad206518/gate_gnu.txt), [traccia](../outputs/sd_marker_offline/20261020T124207Z_ad206518/pcode.txt).

Comando dalla radice: `python3 S33-sections/safety_audit_codex/build_sd_marker_offline.py`, senza-O. Il file ELF viene controllato per segmenti e byte; il suo stesso MainCode modificato e la routine vengono importati e provati in P-code. Non è dichiarata esecuzione dell’intero ELF nel motore GNU o avvio da reset.

Il bundle contiene quattro segmenti: MainCode aAD800, dati originali a360800, routine nuova a02000000 e stack laboratorio07000000..07001000. Solo il MainCode copiato nel bundle riceve una sostituzione di8byte a1353F2: un salto assoluto alla routine. Il Main originale e il firmware29.602.084byte restano invariati; gli altri byte del Main copiato sono confrontati integralmente. Il bundle non è un contenitore di aggiornamento Nikon e non va rinominato firmware.bin.

## Comportamento e controlli

La nuova routine è di272byte incluse stringhe, contro340 del primo prototipo. Riduce le istruzioni di salvataggio/ripristino mantenendo i registri controllati. I salti e le chiamate esterne usano simboli risolti dal linker, con chiamate assolute dove la portata relativa non basta.

La logica rimane quella del [file interruttore](S33_HiddenMenu_Interruttore_File_SD.md): `B:\modifica.modifica` trovato come file→richiesta menu20; assente, directory o errore restituito→135426 normale. Non scrive366880, non imposta3/1 e non richiede anche la directory HiddenMenu nel prefisso provato. Il test si ferma prima dell’esecuzione del managerUI, quindi non esclude altre esigenze successive del menu.

**60scenari eseguiti partendo da1353F2**, attraversando realmente l’istruzione di collegamento:25richieste menu,35continuazioni normali,5stati iniziali×12esiti filesystem. Il probe eredita tutti i controlli del precedente: stato immutato, tracking delle scritture, ripristino core/SP, conteggio mount/rilascio e assenza di fault.

Una baseline usa in un emulatore separato gli8byte originali al punto d’ingresso. Nei7casi normali con stato1 coincidono registri controllati,Z/N/C/V,SP eblink al confine135426. Non è equivalenza dell’intera memoria o dell’effetto dei servizi. I quattro risultati filesystem rimangono simulati; nessuna SD fisica o UI completa viene eseguita.

L’ELF ha ingresso1353F2, non BB540 o il resetROM. La chiave gate_entry fornita al probe indica il punto di partenza1353F2; il simbolo realmente collegato della routine rimane02000000, registrato separatamente nel manifest. La prima baseline ripristina il prefisso originale soltanto nella propria memoria emulata.

## Perché non è stato usato lo spazio finale pieno di zeri

Una ricerca ha trovato254byte finali zero nel payloadMain. Non sono automaticamente spazio libero. Nel campione originale il pool333B78 contiene **35BB04**, e la vera istruzione333972 lo carica in r1. Il tratto333968..33397A prepara inoltre lunghezza16 e passa quel puntatore alla routine128C20. Scrivere la routine a35BB04 sovrapporrebbe dati già referenziati dal firmware.

Il [riscontro GNU](../outputs/sd_marker_offline/20261020T124207Z_ad206518/placement_rejected_gnu.txt) e la ricerca delle paroleLE sono nel manifest. Un’altra parola verso35BBF0 si trova nel payload6 di tipo0: resta un candidato dati, non viene promossa a xref eseguibile. La collocazione35BB04 è stata respinta; non abbiamo convertito gli zeri in una dichiarazione di RAM libera.

Il primo tentativo di collegamento relativo usava erroneamente numeri interpretati dall’assembler come spostamenti. Il test l’ha fermato su destinazione non mappata; il tentativo successivo con simboli ha rilevato la portata insufficiente dalla posizione laboratorio. Nel risultato accettato le chiamate esterne sono assolute e tutti i60casi attraversano il collegamento corretto. I tentativi falliti rimangono conservati, nessun byte Nikon è stato saltato per aggirarli.

## Che cosa manca per un file da installare

Il nuovo codice a02000000 e lo stack07000000 sono collocazioni di laboratorio, non assegnazioni alla fotocamera. Va individuata e verificata una posizione che venga caricata, resti residente, non sovrascriva dati o altro codice e abbia margine stack nel contesto reale. Solo dopo ha senso produrre il contenitore Nikon candidato con i checksum ricostruiti e verificarlo integralmente.

Restano disponibilità della SD a quel punto, risoluzione del nome lungo, attese e rimozione concorrente, inizializzazione completa/uscita menu, versione residenteV1.0, avvio e recupero. Il [nuovo controllo RAM GNU](S33_GNU_RAM_Definita_e_Letture_Prima_Scrittura.md) verifica i prefissi attuali, ma non risolve la collocazione o certifica l’hardware.

Rimuovere modifica.modifica disattiverebbe la richiesta del menu quando il controllo viene raggiunto. Non rimuove il codice installato né ripara un caricatore danneggiato. **NO-GO flash e circa10% funzionale invariati**, nessuna azione sulla Nikon. Prossimo: posizione/residenza del codice e disponibilità SD al punto d’aggancio, mantenendo le verifiche CPU,boot e recupero aperte.
