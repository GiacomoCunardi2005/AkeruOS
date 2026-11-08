# TBIB — accessori originali FED20 e trasporto software a 48 bit

25 ottobre 2026. PASS offline; mappa fisica incompleta; NON_INSTALLARE.

Atlante: `Risultati/Processor_Registers/20261025T203954Z/REGISTER_MAP.md`.
1200 voci: 64 posizioni core, 200 AUX, 936 MMIO singoli. Aggiunte 21 celle
e arricchite quattro già note; nessuna nuova finestra o famiglia calcolata.
Le 25 celle trattate appartengono al gruppo `FED20xx`; non viene assegnato
un nome fisico alla periferica.

## Provenienza e copertura

Il TBIB originale V1.1 è letto dal contenitore a offset `7C`; base ed entry
`01000000`, dimensione e checksum provengono dall'header. Il payload intero
è mappato invariato nelle prove CPU. Nessun padding, troncamento del firmware,
modifica GNU o trasferimento di indirizzi da altri payload/versioni.

Il censimento globale lineare TBIB era stato respinto dalla guardia OOB e
rimane tale. Questa tappa usa accessi eseguiti a PC originali e ridecodifica
finestre delimitate intorno a quei PC. Non dichiara riparata la disassemblazione
globale e non promuove le parole dei pool sulla loro sola forma numerica.
Pool inline e salti che li superano rendono particolarmente importante la
distinzione fra navigazione lineare e istruzione realmente eseguita.

Sono provate 31 routine tra `10031D8` e `1003688`, chiamate dall'harness.
Sono tutte completate con ritorno; non è provato un boot TBIB completo o
che ogni ingresso selezionato sia globalmente raggiungibile sul dispositivo.

## Nuove celle e contratti software

Nuovi indirizzi:

`FED2000/2004/2008/200C/2010/2014/2028/202C/2030/2034/2038/203C/2040/2048/204C/2050/2068/206C/2070/2074/2078`.

Già presenti e arricchiti: `FED2018/201C/2020/2024`.

| Routine o gruppo | Contratto osservato |
|---|---|
| `10031D8`, `1003228`, `100325C` | RMW: argomento zero cancella rispettivamente bit 0/2/1, nonzero imposta |
| `100320C`, `1003688` | Imposta rispettivamente bit 0 di 2004 e bit 1 di 2038, argomento ignorato |
| `1003290` | Preserva low4 di 2028, sostituisce bits4..15 da arg0; scrive high16 a 202C |
| `10032D0` | Scrive low16/high16 dell'argomento a 2030/2034, in quest'ordine |
| `10032F8`, `10033D8` | Store low16 a 203C/206C |
| `100333C` | Legge 2048/204C; scrive 2048 al puntatore arg1 e 204C al puntatore arg0 |
| `10033EC`, `1003410` | OR con maschera / clear con maschera su 2070 |
| `1003430`, `1003464` | Polarità inversa: argomento nonzero cancella bit 1/0 di 2074, zero imposta |
| `1003498`, `10034CC` | Nonzero imposta bit 1/0 di 2078, zero cancella |
| Getter restanti | Letture full16 o singoli bit, con ritorni controllati nell'harness |

Tutti i 1044 accessi MMIO osservati sono halfword: 612 letture e 432 scritture. Questa larghezza degli
accessi non certifica la larghezza fisica del registro o i suoi permessi.
Le sei classi di argomento provate sono 0, 1, 2, 80000000, 12345678, FFFFFFFF;
i flag qui confrontano con zero, senza ridurli a "solo 1 significa vero".

## Scrittura e lettura software di 48 bit

`1003518` riceve r0/r1 come coppia di parole e:

1. imposta bit 0 di `FED2010` tramite RMW;
2. scrive low16 di r1 a `FED2024`;
3. scrive high16 di r0 a `FED2020`;
4. scrive low16 di r0 a `FED201C`;
5. preserva high8 di `FED2014` e sostituisce low8 con `DB`.

`100359C` imposta bit 0 di `FED2018`, legge in ordine 2024/2020/201C,
poi cancella bit 0 di 2018. Restituisce r0 = (2020<<16)|201C e r1 = 2024.
Sono stati verificati entrambi i registri di ritorno in tutti i 18 scenari.

È provato un ordine e un trasporto software. La fixture non implementa
conteggio, latch, tempo, IRQ o snapshot fisico; non è una prova di lettura
atomica dell'hardware o del significato dei bit di controllo.

## Validazione

CPU: `outputs/gnu_arc700/20261025T203639Z_c493e826/`.
Audit: `Risultati/Processor_Registers/20261025T203954Z/evidence/tbib_fed20_audit.json`.

Tre pattern di seed MMIO incrociati con sei argomenti: 18 scenari e 36
esecuzioni riferimento/osservatore, con 18 coppie di tracce identiche.
31 routine per scenario, exit 0 e nessun fault. Stack e r13..r19 preservati.
Non sono stati osservati accessi AUX o istruzioni DSP provvisorie nel percorso.

L'audit ricalcola per bit gli aggiornamenti, verifica opcode/operandi nei
byte originali (210 istruzioni ridecodificate), 738 carichi dai pool, callback MMIO ordinate, registri
di ritorno controllati nell'harness e buffer RAM di uscita. I byte esterni
alle due lane halfword devono rimanere invariati.

Verificati i ledger dei 42 atlanti PASS precedenti: nessuna chiave/geometria
persa. Le schede precedenti restano identiche salvo append dei quattro
arricchimenti e rilocazione dei riferimenti AUX generati. Le prove storiche
che puntano all'atlante parent immutabile sono mantenute. Restano invariati
25 indici AUX con risultati guest e 204 ancore run/PC.

Riproduzione:

1. `python3 Python_Trace_Scripts/s33_verify_tbib_fed20.py`
2. `python3 Python_Trace_Scripts/s33_integrate_tbib_fed20.py outputs/gnu_arc700/20261025T203639Z_c493e826`

L'audit ha richiesto correzioni agli offset del delay slot dei getter e alla
sintassi GNU dello shift implicito di un bit. Il candidato `203907Z` è
FAIL_NOT_ADMITTED per un confronto troppo restrittivo dei percorsi AUX
storici/generati. Nessuna di queste correzioni ha richiesto nuove prove CPU
o modifiche al firmware/GNU; è stato riusato il risultato CPU PASS.

## Limiti e seguito

Seed, backing MMIO, stack e buffer RAM sono fixture. Restano sconosciuti
domini reali dei chiamanti, nomi fisici, reset, permessi, W1C, IRQ, timing e
atomicità. Nessun hardware, USB, NAND o SD toccato; originali e GNU invariati.

Proseguire dai gruppi TBIB dopo `10036A4` e dai restanti collegamenti
pool→accesso, oltre ad AUX indiretti/overlay, BCR/SoC e DSP fisica.
Il goal resta attivo e la mappa fisica è incompleta.
