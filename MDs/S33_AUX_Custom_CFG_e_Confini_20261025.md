# AUX custom: chiamanti, confini e CFG — 25 ottobre 2026

L’atlante passa da 373 a **432 voci**: 64 posizioni core, 173 indici AUX e
195 indirizzi MMIO. Le 59 aggiunte AUX sono supportate da analisi statica del
firmware originale. Non sono registri fisici verificati né nuovi risultati LR/SR
eseguiti nell’emulatore. Il goal rimane attivo: la mappa completa non è provata.

- [Atlante](../Risultati/Processor_Registers/20261024T234600Z/REGISTER_MAP.md)
- [JSON](../Risultati/Processor_Registers/20261024T234600Z/register_map.json)
- [Grafo delle fonti](../Risultati/Processor_Registers/20261024T234600Z/graph.html)
- [Validazione](../Risultati/Processor_Registers/20261024T234600Z/atlas_validation.json)

## Metodo e copertura

`s33_verify_custom_aux_cfg.py` scansiona i 16 payload V1.1 verificati a ogni
halfword, cercando gli encoding BL/BL_S che puntano alle finestre Main:

| Inizio | Fine esclusa |
|---|---|
|0x319000|0x319C00|
|0x339B00|0x33B700|
|0x342000|0x342F00|

Le formule derivano dalle definizioni GNU `arc-tbl.h` e `arc-fxi.h`. Ogni
chiamata ammessa è ridecodificata da GNU e deve coincidere con un confine
indipendente della disassemblazione Main; anche il target deve essere un
confine. Tale riscontro serve a escludere sovrapposizioni, senza trasformare
la scansione lineare in una prova di eseguibilità globale.

Risultato: 169 chiamate ammesse verso 95 entry, 3.037 PC esaminati, 64 indici
con accessi espliciti qualificati e 231 siti LR/SR distinti. Cinque indici erano
già nell’atlante; le nuove voci sono 59. I percorsi sono costruiti dalle entry,
con rami, delay slot e ritorni; i byte di ciascuna istruzione coincidono con
il Main originale e con il firmware contenitore.

La qualificazione richiede almeno un ritorno nel CFG e nessun decode invalido
nel CFG di quella entry. Rimangono espliciti i limiti: fattibilità dei rami
non provata, ritorno delle chiamate dirette assunto per il proseguimento,
chiamate e salti indiretti irrisolti come terminali. Non è una prova che il boot
raggiunga ogni routine o che ogni percorso sia concretamente eseguibile.

Fonte originale Main: SHA256
`06754a1f451f17b3047fe03cdb83fd08af11dac725638818254ef0de26a5ed29`.
Firmware contenitore: SHA256
`1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`.
L’ELF di analisi contiene la sezione Main, verificata con roundtrip byte-identico;
non viene confuso con un’immagine runtime che abbia segmenti PT_LOAD.

## Sovrapposizioni da escludere

A 0x342D62 l’istruzione AND contiene l’immediato lungo `0xFFFF00FF`. La
halfword a 0x342D66, vista isolatamente, assomiglia a BL_S verso 0x342D60.
Entrambi sono interni a istruzioni effettive: il controllo indipendente dei
confini rifiuta questa falsa chiamata. Nessuna voce viene promossa sulla sola
somiglianza dell’opcode o sulla sola presenza di un numero nel file.

Gli output preliminari di questa indagine sono marcati SUPERSEDED e non sono
fonti del nuovo atlante. Il risultato ammesso è
`Risultati/Processor_Registers/custom_cfg_20261024T234117Z/verified_evidence.json`.
La sua copia nell’atlante è `evidence/custom_aux_cfg.json`; i richiami rifiutati,
il controllo dei confini, i CFG e gli indici irrisolti restano consultabili.

## Controllo con la CPU emulata

`s33_verify_call_decoder_against_guest.py` confronta la formula di estrazione
dei target con **1.783 risultati semantici di salto**, su 266 PC distinti per
run, nelle tracce GNU originali già conservate: 1.756 BL con immediato a 25 bit
e 27 BL_S. Tutti coincidono; i byte sorgente sono ricondotti al contenitore
originale. L’audit è `evidence/guest_call_decoder_audit.json`.

Questo controllo riusa esecuzioni della CPU emulata già registrate. Non è una
nuova esecuzione delle routine custom e non verifica ogni encoding possibile;
in particolare non aggiunge copertura guest dell’encoding BL a 21 bit. Le
tracce LR/SR consolidate restano 21 AUX e 65 siti, come nel checkpoint FE1.

Il modello defined-memoryv2 conserva il banco sintetico da 2.048 elementi e
la guardia `S33_AUX_RANGE`. Gli indici qui esaminati lo superano; non sono
eseguiti né è stato ampliato il banco. I sorgenti/configurazioni/build GNU e
le copie laboratorio rimangono in sola lettura.

## Significato software osservabile

Le tre leaf chiamate a 0x342C6C, 0x342CA4 e 0x342CDC leggono rispettivamente
AUX 0x10030, 0x10032 e 0x10034. AND con -16 conserva i 28 bit alti; BMSK
dell’argomento con indice 3 conserva i quattro bit bassi; OR e SR sostituiscono
il nibble basso. Le voci riportano questa trasformazione software, con
significato fisico ignoto. Larghezza 32 indica l’operando LR/SR, senza dedurre
la larghezza o le permission del registro fisico.

Gli altri gruppi qualificati comprendono accessi a 0x10000/1/2, parti delle
famiglie 0x101xx e 0x102xx, e indici 0x10800–0x10C00 già presenti. L’elenco
esatto e i PC sono nel JSON; nessun intervallo intero è espanso per analogia.

## Questioni aperte

Sedici indici visti nei prefissi CFG rimangono non qualificati:
`0x10105`, `0x10106`, `0x10107`, `0x10108`, `0x1010A`, `0x10113`,
`0x10114`, `0x10118`, `0x1027A`, `0x1027B`, `0x1027D`, `0x10283`,
`0x10284`, `0x10285`, `0x10288`, `0x1028C`.
Gli stop indiretti o le parti incomplete non sono stati aggirati.

La ricerca nei 16 payload non trova encoding BL ammessi né puntatori assoluti
espliciti verso 0x319844 o 0x342C2C. Questo è un negativo limitato a quelle
forme: non esclude salti tail, tabelle relative, puntatori costruiti o codice
non coperto. Le famiglie `0x10223+i` e `0x10020/21+2*arg0` restano candidate.
La tabella runtime della famiglia `0x10010+arg0` resta irrisolta; nuove
chiamate non ne forniscono automaticamente i valori. Nessun dominio software
è promosso a un insieme di registri implementati.

L’audit del nuovo atlante verifica i 95 file del parent, gli input GNU e
firmware, 432 chiavi uniche e l’aggiunta esclusiva dei 59 AUX. Il ledger finale
comprende 101 file. La semantica fisica, i BCR reali, la configurazione Nikon
e l’universo completo MMIO restano aperti. Nessun hardware, flash, comando
NAND/vendor, reset USB o scrittura SD. **NON_INSTALLARE** invariato.
