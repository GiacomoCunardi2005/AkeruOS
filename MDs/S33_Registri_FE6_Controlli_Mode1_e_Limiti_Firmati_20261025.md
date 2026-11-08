# Controlli FE6, tabelle modalità1 e limiti firmati

25 ottobre 2026. Atlante `Risultati/Processor_Registers/20261025T104404Z/`:
729 voci,64 posizioni core /197 AUX /468 MMIO. Mappa fisica incompleta,
obiettivo attivo. Le posizioni core comprendono codifiche opzionali/riservate,
non64 registri fisici dimostrati. Nessun registro hardware verificato.

## Ambito e nuovi indirizzi

48 indirizzi hanno accessi nei casi ordinari;42 sono nuovi,6 avevano prove
precedenti. Le nuove ammissioni usano esclusivamente gli accessi ordinari.

- 12 celle nei rami non negativi dei controlli:FE64600/620/640/6C0 con offset0/4/8,
  corrispondenti ai selettori0/1/2/4. Il selettore4 usa un indirizzo speciale,
  non la formula del ramo0..2.
- Tabella di24celle FE60100+4*s,s0..23, e tabella di12celle FE64000+4*s,s0..11.
  Sei celle della prima tabella avevano già scritture dal ciclo239F00;
  questa prova aggiunge anche il read-modify-write. Nuove celle delle tabelle:30.

Nessuna percentuale fisica deriva da queste quantità. L’universo dei registri,
la configurazione reale/BCR e gli effetti periferici restano aperti.

## Operazioni originali

| Accessor | Effetto software nei rami ordinari |
|---|---|
| 2C694C/2C69BC/2C6A5C | Set/clear dei bit1/2/3 all’offset0; argomento1 imposta, gli altri valori azzerano |
| 2C6B0C | RMW bit0 ebit4 dagli argomenti, preserva tutti gli altri bit |
| 2C6A2C | Restituisce mask10hex(bit4) della cella offset8, senza normalizzazione |
| 2C6ACC | Restituisce low15 della cella offset4 e scrive bit15 come byte al puntatore RAM del chiamante |
| 2C6C98 | Solo modalità1: RMWbits12..13 della tabella FE60100, preserva gli altri bit |
| 2C6CE8 | Solo modalità1: stesso RMW nella tabella FE64000 |

Le tabelle controllano gli indici con confronto unsigned. Fuori dal rispettivo
conteggio, con modalità1, i valori di ritorno osservati sono05500100 e05500101hex.
Con cache modalità2 le due funzioni provate saltano gli accessi e ritornano0.
Cache ready1 e parola10000/20000hex sono fixture esplicite del chiamante,
non una configurazione o un reset Nikon.

## Limite firmato: prova distinta dalle ammissioni

In2C694C il primo controllo è signed(s)<=2, senza un controllo minimo.
Per il ramo calcolato l’indirizzo è uint32(FE64600+uint32(s<<5)); il ramo
positivo s=4 usa invece il pool FE646C0.

- 80000000 e80000001hex, interpretati come negativi, attraversano il ramo
  calcolato e accedono rispettivamente aFE64600/FE64620 per overflow32bit.
  Otto eventi completati separati dai720 eventi ordinari. Non sono alias
  fisici o nuove celle: il calcolo software produce gli stessi indirizzi.
- FFFFFFFF raggiunge una lettura aFE645E0;80000004 raggiungeFE64680, mentre
  il selettore positivo4 usaFE646C0. Le due celle non sono mappate nel modello:
  begin senza result, stopatteso11. Nessuna lettura completata o valore valido.

FE645E0 eFE64680 non vengono promossi tramite questi tentativi. Non sono
una lista permanente di indirizzi impossibili: una prova ordinaria indipendente
potrebbe ammetterli in un’altra famiglia. Il fault dimostra il confine del
modello dichiarato, non un difetto hardware. Nessuna prova che i chiamanti
Nikon reali forniscano questi valori negativi.

## Esecuzione, audit e conservazione

Prova: `outputs/gnu_arc700/20261025T104108Z_2704fcf9/verified_evidence.json`.
Sette scenari con osservatore disabilitato/abilitato:14run,7coppie di tracce
identiche byte per byte. 410invocazioni nei sette scenari distinti,820con replay.

I due scenari ordinari con seed0/FFFF producono360 eventi ciascuno; coprono
controlli, getter/outbyte e tutte le celle/campi delle due tabelle. Tre selettori
positivi respinti3/5/7FFFFFFF non produconoMMIO nei controlli. Sono provati
anche indici pari al conteggio eFFFFFFFF per entrambe le tabelle, il gate
modalità2, i due alias negativi e i due fault attesi.

Il chiamante verifica ritorni, byte di output, SP e r13/r14/r15/r16.
Il verificatore controlla sequenza PC/op/indirizzo/valore, larghezza16, celle,
padding A5 e cache invariata. Il byte di output è RAM sintetica700000, non
RAM fisica dedotta libera. Main originale rimane immutato.

`evidence/fe6_controls_mode1_audit.json`: PASS. Ridecodifica al PC guest,
lega i byte al firmware originale, verifica branch firmato/unsigned, shift5,
pool speciali, tracce in ordine e separazione dei tentativi senza risultato.
I contatori profiler non sono usati come conteggio di istruzioni ritirate.

Ledger155file verificato; parent149file invariati. AUX guest invariati:
22indici,74siti run/PC. GNU installazioni/config/sorgenti/build/copielab e
firmware originali preservati. Nessun hardware, flash, NAND/vendor, resetUSB
o scritturaSD. NON_INSTALLARE invariato.

Script: `s33_verify_fe6_controls_mode1.py`, `s33_audit_fe6_controls_mode1.py`,
`s33_integrate_fe6_controls_mode1.py` in `Python_Trace_Scripts/`.
Seguito: domini dei chiamanti per gli altri controlli FE6 indicizzati,
famiglie FF7/FFB/FFC, AUX parametrizzati/candidati codice-dati e BCR/fisica.
