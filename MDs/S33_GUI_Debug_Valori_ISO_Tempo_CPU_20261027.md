# S33 V1.1 — valori delle schermate diagnostiche ISO e tempo

27 ottobre 2026. La prova usa codice originale V1.1 in GNU ARC700, con RAM di laboratorio e servizio di apertura GUI registratore. Le finestre eseguite e le tabelle eventi sono confrontate con `MainCode.dmp`; nessun comando diagnostico è stato inviato alla fotocamera.

## ISO: indice e valore convertito

Nella schermata interna `DebugModeISO` (`0x3F`) il callback `0x7D25B0`, evento `0x4801`, ottiene un indice dal controllo; se diverso da `-1`, passa il byte basso a `0xD03B8`. Questa routine salva il byte a `0x365787` e chiama `0x17C320`, che salva l'indice anche a `0x367BC8`, lo converte con una tabella di salti e passa il risultato a `0xDE78C`. Quest'ultima scrive una halfword a `0x37FBF2` (`0x37FBD0 + 0x22`). Il passaggio dalla schermata al setter è analisi statica; il banco chiama direttamente il setter originale.

| Indice sintetico | Valore scritto nella halfword |
| --- | --- |
| 0–9 | 0, 50, 64, 80, 100, 120, 125, 140, 160, 200 |
| 10–19 | 250, 280, 320, 400, 500, 640, 800, 1000, 1250, 1600 |
| 20–23 | 2000, 2500, 3200, 6400 |
| 24 | 0 |

Tutti i 25 casi sono stati eseguiti e controllati: la tabella è la trasformazione software per quegli input, **non un elenco di ISO fisici garantiti**, né prova che l'interfaccia permetta di selezionarli tutti. Per confronto, il manuale Nikon dichiara ISO 125–1600 nel funzionamento originale. Il significato di zero, l'arbitraggio con AE, la validità per la scena e l'effettivo guadagno sensore restano aperti.

## Tempo: conferma e valore memorizzato

Nella schermata interna `DebugModeExpTime` (`0x3E`), evento `0x0580`, il callback `0x7D2394` legge la word `0x899AD0`, ne calcola il valore moltiplicato per 1000 con l'aritmetica a 32 bit e chiama `0xD03E0`. Quest'ultima scrive la word a `0x365788`; `0xDE7B4` scrive lo stesso valore a `0x37FBF4` (`0x37FBD0 + 0x24`). Quindi il callback richiede apertura GUI `0x1453E4(0x36,0)`.

Il banco ha iniettato i valori 0, 1, 42, 120 e 4000 e verificato le due word, rispettivamente 0, 1000, 42000, 120000 e 4000000; il servizio di apertura era un registratore. Il test non dimostra che ogni input sia raggiungibile dalla GUI, né l'unità del valore salvato o il tempo fisico di esposizione. Non dimostra che il valore sopravviva a un successivo aggiornamento AE o venga applicato allo scatto.

## Limiti e prove

In totale **30 casi CPU PASS**: setter e conversione ISO originali, callback di conferma tempo e setter originali, con sola apertura GUI sostituita. RAM e input sono sintetici; non sono eseguiti coda eventi, sensore o ciclo di acquisizione. Il valore ISO e la word del tempo sono osservati in memoria emulata: la loro influenza su una fotografia resta da provare. Nessuna istruzione firmware è stata modificata per aggirare limiti del simulatore e nessuna operazione hardware/SD è stata effettuata.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_debug_exposure_values_cpu.py), [30 casi](../Risultati/GUI_S33/debug_exposure_values_cpu_20261027T213830Z/cases.json), [finestre GNU](../Risultati/GUI_S33/debug_exposure_values_cpu_20261027T213830Z/gnu_windows.txt), [servizio sostituito](../Risultati/GUI_S33/debug_exposure_values_cpu_20261027T213830Z/fixture_patch.json) e [traccia](../Risultati/GUI_S33/debug_exposure_values_cpu_20261027T213830Z/cases.trace). Candidati **NON_INSTALLARE**.
