# Diagnosi timeout del banco manager 0x700

Data 2026-11-04; firmware 1.1; analisi offline. [Audit ripetibile delle tracce e degli ELF](../Python_Trace_Scripts/s33_verify_manager700_timeout_audit.py): [3/3 PASS](../Risultati/GUI_S33/manager700_timeout_audit_20261104.json). Le tre esecuzioni diagnostiche sono state fermate dopo un secondo di traccia; non sono test di completamento della transizione.

## Risultati

1. Nel [primo esperimento con gate aperti](../Risultati/GUI_S33/key_scanner_manager700_cpu_20261104T105837794514Z/verified_evidence.json), il resolver carica il descrittore 0x989FCC e il manager invia 0x4403. Il suo callback punta a 0x7D252C, **assente dall'ELF del banco**: nella [traccia limitata](../Risultati/GUI_S33/manager700_timeout_trace_20261104/trace.txt) il simulatore ripete un salto a sé allo stesso indirizzo. Il payload verificato contiene istruzioni originali non nulle a quell'indirizzo. Il timeout è quindi spiegato, per questa corsa, da codice non caricato nel banco; non è prova di un blocco della fotocamera.
2. Nel [secondo esperimento](../Risultati/GUI_S33/key_scanner_lifecycle700_cpu_20261104T110049403082Z/verified_evidence.json) il callback ISO viene sostituito nel banco con uno stub che restituisce **1**. Il manager interpreta il risultato della consegna come redirect verso ID 1: il resolver legge il descrittore 0x7833CC dalla tabella e in seguito l'evento 0x4401 raggiunge 0x16A05C. Nell'ELF tale indirizzo ricade in un gap riempito di zeri, e la [traccia limitata](../Risultati/GUI_S33/manager700_iso_stub_trace_20261104/trace.txt) mostra il salto a sé. Il redirect è conseguenza della fixture, non comportamento dimostrato del callback ISO originale.
3. Nel [terzo esperimento](../Risultati/GUI_S33/key_scanner_lifecycle700_cpu_20261104T110159720669Z/verified_evidence.json), callback ISO e servizi 0x16A05C/0x16A188 sono stub; i ritorni del callback e di 0x16A188 sono impostati a -1. L'evento 0x4406 per CaptureMenu 0x9802AC raggiunge 0x16A1FC, anch'esso un gap a zero nell'ELF; la [traccia limitata](../Risultati/GUI_S33/manager700_lifecycle_trace_20261104/trace.txt) mostra il salto a sé. Il payload verificato contiene istruzioni non nulle anche qui.

La regressione dei [gate del manager](../Risultati/GUI_S33/key_scanner_manager700_cpu_20261104T110304872788Z/verified_evidence.json) passa ancora 8/8. Il verificatore dell'audit controlla le prime occorrenze di questi indirizzi, i frammenti significativi delle tracce, le mappature degli ELF e la presenza dei byte originali nei payload.

## Prossimo passo e limiti

Caricare nel banco le finestre originali e le loro dipendenze per 0x7D252C, 0x16A05C, 0x16A188 e 0x16A1FC, con dati e servizi lifecycle dichiarati; poi rieseguire il caso con gate aperti e verificare transizione e ritorni senza assumere che gli stub riproducano la fotocamera. Non è ancora dimostrata alcuna apertura di menu, inizializzazione ISO, selezione fisica, rendering o persistenza. **NON_INSTALLARE**.
