# S33 V1.1 — lunghezza CFA richiesta e file osservato, 31 ottobre 2026

La prova GNU del ramo diagnostico `0x1E6A54 → 0x28D66C`, con dimensioni sintetiche 4208 × 3152, ha registrato dalla chiamata al backend di scrittura due lunghezze diverse a seconda del campo di contesto `+8`:

| Campo di contesto | Lunghezza richiesta alla fixture |
|---:|---:|
| 2 | 26.527.232 byte |
| 1 | 19.895.424 byte |

Entrambi i casi passano: [risultati e tracce](../Risultati/HiddenMenu_RAW/cfa_geometry_cpu_20261031T204237921289Z/verified_evidence.json). L'arrotondamento a 16 non cambia queste dimensioni; il prodotto viene rispettivamente raddoppiato o moltiplicato per 3 e diviso per 2. Il backend è una fixture che registra puntatore e lunghezza e restituisce un conteggio imposto uguale alla richiesta: non legge realmente i 19 o 26 MB e non prova né capacità né scrittura su file. Il modello GNU DSP usato è sperimentale; evento, contesto, dati e servizi sono sintetici. Il banco entra direttamente nel frammento e si ferma a `0x1E6ACC`.

Nel workspace attuale è stato confrontato integralmente `CFAi1012.raw` con `DSCo1012.raw`: header CFAi 20.808 byte, dimensioni nell'header 4208 × 3152, payload 13.263.616 byte uguale alla prima metà del DSCo da 26.527.232 byte. SHA-256 rispettivi `0c7328612445eaf5803b91023166a19ce53916440233a5d3c3f8943696887a85` e `314cc266a2224b38cfcfb3fcac0cfe5af89c483fa43e3309a8db535fe8e9b97f`. Né il payload né la dimensione totale del CFAi, 13.284.424 byte, coincidono con le due richieste nel banco per quelle dimensioni. Non è provato che header e payload provengano da scritture separate: [prova successiva su conteggi brevi](S33_RAW_CFA_Scrittura_Parziale_Geometria_CPU_20261031.md).

Per aritmetica senza overflow, le dimensioni arrotondate sono multipli di 16: quindi la richiesta del primo ramo è multipla di 512 e quella dell'altro di 384. Il payload osservato lascia resto 256 in entrambi i casi. Questo confronto **non identifica la causa**: non sappiamo se il file provenga da questo percorso, se il contesto corrisponda ai campi dell'header, né se intervengano scritture parziali o altre trasformazioni. Una richiesta non equivale a byte effettivamente scritti o persistiti. Non ne deriva una capacità di buffer né un punto sicuro per inserire il processore Mono RAW.

La precedente [analisi delle dieci coppie](S33_RawsAnalysis_Struttura_e_Risultati_20261029.md) resta evidenza storica; il verificatore storico che richiede tutte e dieci le coppie non è riproducibile nello stato attuale perché non tutte sono presenti direttamente in `RawsAnalysis`. I file sono stati solo letti. **NON_INSTALLARE**.

Riproduzione CPU: `python3 Python_Trace_Scripts/s33_verify_cfa_menu_dispatcher_cpu.py --geometry`. Regressione dei sei scenari preesistenti: [PASS](../Risultati/HiddenMenu_RAW/cfa_menu_dispatcher_cpu_20261031T2042751638Z/verified_evidence.json).
