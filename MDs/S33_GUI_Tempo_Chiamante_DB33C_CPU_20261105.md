# Tempo del menu nel frammento chiamante DB33C — 5 novembre 2026

**6/6 CPU emulata PASS; NON_INSTALLARE.** Dopo CaptureMenu → Akeru sintetico → pagina Nikon → modifica e conferma del tempo, il banco ora entra nel frammento originale `0xDB31C`. La traccia mostra `0xDB320 → 0xD8C20`, il ritorno e la chiamata originale `0xDB33C → 0xD8CA4 → 0xF6F54 → 0xFDA28`. Il banco controlla tempo, ISO e flag nel primo risultato e nella copia finale; lo stack ritorna al valore iniziale. Una fixture a `0xDB340` riporta il controllo al banco dopo il ritorno di `0xD8CA4`: la continuazione originale della funzione non viene eseguita.

| Tempo confermato | Limite sintetico | Risultato | Scenario | Cartella `Risultati/GUI_S33/…` |
|---:|---:|---:|---|---|
| 121 | 1000000 | 121000 | guardia occupata | `snapshot_capture_focus_original_cpu_20261105T192058577559Z_210434` |
| 119 | 1000000 | 119000 | discesa | `snapshot_capture_focus_original_cpu_20261105T192112182049Z_210822` |
| 121 | 20000 | 20000 | guardia occupata | `snapshot_capture_focus_original_cpu_20261105T192112145796Z_210820` |
| 119 | 20000 | 20000 | discesa | `snapshot_capture_focus_original_cpu_20261105T192112174317Z_210821` |
| 121 | 1000000 | 121000 | ritorno contestuale libero | `snapshot_capture_focus_original_cpu_20261105T192112152608Z_210823` |
| 121 | 1000000 | 121000 | ritorno con retry iniettato | `snapshot_capture_focus_original_cpu_20261105T192112193379Z_210824` |

L'ISO software è 125 e il flag del risultato 1 in ogni caso. Il confronto di regressione che chiama direttamente `0xD8CA4` passa nella cartella `snapshot_capture_focus_original_cpu_20261105T192112192702Z_210825`. [Verificatore](../Python_Trace_Scripts/s33_verify_snapshot_capture_focus_original_cpu.py), [prova precedente con chiamata diretta](S33_GUI_Tempo_Menu_Calcolo_CPU_20261105.md) e [individuazione statica dei siti chiamanti](S33_GUI_ISO_Soglia_e_Buffer_20261027.md).

Il banco entra nel frammento a metà funzione con `fp` e locali sintetici (`fp−16=4`, `fp−12=1`, `r13=0`); la funzione originale `0xD8C20` ritorna zero nel contesto scelto e `0xE3FF0` è sostituita da una fixture che ritorna zero. Contesto, ISO, limite, guardie, eventi e ordine sono imposti. Anche copia byte, dispatch, callback e il registratore che sostituisce confronto/ramo a `0xD8E22` sono fixture; DSP GNU è sperimentale. La presenza e l'esecuzione di questo frammento non dimostrano che sia raggiunto da un tasto di scatto reale, né la semantica fisica, AE, concorrenza o funzionamento del sensore. Nessun dispositivo o supporto modificato.

REA ARC/Ghidra ha letto e confrontato col payload V1.1 cinque finestre a `0xDB31C`, `0xDB33C`, `0xDB340`, `0xD8C20` e `0xE3FF0`: [evidenza statica](../Risultati/GUI_S33/rea_time_caller_bytes_20261105T192225Z/evidence.json). Non dimostra esecuzione o semantica.

Per risalire oltre il frammento, il disassemblaggio verificato mostra un prologo candidato a `0xDB138` e, a `0xDB1DE..0xDB1F8`, il caricamento iniziale di `fp−12` da `0x37FBD0+0x1A6` e di `fp−16` da `0x380A24+4`. [Finestre e ulteriore esecuzione PASS](../Risultati/GUI_S33/snapshot_capture_focus_original_cpu_20261105T192239002118Z_213077/). È evidenza statica: istruzioni intermedie possono modificare quei locali e il test CPU continua a imporli, quindi non prova la loro provenienza al momento della chiamata.
