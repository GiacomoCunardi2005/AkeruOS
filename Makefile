CC := arc-snps-elf-gcc
OBJDUMP := arc-snps-elf-objdump
SIZE := arc-snps-elf-size

CFLAGS := -mcpu=arc700 -mno-sdata -O2 -ffreestanding -fno-builtin -Wall -Wextra

.RECIPEPREFIX := >
.PHONY: all clean disasm gnu-verify gnu-tbib gnu-clock gnu-main gnu-dsp-verify gnu-div-verify gnu-aux-verify gnu-mul-verify gnu-device-verify gnu-control-verify gnu-srdelay-verify gnu-main-clock100 gnu-irq-hint-verify gnu-main-irq-empty
.PHONY: runtime-devices-verify
.PHONY: gnu-gui-pipeline-verify
.PHONY: mono-scanline-verify
.PHONY: menu-model-verify menu-queue-model-verify menu-back-queue-verify menu-manager-model-verify menu-descriptor-model-verify mono-raw-verify color-pipeline-verify
.PHONY: ram-dump-verify ram-dump-sd-io-verify ram-dump-sd-marker-verify
.PHONY: usb-ram-core-verify usb-ram-client-verify usb-ram-transfers-verify usb-ram-worker-verify usb-ram-controller-start-verify
.PHONY: usb-ram-open-buffer-verify
.PHONY: usb-ram-worker-lifetime-verify
.PHONY: usb-ram-queue-consumer-verify
.PHONY: usb-ram-irq-dispatch-verify
.PHONY: usb-ram-controller-config-verify
.PHONY: usb-ram-controller-init-verify
.PHONY: usb-ram-parent-startup-verify
.PHONY: usb-ram-device-completion-verify
.PHONY: usb-ram-transport-verify usb-ram-application-verify usb-ram-class-lifecycle-verify usb-ram-class-close-verify

all: build/main.o

# Independent diagnostic object; no task hook or Nikon API addresses are bound.
build/ram_dump.o: ram_dump.c ram_dump.h
>mkdir -p build
>$(CC) $(CFLAGS) -Werror -c $< -o $@
>$(SIZE) $@

# Write/close component only; no complete SD session or firmware image.
build/nikon_v11_sd_io.o: nikon_v11_sd_io.c nikon_v11_sd_io.h
>mkdir -p build
>$(CC) $(CFLAGS) -mlong-calls -Werror -c $< -o $@
>$(SIZE) $@

build/nikon_v11_sd_marker.o: nikon_v11_sd_marker.c nikon_v11_sd_marker.h
>mkdir -p build
>$(CC) $(CFLAGS) -mlong-calls -Werror -c $< -o $@
>$(SIZE) $@

build/main.o: main.c
>mkdir -p build
>$(CC) $(CFLAGS) -c $< -o $@
>$(SIZE) $@

disasm: build/main.o
>$(OBJDUMP) -d $<

clean:
>rm -f build/*.o

# Offline GNU ARC700; firmware originale e installazione GNU montati in sola lettura.
gnu-verify:
>python3 ../Python_Trace_Scripts/s33_run_gnu_arc700.py verify

gnu-tbib:
>python3 ../Python_Trace_Scripts/s33_run_gnu_arc700.py tbib --trace

gnu-clock:
>python3 ../Python_Trace_Scripts/s33_run_gnu_arc700.py clock

gnu-main:
>python3 ../Python_Trace_Scripts/s33_run_gnu_main.py

gnu-gui-pipeline-verify:
>python3 ../Python_Trace_Scripts/s33_verify_gui_pipeline_cpu.py

# Prototype only; original callback selection is unchanged.
mono-scanline-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_mono_scanline.py
>python3 ../Python_Trace_Scripts/s33_verify_gui_mono_graphics_prototype_cpu.py -3
>python3 ../Python_Trace_Scripts/s33_verify_gui_mono_graphics_prototype_cpu.py 0

# Offline isolated navigation model; no camera bindings.
menu-model-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_menu.py

menu-back-queue-verify:
>python3 ../Python_Trace_Scripts/s33_verify_gui_original_queue_back_menu_cpu.py

color-pipeline-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_color_pipeline.py

mono-raw-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_mono_raw.py
>python3 ../Python_Trace_Scripts/s33_verify_mono_raw_equivalence.py
>python3 ../Python_Trace_Scripts/s33_verify_mono_raw_real_crops.py

menu-queue-model-verify:
>python3 ../Python_Trace_Scripts/s33_verify_gui_original_queue_menu_cpu.py

menu-manager-model-verify:
>python3 ../Python_Trace_Scripts/s33_verify_gui_original_manager_menu_cpu.py

menu-descriptor-model-verify:
>python3 ../Python_Trace_Scripts/s33_verify_gui_synthetic_descriptor_menu_cpu.py

gnu-dsp-verify:
>python3 ../Python_Trace_Scripts/s33_verify_gnu_dsp_lab.py

gnu-div-verify:
>python3 ../Python_Trace_Scripts/s33_verify_gnu_tbib_arithmetic.py

gnu-aux-verify:
>python3 ../Python_Trace_Scripts/s33_verify_gnu_aux_fixed.py

gnu-mul-verify:
>python3 ../Python_Trace_Scripts/s33_verify_gnu_tbib_arithmetic.py --multiply

gnu-device-verify:
>python3 ../Python_Trace_Scripts/s33_verify_gnu_boot_device_writes.py

gnu-control-verify:
>python3 ../Python_Trace_Scripts/s33_verify_gnu_boot_control_cluster.py

gnu-srdelay-verify:
>python3 ../Python_Trace_Scripts/s33_verify_gnu_srdelay.py

gnu-main-clock100:
>python3 ../Python_Trace_Scripts/s33_run_gnu_main.py --dsp-lab --clock100-lab

gnu-irq-hint-verify:
>python3 ../Python_Trace_Scripts/s33_verify_gnu_irq_hint.py

gnu-main-irq-empty:
>python3 ../Python_Trace_Scripts/s33_run_gnu_main.py --dsp-lab --clock100-lab --irq-hint-empty-lab

# P-code runtime laboratory: original dispatch, iris GPIO/completion and TIMER1.
runtime-devices-verify:
>python3 ../Python_Trace_Scripts/s33_run_runtime_devices.py

ram-dump-verify:
>python3 ../Python_Trace_Scripts/s33_verify_ram_dumper.py

ram-dump-sd-io-verify:
>python3 ../Python_Trace_Scripts/s33_verify_ram_dump_sd_io_port.py

ram-dump-sd-marker-verify:
>python3 ../Python_Trace_Scripts/s33_verify_ram_dump_sd_marker.py

usb-ram-core-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_usb_ram_core.py

usb-ram-client-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_ramdump_client.py

usb-ram-transfers-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_usb_transfers.py

usb-ram-worker-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_usb_worker.py

usb-ram-controller-start-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_usb_controller_start.py

usb-ram-open-buffer-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_usb_open_buffer.py

usb-ram-worker-lifetime-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_usb_worker_lifetime.py

usb-ram-queue-consumer-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_usb_queue_consumer.py

usb-ram-irq-dispatch-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_usb_irq_dispatch.py

usb-ram-controller-config-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_usb_controller_config.py

usb-ram-controller-init-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_usb_controller_init.py

usb-ram-parent-startup-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_usb_parent_startup.py

usb-ram-device-completion-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_usb_device_completion.py

usb-ram-transport-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_usb_ram_transport.py

usb-ram-application-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_usb_application.py

usb-ram-class-lifecycle-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_usb_class_lifecycle.py

usb-ram-class-close-verify:
>python3 ../Python_Trace_Scripts/s33_verify_akeru_usb_class_close.py
