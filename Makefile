TARGET = armv7-unknown-linux-gnueabihf
PLUGIN_DIR = lcpreader.koplugin/libs

.PHONY: kobo install clean

kobo:
	cargo build --release -p plugin --target $(TARGET)
	arm-unknown-linux-gnueabihf-gcc -shared -nostdlib \
	  -o target/libreadium_lcp.so \
	  -Wl,--whole-archive \
	    target/$(TARGET)/release/libreadium_lcp.a \
	  -Wl,--no-whole-archive -lgcc

install: kobo
	cp target/libreadium_lcp.so $(PLUGIN_DIR)/

clean:
	rm -f target/libreadium_lcp.so
