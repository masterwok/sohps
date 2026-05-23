CC = gcc
CFLAGS = -Wall -Wextra -fPIC
LDFLAGS = -L./build -Wl,--no-as-needed -lcustom

BIN_DIR = bin
BUILD_DIR = build
SRC = main.c

all: setup_env binaries

setup_env:
	mkdir -p $(BIN_DIR) $(BUILD_DIR)
	
	# Clean up any lingering read-only directories from previous runs
	-chmod -R 777 /tmp/sohps_test /tmp/sohps_readonly /tmp/sohps_writable_file 2>/dev/null
	
	mkdir -p /tmp/sohps_test /tmp/sohps_readonly /tmp/sohps_writable_file
	
	# Create a vulnerable rootfs simulation for System Preload audit
	mkdir -p /tmp/sohps_test/etc
	chmod 777 /tmp/sohps_test/etc
	
	# Ensure libcustom.so is in /tmp/sohps_test for absolute linking
	$(CC) $(CFLAGS) -shared -o /tmp/sohps_test/libcustom.so libcustom.c
	
	# 1. Writable Dir, Missing File
	chmod 777 /tmp/sohps_test
	mkdir -p /tmp/sohps_test/missing
	chmod 777 /tmp/sohps_test/missing
	
	# 2. Read-Only Dir
	chmod 555 /tmp/sohps_readonly
	
	# 3. Writable File, RO Dir
	rm -f /tmp/sohps_writable_file/libcustom.so
	touch /tmp/sohps_writable_file/libcustom.so
	chmod 666 /tmp/sohps_writable_file/libcustom.so
	chmod 555 /tmp/sohps_writable_file

$(BUILD_DIR)/libcustom.so: libcustom.c
	$(CC) $(CFLAGS) -shared -o $@ $^

binaries: $(BUILD_DIR)/libcustom.so
	# --- Hijack Analyzer Target Binaries ---
	
	# 1. Writable Path (Absolute)
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -Wl,-rpath,/tmp/sohps_test -o $(BIN_DIR)/test_writable_path
	
	# 2. Writable File (Injection)
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -Wl,-rpath,/tmp/sohps_writable_file -o $(BIN_DIR)/test_writable_file
	
	# 3. Missing Library in Writable Dir
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -Wl,-rpath,/tmp/sohps_test/missing -o $(BIN_DIR)/test_missing_writable
	
	# 4. Implicit CWD (Empty Path)
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -Wl,-rpath,: -o $(BIN_DIR)/test_implicit_cwd
	
	# 5. $ORIGIN Hijack
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -Wl,-rpath,'$$ORIGIN/../lib' -o $(BIN_DIR)/test_origin
	
	# 6. Relative Path
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -Wl,-rpath,./lib -o $(BIN_DIR)/test_relative
	
	# 7. Absolute Path (DT_NEEDED containing '/')
	# We link directly against the .so path to force an absolute DT_NEEDED entry
	$(CC) $(CFLAGS) $(SRC) /tmp/sohps_test/libcustom.so -o $(BIN_DIR)/test_needed_abs
	
	# --- ELF Parser & Edge Case Target Binaries ---
	# Force legacy DT_RPATH
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -Wl,--disable-new-dtags -Wl,-rpath,/tmp/sohps_test/rpath -o $(BIN_DIR)/test_rpath
	# Force modern DT_RUNPATH
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -Wl,--enable-new-dtags -Wl,-rpath,/tmp/sohps_test/runpath -o $(BIN_DIR)/test_runpath
	# Multiple colon-separated paths
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -Wl,--enable-new-dtags -Wl,-rpath,/tmp/sohps_test/one:/tmp/sohps_test/two -o $(BIN_DIR)/test_colon_split
	# Nodefaultlib (-z nodefaultlib)
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -Wl,-z,nodefaultlib -Wl,-rpath,/tmp/sohps_test/nodeflib -o $(BIN_DIR)/test_nodeflib

clean:
	-chmod -R 777 /tmp/sohps_test /tmp/sohps_readonly /tmp/sohps_writable_file 2>/dev/null
	rm -rf $(BIN_DIR) $(BUILD_DIR) /tmp/sohps_test /tmp/sohps_readonly /tmp/sohps_writable_file
