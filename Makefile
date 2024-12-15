CC = g++
CFLAGS = -fPIC -Wall -Wextra -std=c++17 -I./src
PLUGIN_CFLAGS = -shared $(CFLAGS) -fprofile-arcs -ftest-coverage
TEST_CFLAGS = -g $(CFLAGS)
LDFLAGS = -lmysqlclient -lssl -lcrypto -lgcov
GTEST_LDFLAGS = $(LDFLAGS) -lgtest -lgtest_main -pthread

BUILD_DIR = ./build
SRC_DIR = ./src
TEST_DIR = ./tests/unit

TARGET = $(BUILD_DIR)/openssl_encryption_udf.so
TEST_TARGET = $(BUILD_DIR)/test_runner

SRC_SOURCES = $(wildcard $(SRC_DIR)/*.cpp)
TEST_SOURCES = $(wildcard $(TEST_DIR)/*.cpp)

SRC_OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(SRC_SOURCES))
TEST_OBJS = $(patsubst $(TEST_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(TEST_SOURCES))

default: $(TARGET)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(BUILD_DIR)
	@echo "Compiling source: $<"
	$(CC) $(CFLAGS) -fprofile-arcs -ftest-coverage -c $< -o $@

$(TARGET): $(SRC_OBJS)
	@echo "Linking plugin: $@"
	$(CC) $(PLUGIN_CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(TEST_DIR)/%.cpp
	@mkdir -p $(BUILD_DIR)
	@echo "Compiling test: $<"
	$(CC) $(TEST_CFLAGS) -c $< -o $@

$(TEST_TARGET): $(SRC_OBJS) $(TEST_OBJS)
	@echo "Linking test runner: $@"
	$(CC) $(TEST_CFLAGS) -o $@ $(BUILD_DIR)/openssl_encrypt.o $(BUILD_DIR)/openssl_decrypt.o $(BUILD_DIR)/iv_generator.o $(BUILD_DIR)/openssl_encryption_test.o $(GTEST_LDFLAGS)

test: $(TEST_TARGET)
	@echo "Running unit tests..."
	$(TEST_TARGET)

cov:
	@echo "Collecting coverage data..."
	lcov --directory $(BUILD_DIR) --capture --output-file $(BUILD_DIR)/coverage.info --exclude '/usr/*'
	genhtml $(BUILD_DIR)/coverage.info --output-directory $(BUILD_DIR)/coverage_report

install: $(TARGET)
	@echo "Installing plugin to /usr/lib/mysql/plugin/"
	sudo cp $(TARGET) /usr/lib/mysql/plugin/

clean:
	@echo "Cleaning build directory..."
	$(RM) -r $(BUILD_DIR)
