BUILD_DIR ?= ./build
SRC_DIR ?= ./src
PRIV_DIR ?= ./priv

TARGET ?= hamlin.bin

CC ?= clang
CXX ?= clang++

CPPFLAGS += -MD -g
CFLAGS += -Wall -O2 -g -fsanitize=address
CXXFLAGS += -Wall -std=c++17 -O2 -g -fsanitize=address
LDFLAGS += -std=c++17 -lstdc++fs -O3 -lasan

SRCS := $(wildcard $(SRC_DIR)/*.cpp) $(wildcard $(SRC_DIR)/**/*.cpp)
OBJS := $(SRCS:$(SRC_DIR)/%.cpp=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

$(BUILD_DIR)/$(TARGET): $(OBJS)
	$(CXX) $(filter-out ./build/pngtest.o,$(OBJS)) -o $@ $(LDFLAGS)
	#strip -s $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

.PHONY: clean docker

run: $(BUILD_DIR)/$(TARGET)
	$<

clean:
	rm -rf $(BUILD_DIR)

-include $(DEPS)
