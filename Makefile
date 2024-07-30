CC = g++
TARGET = pcap-test
SRCS = main.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ -lpcap

%.o: %.cpp
	$(CC) -c $< -o $@

clean-obj:
	rm -f $(OBJS)

clean: clean-obj
	rm -f $(TARGET)

.PHONY: all clean clean-obj