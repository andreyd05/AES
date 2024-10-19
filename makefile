CFLAGS = -Wall
LDFLAGS =
OBJFILES = aes_threads.o aes_util.o
TARGET = aes

all: $(TARGET)

$(TARGET): $(OBJFILES)
	g++ $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)
	del $(OBJFILES)

clean:
	del $(OBJFILES) $(TARGET).exe