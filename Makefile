# CC auto-detection
# GCC v4.7.x (or later)	: `CC = g++'
# GCC v4.5.x or v4.6.x	: `CC = gcc'

# skip auto-detection when `CC' is (explicitly) defined in the command line
ifneq ($(origin CC),"command line")
GCCVER = $(shell $(CC) -dumpversion | cut -d. -f-2 | sed 's/\.//')
ifeq ($(GCCVER),47)
CC = g++
endif
ifeq ($(GCCVER),46)
CC = gcc
endif
ifeq ($(GCCVER),45)
CC = gcc
endif
endif

# `CC' version check 
GCCVER = $(shell $(CC) -dumpversion | cut -d. -f-2 | sed 's/\.//')
ifneq ($(GCCVER),47)
ifneq ($(GCCVER),46)
ifneq ($(GCCVER),45)
$(error Bad GCC version, please install v4.5.x, v4.6.x, or 4.7.x)
endif
endif
endif

CFLAGS	= -DIN_GCC -fPIC -shared -O2 -fvisibility=hidden	\
	-Wall -Wno-unused-variable 				\
	-I`$(CC) --print-file-name=plugin/include`		\
	-lbsd -DDEBUG

# do not make changes below this line
SRC		= kguard.c
SHARED_OBJ	= $(SRC:.c=.so)

# phony targets
.PHONY: all clean

# default target
all: $(SHARED_OBJ)

# build the shared library
$(SHARED_OBJ): $(SRC) $(SRC:.c=.h)
	$(CC) $(CFLAGS) $(SRC) -o $@

# clean
clean:
	rm -rf $(SHARED_OBJ)
