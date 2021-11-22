# Makefile for tgtdelegation
# Author: Connor McGarr (@33y0re)

# Flags and paths
CFLAGS := -Os -s
CXXFLAGS += -w
COMPILED := Compiled

# mingw shorthand declarations
CC_x64 := x86_64-w64-mingw32-gcc
STR_x64 := x86_64-w64-mingw32-strip
CC_x86 := i686-w64-mingw32-gcc
STR_x86 := i686-w64-mingw32-strip
RM := rm

tgtdelegation:
	@echo [+] Building tgtdelegation...
	$(CC_x64) -o $(COMPILED)/tgtdelegation.x64.o -c tgtdelegation.c $(CFLAGS) $(CXXFLAGS)
	$(STR_x64) -N tgtdelegation.c $(COMPILED)/tgtdelegation.x64.o
	$(CC_x86) -o $(COMPILED)/tgtdelegation.x86.o -c tgtdelegation.c $(CFLAGS) $(CXXFLAGS)
	$(STR_x86) -N tgtdelegation.c $(COMPILED)/tgtdelegation.x86.o

clean:
	$(RM) $(COMPILED)/*.o