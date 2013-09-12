all:
	gcc -g -Wall -Wextra -o mrinfo mrinfo.c output.c -lpcap
clean:
	rm -fv ./mrinfo ./mrinfo.o ./output.o
