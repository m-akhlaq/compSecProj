all: do

do: explorer.c
	gcc explorer.c -o explorer

clean:
	rm explorer
