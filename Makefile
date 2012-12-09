all:
	gcc dump4mkd.c -lpcap -lpopt -o dump4mkd
clean:
	rm dump4mkd
