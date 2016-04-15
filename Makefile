CFLAGS=-c -fPIC -fno-stack-protector -Wall
LDFLAGS=-x --shared

all: pam_unshare.so

clean:
	rm -f pam_unshare.so pam_unshare.o

pam_unshare.o: src/pam_unshare.c
	$(CC) $(CFLAGS) src/pam_unshare.c

pam_unshare.so: pam_unshare.o
	$(LD) $(LDFLAGS) -o pam_unshare.so pam_unshare.o

