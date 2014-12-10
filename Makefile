nullfs: nullfs.c
	gcc -lfuse -o nullfs nullfs.c

install: nullfs
	rm -f /sbin/mount.nullfs
	cp nullfs /sbin/mount.nullfs
	chmod 755 /sbin/mount.nullfs
