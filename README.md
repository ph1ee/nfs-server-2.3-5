# Running legacy NFSv2 server on Ubuntu 12.04

Remove built-in NFS packages.

```sh
$ sudo apt-get purge nfs-common nfs-kernel-server
```

Build and install this legacy one.

```sh
$ ./configure --prefix=/usr --enable-multiple-servers
$ make
$ sudo checkinstall make install
```

Edit */etc/exports*
```
/rootfs 10.0.0.0/255.255.0.0(rw,sync,no_root_squash)
```

Run NFS server

```sh
$ sudo ./S60nfs
```
