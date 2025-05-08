# pam-unixsock

pam_unixsock is PAM module to send credentials to a unix socket. See pam_unixsock.8.md for more
information.

In `go/pamserve` you'll find a skeleton Go server that listen on the unix socket and echos back an
OK.

## Requirements

- The LibPAM development headers (libpam-dev or libpam0g-dev)
- A PAM-based system (currently only tested on Linux)

## Source Install

    make clean
    make all

And then copy it to:

    cp pam_unixsock.so /lib/security

Or for Ubuntu

    cp pam_unixsock.so /usr/lib/x86_64-linux-gnu/security

## Testing

Create a fake pam service called `unixsock`:

```
% cat /etc/pam.d/unixsock
#%PAM-1.0
auth       required     pam_unixsock.so
```

Open a reader on the socket:

```
# nc -lU /var/run/pam_unix.sock
```

Use pamtester to authenticate yourself; you can just use a fake password here.

```
% sudo pamtester unixsock $USER authenticate
```

## License

Copyright (c) 2007, 2013 Jamieson Becker

All rights reserved. This package is free software, licensed under the GNU
General Public License (GPL), version 2 or later.

No warranty is provided for this software. Please see the complete terms of
the GNU General Public License for details or contact the author.

Later versions Copyright (c) 2025 Miek Gieben
