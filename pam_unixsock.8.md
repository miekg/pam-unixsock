%%%
title="pam_unixsock 8"
area="Linux-PAM Manual"
date=2025-03-02
[[author]]
fullname="Miek Gieben"
%%%

# NAME

pam_unixsock - PAM module to send credentials to a unix socket

# Synopsis

**pam_unixsock.so** [**hidden**] [**no_authtok**] [**timeout**] [**debug**] [*PROMPT*]

# Description

This code is a pluggable authentication module (PAM) that redirects the credentials to a local Unix
socket. The server listening on that socket is then free to do many more complex things, because
it's free from the calling process' address space. The Unix socket defaults to
`/var/run/pam_unix.sock`. The protocol is described below and is fairly simplistic. If *PROMPT* is
given, the text is used to prompt the user for another authentication token.

# Options

**debug**
:  print debug information

**no_authtok**
:  do not ask for a password (yet again)

**timeout**
:  set the timeout in seconds for how long to wait for a response from the server, the default is
   `timeout=2`

**hidden**
:  when prompting for another authentication token, hide the input


# Protocol

**pam_unixsock** implements an extremely simple socket protocol whereby it passes an username, the
PAM service, a potential password and second token (2FA, see the extra prompt stuff) (separated by
new lines) to the Unix socket and then your server simply replies with a 0 or 1:

    [pam_unixsock]   john_smith\n
    [pam_unixsock]   <pam_service>\n
    [pam_unixsock]   <pam_authtok>\n
    [pam_unixsock]   <prompt>\n
    [your server]    1\n

If your server answers within `timeout` (2 by default) with a `1` you are authenticated.

# Example

    auth       required     pam_unixsock.so no_authtok Enter 2FA:

# Author
