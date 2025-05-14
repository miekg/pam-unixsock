%%%
title="pam_unixsock 8"
area="Linux-PAM Manual"
date=2025-03-02
[[author]]
fullname="Miek Gieben"
%%%

# NAME

pam_unixsock - PAM module to send credentials to a Unix socket

# Synopsis

**pam_unixsock.so** [**hidden**] [**failopen**] [**timeout**] [**debug**] [*PROMPT*]

# Description

This is a pluggable authentication module (PAM) that redirects the credentials to a local Unix
socket. The server listening on that socket is then free to do many more complex things, because
it's free from the calling process' address space. The Unix socket defaults to
`/var/run/pam_unix.sock`. The protocol is described below and is fairly simplistic. If _PROMPT_ is
given, the text is used to prompt the user for another (2FA) authentication token. This module only
implements the _auth_ module.

If the user authenticated with SSH and `SSH_AUTH_INFO_0` contains a security key; everything is side stepped
and the user is allowed without prompting for a second factor.

# Options

**debug**
: log debug information with `syslog(3)`.

**timeout**
: set the timeout in seconds for how long to wait for a response from the server, the default is
`timeout=2`.

**hidden**
: when prompting for another authentication token, hide the input.

**failopen**
: when set ignore failures to _connect_ to the Unix socket and returns PAM_SUCCESS.

# Protocol

**pam_unixsock** implements an extremely simple socket protocol whereby it passes an username, the
PAM module and service, the second token (i.e. **PROMPT**), and the environment variable
`SSH_AUTH_INFO_0` (separated by new lines) to the Unix socket and then your server simply replies with a 0 or 1:

    [pam_unixsock]   john_smith\n
    [pam_unixsock]   <pam_module>\n
    [pam_unixsock]   <pam_service>\n
    [pam_unixsock]   <prompt>\n
    [pam_unixsock]   <env>\n
    [your server]    1\n

If your server answers within `timeout` with a `1` you are considered authenticated.

**pam_module**
: this will be a string like "auth", or "passwd", etc.

**pam_service**
: name of the calling process as given to PAM, i.e. "sshd".

**prompt**
: the input that the user provided for **PROMPT**

**env**
: the contents of the environment variable `SSH_AUTH_INFO_0` (this comes from OpenSSH), or empty if
it's not found.

# Configuration

With Ubuntu (24.04), in `/etc/pam.d/sshd`:

    # Standard Un*x authentication.
    @include common-auth

    # add this line
    auth required pam_unixsock.so debug Enter 2FA token:

If you want to pace the 2fa rollout, you can use pam_succeed_if.so, to skip (success=1) 2fa module
when the user is not in the 2fa group.

    auth [success=1] required pam_succeed_if.so user notingroup 2fa
    auth required pam_unixsock.so debug Enter 2FA token:

## SSH

In the `sshd` configuration be sure to add:

```
KbdInteractiveAuthentication yes
UsePAM yes
```

Note that with public key authentication this is bypassed, and you log in without being asked for a
second token.

# Notes

In Fedora the socket can't be written to by sshd because selinux does not allow it.

If you get the error when using `sshd`:

    pam_unixsock(sshd:auth): conv->conv returned error: Conversation error

Be sure to have enabled `ChallengeResponseAuthentication yes` in the sshd configuration.

# Author
