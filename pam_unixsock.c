#define _GNU_SOURCE
#include <errno.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_TIMEOUT 10
#define SOCKET_PATH "/var/run/pam_unix.sock"

/*
 * matchsk matches the string to see if it was a security key (sk).
 * Example test match:
 * "publickey sk-ssh-ed25519@openssh.com
 * AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIPkPxpwWvlgbEC6rEv15cULdMvfc3ai4fmskptv+WhmQAAAABHNzaDo="
 */
bool matchsk(const char *s) {
  // Shortcut empty string check
  if (s == NULL || *s == '\0') {
    return false;
  }

  // Make a copy since strtok modifies the string
  char *copy = strdup(s);
  if (copy == NULL) {
    return false; // Memory allocation failed
  }

  bool result = false;
  char *saveptr = NULL;

  // First token must be "publickey"
  char *token = strtok_r(copy, " ", &saveptr);
  if (token == NULL || strcmp(token, "publickey") != 0) {
    goto cleanup;
  }

  // Second token must start with "sk-" and end with "@openssh.com"
  token = strtok_r(NULL, " ", &saveptr);
  if (token == NULL) {
    goto cleanup;
  }

  size_t token_len = strlen(token);
  const char *prefix = "sk-";
  const char *suffix = "@openssh.com";
  size_t prefix_len = strlen(prefix);
  size_t suffix_len = strlen(suffix);

  // Check prefix and suffix
  if (strncmp(token, prefix, prefix_len) != 0) {
    goto cleanup;
  }

  if (token_len < suffix_len ||
      strcmp(token + token_len - suffix_len, suffix) != 0) {
    goto cleanup;
  }

  // If we got here, all checks passed
  result = true;

cleanup:
  free(copy);
  return result;
}

static int connect_to_socket(int timeout) {
  int sockfd;
  struct sockaddr_un addr;
  struct timeval tv;

  sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sockfd < 0) {
    return sockfd;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

  tv.tv_sec = timeout;
  tv.tv_usec = 0;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    syslog(LOG_ERR, "pam_unixsock(:auth): connect to socket %s failed: %s",
           SOCKET_PATH, strerror(errno));
    close(sockfd);
    return -1;
  }
  return sockfd;
}

static int send_credentials(int sockfd, bool debug, const char *username,
                            const char *service, const char *module,
                            const char *prompt_response, const char *env) {

  dprintf(sockfd, "%s\n%s\n%s\n%s\n%s\n", username, service, module,
          prompt_response ? prompt_response : "", env ? env : "");
  char response;
  if (debug) {
    syslog(LOG_INFO,
           "pam_unixsock(%s:auth): wrote credentials to socket %s for %s",
           service, SOCKET_PATH, username);
  }
  if (read(sockfd, &response, 1) == 1 && response == '1') {
    if (debug) {
      syslog(LOG_INFO,
             "pam_unixsock(%s:auth): positive response from server seen for %s",
             service, username);
    }
    return PAM_SUCCESS;
  }
  // if we got here, due to a timeout of the request, we can't really say
  // PAM_SUCCESS, because then everything would OK all requests...
  return PAM_AUTH_ERR;
}

char *concat_with_space(const char *a, const char *b) {
  if (!a) {
    return (char *)b;
  }

  size_t la = strlen(a);
  size_t lb = strlen(b);
  size_t len = la + lb + 2; // +1 for space, +1 for null terminator

  char *result = malloc(len);
  if (!result)
    return NULL;

  snprintf(result, len, "%s %s", a, b);
  return result;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
  int retval;
  char *prompt = NULL;
  bool hidden = false;
  bool failopen = false;
  bool debug = false;
  int timeout = DEFAULT_TIMEOUT;

  for (int i = 0; i < argc; i++) {
    if (strcmp(argv[i], "hidden") == 0) {
      hidden = true;
      continue;
    }
    if (strcmp(argv[i], "debug") == 0) {
      debug = true;
      continue;
    }
    if (strncmp(argv[i], "timeout=", 8) == 0) {
      timeout = atoi(argv[i] + 8);
      continue;
    }
    if (strncmp(argv[i], "failopen", 8) == 0) {
      failopen = true;
      continue;
    }
    prompt = concat_with_space(prompt, argv[i]);
  }

  if (prompt) {
    prompt = concat_with_space(prompt, ""); // adds trailing space
  }

  const char *ssh_auth_info_0 = pam_getenv(pamh, "SSH_AUTH_INFO_0");
  // if ssh_auth_info_0 contains the following we detected a security key, we
  // allow access if seen and shortcut the whole procedure:
  //    publickey sk-ssh-ed25519@openssh.com \
  //    AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIPkPxpwWvlgbEC6rEv15cULdMvfc3ai4fmskptv+WhmQAAAABHNzaDo=
  if (matchsk(ssh_auth_info_0)) {
    syslog(LOG_INFO, "pam_unixsock(auth): security key seen %s",
           ssh_auth_info_0);
    return PAM_SUCCESS;
  }

  const char *username, *service, *prompt_response = "";
  pam_get_user(pamh, &username, NULL);
  pam_get_item(pamh, PAM_SERVICE, (const void **)&service);

  if (prompt) {
    struct pam_message msg[1];
    const struct pam_message *pmsg[1];
    struct pam_response *resp = NULL;
    struct pam_conv *conv;

    retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (retval != PAM_SUCCESS) {
      syslog(LOG_ERR, "pam_unixsock(:auth): get conv returned error: %s",
             pam_strerror(pamh, retval));
      return PAM_CONV_ERR;
    }
    if (!conv || !conv->conv) {
      syslog(LOG_ERR, "pam_unixsock(:auth): conv() function invalid");
      return PAM_CONV_ERR;
    }

    pmsg[0] = &msg[0];
    msg[0].msg = prompt;
    msg[0].msg_style = hidden ? PAM_PROMPT_ECHO_OFF : PAM_PROMPT_ECHO_ON;
    retval = conv->conv(1, pmsg, &resp, conv->appdata_ptr);
    if (retval != PAM_SUCCESS) {
      syslog(LOG_ERR, "pam_unixsock(:auth): conv->conv returned error: %s",
             pam_strerror(pamh, retval));
      return PAM_CONV_ERR;
    }
    prompt_response = resp->resp;
  }
  free(prompt);

  int sockfd = connect_to_socket(timeout);
  if (sockfd < 0) {
    if (!failopen) {
      return PAM_AUTH_ERR;
    }
    return PAM_SUCCESS;
  }

  retval = send_credentials(sockfd, debug, username, service, "auth",
                            prompt_response, ssh_auth_info_0);
  close(sockfd);
  return retval;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv) {
  return PAM_SUCCESS;
}
