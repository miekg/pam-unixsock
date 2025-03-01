#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <time.h>

#define DEFAULT_TIMEOUT 2
#define SOCKET_PATH "/var/run/pam_unix.sock"

bool debug = false;

#ifdef DBG
#undef DBG
#endif
#define DBG(x...) if (debug) { D(x); }

#define D(x...) do {							        \
  fprintf (stdout, "debug: %s:%d (%s): ", __FILE__, __LINE__, __FUNCTION__);	\
  fprintf (stdout, x);								\
  fprintf (stdout, "\n");							\
} while (0)

static int connect_to_socket(int timeout)
{
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
		close(sockfd);
		return -1;
	}
	return sockfd;
}

static int send_credentials(int sockfd, const char *username,
			    const char *service, const char *password, const char *prompt_response)
{
	dprintf(sockfd, "%s\n%s\n%s\n%s\n", username, service,
		password ? password : "", prompt_response ? prompt_response : "");
	char response;
	if (read(sockfd, &response, 1) == 1 && response == '1') {
		return PAM_SUCCESS;
	}
	return PAM_AUTH_ERR;
}

char *concat_with_space(const char *a, const char *b)
{
	if (!a) {
		return (char *)b;
	}

	size_t la = strlen(a);
	size_t lb = strlen(b);
	size_t len = la + lb + 2;	// +1 for space, +1 for null terminator

	char *result = malloc(len);
	if (!result)
		return NULL;

	snprintf(result, len, "%s %s", a, b);
	return result;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval;
	char *prompt = NULL;
	bool authtoken = true;
	bool hidden = false;
	int timeout = DEFAULT_TIMEOUT;

	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "hidden") == 0) {
			hidden = true;
			continue;
		}
		if (strcmp(argv[i], "no_authtok") == 0) {
			authtoken = false;
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

		prompt = concat_with_space(prompt, argv[i]);
	}

	if (prompt) {
		prompt = concat_with_space(prompt, "");	// adds trailing space
	}

	const char *username, *password, *service, *prompt_response = "";
	pam_get_user(pamh, &username, NULL);
	if (authtoken) {
		pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
	}
	pam_get_item(pamh, PAM_SERVICE, (const void **)&service);

	if (prompt) {
		struct pam_message msg[1];
		const struct pam_message *pmsg[1];
		struct pam_response *resp = NULL;
		struct pam_conv *conv;

		pam_get_item(pamh, PAM_CONV, (const void **)&conv);
		retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
		if (retval != PAM_SUCCESS) {
			DBG("get conv returned error: %s", pam_strerror(pamh, retval));
			return retval;
		}
		if (!conv || !conv->conv) {
			DBG("conv() function invalid");
			return PAM_CONV_ERR;
		}

		pmsg[0] = &msg[0];
		msg[0].msg = prompt;
		msg[0].msg_style = hidden ? PAM_PROMPT_ECHO_OFF : PAM_PROMPT_ECHO_ON;
		retval = conv->conv(1, pmsg, &resp, conv->appdata_ptr);
		if (retval != PAM_SUCCESS) {
			DBG("conv->conv returned error: %s", pam_strerror(pamh, retval));
			return retval;
		}
		prompt_response = resp->resp;
//              pam_prompt(pamh, (char **)&prompt_response, "%s", prompt); // for other pam modules?? option!?
	}
	free(prompt);

	int sockfd = connect_to_socket(timeout);
	if (sockfd < 0) {
		return PAM_SUCCESS;	// Assume success on timeout or failure to connect
	}

	retval = send_credentials(sockfd, username, service, password, prompt_response);
	close(sockfd);
	return retval;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}
