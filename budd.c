/*
 * COPYRIGHT AND PERMISSION NOTICE
 *
 * Copyright (c) 2016, John Keeping <john@keeping.me.uk>
 *
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Except as contained in this notice, the name of a copyright holder shall not
 * be used in advertising or otherwise to promote the sale, use or other
 * dealings in this Software without prior written authorization of the
 * copyright holder.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>

#include <getopt.h>

#include <curl/curl.h>

/* XXX: NoIP only supports IPv4, so we do too. */
#define MAX_IP_LEN	16

#define BUDD_USERAGENT	\
	"BUDD/" BUDD_VERSION


enum log_level {
	LOG_DEBUG,
	LOG_INFO,
	LOG_WARN,
	LOG_ERROR,
};

struct buf {
	size_t alloc;
	size_t sz;
	char *data;
};
#define BUF_INC		1024

static struct {
	const char *ip_url;
	const char *update_url;

	enum log_level log_threshold;
	FILE *log_file;

	const char *target_host;
	const char *username;
	const char *password;;

	char public_ip[MAX_IP_LEN + 1];
	char target_ip[MAX_IP_LEN + 1];
} state = {
	.ip_url = "http://ip1.dynupdate.no-ip.com/",
	.update_url = "https://dynupdate.no-ip.com/nic/update",

	.log_threshold = LOG_INFO,
};

static void __attribute__((noreturn, format(printf, 1, 2)))
die(const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(1);
}

static void __attribute__((noreturn, format(printf, 1, 2)))
die_errno(const char *msg, ...)
{
	int err = errno;
	va_list ap;
	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);

	fprintf(stderr, ": %s\n", strerror(err));
	exit(1);
}

static void __attribute__((noreturn, format(printf, 2, 3)))
die_curl(CURLcode cres, const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);

	fprintf(stderr, ": %s\n", curl_easy_strerror(cres));
	exit(1);
}

static void __attribute__((format(printf, 2, 3)))
log_msg(enum log_level level, const char *msg, ...)
{
	static const char *const level_names[] = {
		[LOG_DEBUG] = "DEBUG",
		[LOG_INFO] = "INFO",
		[LOG_WARN] = "WARNING",
		[LOG_ERROR] = "ERROR",
	};
	va_list ap;
	if (level < state.log_threshold)
		return;

	va_start(ap, msg);
	fprintf(state.log_file, "[%s] ", level_names[level]);
	vfprintf(state.log_file, msg, ap);
	fprintf(state.log_file, "\n");
	va_end(ap);
}

#define log_debug(...)	log_msg(LOG_DEBUG, __VA_ARGS__)
#define log_info(...)	log_msg(LOG_INFO, __VA_ARGS__)
#define log_warn(...)	log_msg(LOG_WARN, __VA_ARGS__)
#define log_error(...)	log_msg(LOG_ERROR, __VA_ARGS__)

static char *xstrdup(const char *s)
{
	char *r = strdup(s);
	if (!r)
		die("out of memory");
	return r;
}

static int sane_isspace(char c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static char *strip_ws(char *v)
{
	char *end;
	while (sane_isspace(*v))
		v++;

	end = v + strlen(v);
	if (end != v)
		end--;

	while (end != v && sane_isspace(*end))
		*end-- = '\0';

	return v;
}

static size_t buf_write_cb(char *ptr,
		size_t size, size_t nmemb, void *user)
{
	struct buf *buf = user;
	size_t realsize = size * nmemb;

	if ((buf->alloc - buf->sz) < realsize) {
		size_t newsize = buf->alloc + BUF_INC;
		char *newdata = realloc(buf->data, newsize);
		if (!newdata)
			return 0;

		buf->data = newdata;
		buf->alloc = newsize;
	}

	memcpy(buf->data + buf->sz, ptr, realsize);
	buf->sz += realsize;

	return realsize;
}

static size_t public_ip_write_cb(char *ptr,
		size_t size, size_t nmemb, void *user)
{
	size_t *offset = user;
	size_t len = size * nmemb;
	if (len + *offset > MAX_IP_LEN)
		len = MAX_IP_LEN - *offset;

	if (len)
		memcpy(state.public_ip + *offset, ptr, len);
	*offset += len;
	return len;
}

static CURLcode get_public_ip(void)
{
	CURLcode cres;
	size_t offset = 0;
	CURL *curl = curl_easy_init();
	if (!curl)
		return CURLE_FAILED_INIT;

	curl_easy_setopt(curl, CURLOPT_USERAGENT, BUDD_USERAGENT);
	curl_easy_setopt(curl, CURLOPT_URL, state.ip_url);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, public_ip_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &offset);

	log_debug("requesting public IP from %s", state.ip_url);
	cres = curl_easy_perform(curl);
	if (cres == CURLE_OK)
		log_debug("public IP: %s", state.public_ip);
	else
		log_error("failed to get public IP: %s",
				curl_easy_strerror(cres));

	curl_easy_cleanup(curl);
	return cres;
}

static int get_target_ip(void)
{
	struct addrinfo *info, *ai;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
	};
	int ret;

	log_debug("looking up current IP for %s", state.target_host);
	ret = getaddrinfo(state.target_host, NULL, &hints, &info);
	if (ret) {
		log_error("failed to get current target IP: %s\n",
			gai_strerror(ret));
		return -1;
	}

	for (ai = info; ai; ai = ai->ai_next) {
		struct sockaddr_in *addr = (struct sockaddr_in *) ai->ai_addr;
		if (inet_ntop(ai->ai_family, &addr->sin_addr,
				state.target_ip,
				sizeof(state.target_ip) - 1))
			break;
	}

	if (ai) {
		log_debug("result: %s", state.target_ip);
		ret = 0;
	} else {
		log_warn("failed to get current target IP: no address found");
		ret = -1;
	}
	freeaddrinfo(info);
	return ret;
}

static CURLcode check_result(struct buf *b, bool *fatal)
{
	char nul = '\0';
	char *s, *end;
	*fatal = false;

	/* Ensure buffer is null-terminated. */
	if (buf_write_cb(&nul, 1, 1, b) != 1)
		return CURLE_OUT_OF_MEMORY;

	s = strip_ws(b->data);
	log_debug("response: %s", s);
	end = strchrnul(s, ' ');
	*end = '\0';

	if (!strcmp(s, "good") || !strcmp(s, "nochg"))
		return CURLE_OK;

	*end = ' ';
	if (!strcmp(s, "911")) {
		log_warn("server will not accept request now: %s", s);
		return CURLE_ABORTED_BY_CALLBACK;
	}

	/* Everything else is fatal. */
	*fatal = true;
	if (!strcmp(s, "nohost"))
		log_error("hostname not found under specified account");
	else if (!strcmp(s, "badauth"))
		log_error("bad authentication credentials");
	else if (!strcmp(s, "badagent"))
		log_error("client has been disabled by server");
	else if (!strcmp(s, "!donator"))
		log_error("requested feature is not available to current user");
	else if (!strcmp(s, "abuse"))
		log_error("user is blocked due to abuse");
	return CURLE_ABORTED_BY_CALLBACK;
}

static CURLcode send_update(void)
{
	CURLcode cres = CURLE_OUT_OF_MEMORY;
	bool fatal_error;
	char *url = NULL, *hostname = NULL, *ip = NULL;
	struct buf result_buf = { 0 };
	CURL *curl = curl_easy_init();
	if (!curl)
		return CURLE_FAILED_INIT;

	hostname = curl_easy_escape(curl, state.target_host, 0);
	ip = curl_easy_escape(curl, state.public_ip, 0);
	if (!hostname || !ip)
		goto out;

	if (asprintf(&url, "%s?hostname=%s&myip=%s",
			state.update_url, hostname, ip) < 0)
		goto out;

	curl_easy_setopt(curl, CURLOPT_USERAGENT, BUDD_USERAGENT);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, buf_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result_buf);

	/* NoIP only supports basic auth. */
	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, (long) CURLAUTH_BASIC);
	curl_easy_setopt(curl, CURLOPT_USERNAME, state.username);
	curl_easy_setopt(curl, CURLOPT_PASSWORD, state.password);

	log_debug("sending request %s", url);
	cres = curl_easy_perform(curl);

	if (cres != CURLE_OK) {
		log_error("failed to update IP for %s: %s",
			state.target_host, curl_easy_strerror(cres));
		goto out;
	}

	cres = check_result(&result_buf, &fatal_error);
	if (cres == CURLE_OK)
		log_info("updated IP for %s to %s",
			state.target_host, state.public_ip);

out:
	curl_free(hostname);
	curl_free(ip);
	curl_easy_cleanup(curl);
	free(url);
	free(result_buf.data);
	return cres;
}

static void handle_config_entry(const char *key, const char *value)
{
	if (!strcasecmp(key, "ip-url"))
		state.ip_url = xstrdup(value);
	else if (!strcasecmp(key, "update-url"))
		state.update_url = xstrdup(value);
	else if (!strcasecmp(key, "host"))
		state.target_host = xstrdup(value);
	else if (!strcasecmp(key, "username"))
		state.username = xstrdup(value);
	else if (!strcasecmp(key, "password"))
		state.password = xstrdup(value);
	else
		die("unknown config key: %s", key);
}

static void load_config(const char *filename)
{
	char *line = NULL;
	size_t line_len = 0;
	FILE *f = fopen(filename, "r");
	if (!f)
		die_errno("failed to open config file '%s'", filename);

	while (getline(&line, &line_len, f) >= 0) {
		char *key = line, *value;

		/* Comments must start in column zero. */
		if (*line == '#')
			continue;

		value = strchr(key, '=');
		if (value) {
			*value++ = '\0';
			value = strip_ws(value);
		}
		key = strip_ws(key);

		if (!(value && *value) && *key)
			die("invalid config entry: %s", key);

		if (*key)
			handle_config_entry(key, value);
	}

	if (!feof(f))
		die_errno("failed to read config file '%s'", filename);

	free(line);
	fclose(f);

	if (!state.target_host)
		die("'host' not specified in config");
	if (!state.username)
		die("'username' not specified in config");
	if (!state.password)
		die("'password' not specified in config");
}

static void usage(FILE *f)
{
	fprintf(f, "usage: budd [--force] --config <file>\n");
}

static const struct option long_opts[] = {
	{ "--config",	required_argument,	0, 'c' },
	{ "--force",	no_argument,		0, 'f' },
	{ "--help",	no_argument,		0, 'h' },
	{ NULL }
};

int main(int argc, char *argv[])
{
	CURLcode cres;
	int force = 0, c;
	const char *config_file = NULL;
	state.log_file = stderr;

	while ((c = getopt_long(argc, argv, "c:fh", long_opts, NULL)) >= 0) {
		switch (c) {
		case 'c':
			config_file = optarg;
			break;
		case 'f':
			force = 1;
			break;
		case 'h':
			usage(stdout);
			return 0;
		case '?':
			die("unknown option: %s", optarg);
		default:
			die("BUG: unhandled option: %s", optarg);
		}
	}

	if (!config_file)
		die("no configuration file specified");

	load_config(config_file);

	cres = curl_global_init(CURL_GLOBAL_DEFAULT);
	if (cres != CURLE_OK)
		die_curl(cres, "Failed to initialize curl");

	cres = get_public_ip();
	if (cres != CURLE_OK)
		die_curl(cres, "Failed to get public IP");

	if (get_target_ip() || force ||
	    strcmp(state.public_ip, state.target_ip))
		send_update();
	else
		log_info("skipping update: IP is already correct");

	curl_global_cleanup();
	return 0;
}
