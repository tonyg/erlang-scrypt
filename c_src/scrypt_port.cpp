#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#ifdef _WIN32
#include <Winsock2.h>
#else
#include <arpa/inet.h> /* ntohl, htonl */
#endif

#include "scrypt.h"

static uint32_t read_uint32(void) {
  uint32_t v = 0;
  size_t n = fread(&v, sizeof(uint32_t), 1, stdin);

  switch (n) {
    case 0:
      exit(0);

    case 1:
      break;

    default:
      perror("fread");
      exit(1);
  }

  return ntohl(v);
}

static void *read_buf(uint32_t len, char const *name) {
  void *buf = calloc(1, len);

  if (buf == NULL) {
    fprintf(stderr, "buffer allocation for %s failed\n", name);
    exit(1);
  }

  if (len > 0) {
    if (fread(buf, len, 1, stdin) != 1) {
      fprintf(stderr, "fread %s: %d (%s)\n", name, errno, strerror(errno));
      exit(1);
    }
  }

  return buf;
}

static void write_uint32(uint32_t v) {
  uint32_t v1 = htonl(v);
  if (fwrite(&v1, sizeof(uint32_t), 1, stdout) != 1) {
    perror("fwrite");
    exit(1);
  }
}

typedef struct {
    char *passwd;
    char *salt;
	struct {
		uint32_t packetlen;
		uint32_t passwdlen;
		uint32_t saltlen;
		uint32_t N;
		uint32_t r;
		uint32_t p;
		uint32_t buflen;
	} hdr;
} Cmd;

static Cmd *read_cmd()
{
    Cmd * cmd;
    uint32_t packetlen;
    size_t n;
	size_t offset = 2 * sizeof(char*) + sizeof(uint32_t);

	n = fread(&packetlen, sizeof(uint32_t), 1, stdin);
    switch (n) {
        case 0: exit(0);
        case 1: break;
        default:
			perror("fread");
			exit(1);
	}

    packetlen = ntohl(packetlen);

    cmd = (Cmd*)calloc(1, packetlen + offset);
	cmd->passwd = ((char*)cmd + 2 * sizeof(char*)) + sizeof(cmd->hdr);

	n = fread((char*)cmd + offset, 1, packetlen, stdin);
	if (n != packetlen) {
		perror("fread");
		exit(1);
	}

    cmd->hdr.packetlen = packetlen;
    cmd->hdr.passwdlen = ntohl(cmd->hdr.passwdlen);
    cmd->hdr.saltlen = ntohl(cmd->hdr.saltlen);
    cmd->hdr.N = ntohl(cmd->hdr.N);
    cmd->hdr.r = ntohl(cmd->hdr.r);
    cmd->hdr.p = ntohl(cmd->hdr.p);
    cmd->hdr.buflen = ntohl(cmd->hdr.buflen);
	cmd->salt = cmd->passwd + cmd->hdr.passwdlen;

    return cmd;
}

int main(int argc, char *argv[])
{
    Cmd * c = NULL;
	void * buf = NULL;
    uint32_t buffer_limit = 131072; /* 128k */

    if (argc > 1) {
        buffer_limit = atol(argv[1]);
    }

    while (1) {
		c = read_cmd();
		if (c == NULL) {
			fprintf(stderr, "command read failed\n");
			exit(1);
		}

		if ((c->hdr.passwdlen > buffer_limit) || (c->hdr.saltlen > buffer_limit) || (c->hdr.buflen > buffer_limit)) {
			fprintf(stderr, "buffer limit exceeded\n");
			exit(1);
		}

		buf = calloc(1, c->hdr.buflen);
		if (buf == NULL) {
			fprintf(stderr, "buffer allocation for buf failed\n");
			exit(1);
		}

		if (crypto_scrypt((const uint8_t*)c->passwd, c->hdr.passwdlen,
						  (const uint8_t*)c->salt, c->hdr.saltlen,
						  c->hdr.N, c->hdr.r, c->hdr.p,
						  (uint8_t*)buf, c->hdr.buflen)) {
			fprintf(stderr, "crypto_scrypt failed\n");
			exit(1);
		}

		write_uint32(c->hdr.buflen);

		if (fwrite(buf, c->hdr.buflen, 1, stdout) != 1) {
			perror("fwrite buf");
			exit(1);
		}

		fflush(stdout);

		free(c);
		free(buf);

		c = NULL;
		buf = NULL;
	}
}
