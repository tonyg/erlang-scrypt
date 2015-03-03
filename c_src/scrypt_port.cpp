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

#include "crypto_scrypt.h"

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

int main(int argc, char *argv[]) {
  uint32_t buffer_limit = 131072; /* 128k */

  if (argc > 1) {
    buffer_limit = atol(argv[1]);
  }

  while (1) {
    uint32_t packetlen;
    uint32_t passwdlen;
    uint32_t saltlen;
    uint32_t N;
    uint32_t r;
    uint32_t p;
    uint32_t buflen;
    void *passwd;
    void *salt;
    void *buf;

    packetlen = read_uint32(); /* ignored for now */

    passwdlen = read_uint32();
    saltlen = read_uint32();
    N = read_uint32();
    r = read_uint32();
    p = read_uint32();
    buflen = read_uint32();

    if ((passwdlen > buffer_limit) || (saltlen > buffer_limit) || (buflen > buffer_limit)) {
      fprintf(stderr, "buffer limit exceeded\n");
      exit(1);
    }

    passwd = read_buf(passwdlen, "passwd");
    salt = read_buf(saltlen, "salt");

    buf = calloc(1, buflen);
    if (buf == NULL) {
      fprintf(stderr, "buffer allocation for buf failed\n");
      exit(1);
    }

    if (crypto_scrypt((const uint8_t*)passwd, passwdlen, (const uint8_t*)salt, saltlen, N, r, p, (uint8_t*)buf, buflen)) {
      fprintf(stderr, "crypto_scrypt failed\n");
      exit(1);
    }

    write_uint32(buflen);
    if (fwrite(buf, buflen, 1, stdout) != 1) {
      perror("fwrite buf");
      exit(1);
    }
    fflush(stdout);

    free(passwd);
    free(salt);
    free(buf);
  }
}
