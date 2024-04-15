/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */
// Adapted from the public domain, estream code by D. Bernstein.
// Adapted by Zondax

#include "chacha.h"
#include "app_main.h"
#include "coin.h"
#include "cx.h"
#include "os.h"
#include "zxmacros.h"

#define U8TO32_LITTLE(p)                                                       \
  (((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) |                          \
   ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))
// sigma contains the ChaCha constants, which happen to be an ASCII string.
static const uint8_t sigma[16] = {'e', 'x', 'p', 'a', 'n', 'd', ' ', '3',
                                  '2', '-', 'b', 'y', 't', 'e', ' ', 'k'};
#define ROTATE(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
// QUARTERROUND updates a, b, c, d with a ChaCha "quarter" round.
#define QUARTERROUND(a, b, c, d)                                               \
  x[a] += x[b];                                                                \
  x[d] = ROTATE(x[d] ^ x[a], 16);                                              \
  x[c] += x[d];                                                                \
  x[b] = ROTATE(x[b] ^ x[c], 12);                                              \
  x[a] += x[b];                                                                \
  x[d] = ROTATE(x[d] ^ x[a], 8);                                               \
  x[c] += x[d];                                                                \
  x[b] = ROTATE(x[b] ^ x[c], 7);

void CRYPTO_hchacha20(uint8_t out[32], const uint8_t key[32],
                      const uint8_t nonce[16]) {
  uint32_t x[16];
  MEMCPY(x, sigma, sizeof(sigma));
  MEMCPY(&x[4], key, 32);
  MEMCPY(&x[12], nonce, 16);
  for (size_t i = 0; i < 20; i += 2) {
    QUARTERROUND(0, 4, 8, 12)
    QUARTERROUND(1, 5, 9, 13)
    QUARTERROUND(2, 6, 10, 14)
    QUARTERROUND(3, 7, 11, 15)
    QUARTERROUND(0, 5, 10, 15)
    QUARTERROUND(1, 6, 11, 12)
    QUARTERROUND(2, 7, 8, 13)
    QUARTERROUND(3, 4, 9, 14)
  }
  MEMCPY(out, &x[0], sizeof(uint32_t) * 4);
  MEMCPY(&out[16], &x[12], sizeof(uint32_t) * 4);
}

#define U32TO8_LITTLE(p, v)                                                    \
  {                                                                            \
    (p)[0] = (v >> 0) & 0xff;                                                  \
    (p)[1] = (v >> 8) & 0xff;                                                  \
    (p)[2] = (v >> 16) & 0xff;                                                 \
    (p)[3] = (v >> 24) & 0xff;                                                 \
  }

// chacha_core performs 20 rounds of ChaCha on the input words in
// |input| and writes the 64 output bytes to |output|.
void chacha_core(uint8_t *output, const uint32_t *input) {
  uint32_t x[16];
  int i;
  MEMCPY(x, input, sizeof(uint32_t) * 16);
  for (i = 20; i > 0; i -= 2) {
    QUARTERROUND(0, 4, 8, 12)
    QUARTERROUND(1, 5, 9, 13)
    QUARTERROUND(2, 6, 10, 14)
    QUARTERROUND(3, 7, 11, 15)
    QUARTERROUND(0, 5, 10, 15)
    QUARTERROUND(1, 6, 11, 12)
    QUARTERROUND(2, 7, 8, 13)
    QUARTERROUND(3, 4, 9, 14)
  }
  for (i = 0; i < 16; ++i) {
    x[i] += input[i];
  }
  for (i = 0; i < 16; ++i) {
    U32TO8_LITTLE(output + 4 * i, x[i]);
  }
}

void chacha(uint8_t *out, const uint8_t *in, size_t in_len, const uint8_t *key,
            const uint8_t *nonce, uint32_t counter) {
  uint32_t input[16];
  uint8_t buf[64];
  size_t todo, i;
  input[0] = U8TO32_LITTLE(sigma + 0);
  input[1] = U8TO32_LITTLE(sigma + 4);
  input[2] = U8TO32_LITTLE(sigma + 8);
  input[3] = U8TO32_LITTLE(sigma + 12);
  input[4] = U8TO32_LITTLE(key + 0);
  input[5] = U8TO32_LITTLE(key + 4);
  input[6] = U8TO32_LITTLE(key + 8);
  input[7] = U8TO32_LITTLE(key + 12);
  input[8] = U8TO32_LITTLE(key + 16);
  input[9] = U8TO32_LITTLE(key + 20);
  input[10] = U8TO32_LITTLE(key + 24);
  input[11] = U8TO32_LITTLE(key + 28);
  input[12] = counter;
  input[13] = U8TO32_LITTLE(nonce + 0);
  input[14] = U8TO32_LITTLE(nonce + 4);
  input[15] = U8TO32_LITTLE(nonce + 8);
  while (in_len > 0) {
    todo = sizeof(buf);
    if (in_len < todo) {
      todo = in_len;
    }
    chacha_core(buf, input);
    io_seproxyhal_io_heartbeat();
    for (i = 0; i < todo; i++) {
      out[i] = in[i] ^ buf[i];
    }
    out += todo;
    in += todo;
    in_len -= todo;
    input[12]++;
  }
}
