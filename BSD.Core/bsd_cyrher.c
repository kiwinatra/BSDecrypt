#include <string.h>
#include "../include/bsd_cipher.h"

// Инициализация S-бокса (Key Scheduling Algorithm)
void bsd_cipher_init(bsd_cipher_ctx *ctx, const uint8_t *key, int key_len) {
    // Сохраняем ключ
    if (key_len > 32) key_len = 32;
    memcpy(ctx->key, key, key_len);
    ctx->key_len = key_len;
    ctx->position = 0;
    ctx->prev_cipher = 0;
    
    // Инициализация S-бокса значениями 0..255
    for (int i = 0; i < 256; i++) {
        ctx->S[i] = i;
    }
    
    // Перемешивание S-бокса ключом (как в RC4)
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + ctx->S[i] + key[i % key_len]) % 256;
        // Swap
        uint8_t temp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = temp;
    }
    
    // Дополнительный проход для усиления (своя мутация)
    j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + ctx->S[i] + ctx->S[(i + 128) % 256]) % 256;
        uint8_t temp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = temp;
    }
}

// Генерация псевдослучайного байта с мутацией
static uint8_t next_byte(bsd_cipher_ctx *ctx) {
    static int i = 0, j = 0;
    
    // Если позиция 0 — сбрасываем счётчики
    if (ctx->position == 0) {
        i = 0;
        j = 0;
    }
    
    i = (i + 1) % 256;
    j = (j + ctx->S[i]) % 256;
    
    // Swaps
    uint8_t temp = ctx->S[i];
    ctx->S[i] = ctx->S[j];
    ctx->S[j] = temp;
    
    // Добавляем мутацию от позиции и предыдущего зашифрованного байта
    uint8_t mutation = (ctx->position % 256) ^ ctx->prev_cipher;
    uint8_t result = ctx->S[(ctx->S[i] + ctx->S[j] + mutation) % 256];
    
    ctx->position++;
    return result;
}

// Шифрование (прямой проход)
void bsd_cipher_encrypt(bsd_cipher_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len) {
    for (size_t n = 0; n < len; n++) {
        uint8_t keystream = next_byte(ctx);
        out[n] = in[n] ^ keystream;
        ctx->prev_cipher = out[n];  // Обратная связь
    }
}

// Дешифрование (обратный проход — для симметричного шифра то же самое)
void bsd_cipher_decrypt(bsd_cipher_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len) {
    for (size_t n = 0; n < len; n++) {
        uint8_t keystream = next_byte(ctx);
        out[n] = in[n] ^ keystream;
        ctx->prev_cipher = in[n];   // Важно: используем входной байт для обратной связи
    }
}