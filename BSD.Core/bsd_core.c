#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../include/bsd_constants.h"
#include "../include/bsd_core.h"
#include "../include/bsd_cipher.h"

// Генерация случайного ключа
static void generate_key(uint8_t *key, int key_len) {
    srand(time(NULL));
    for (int i = 0; i < key_len; i++) {
        key[i] = rand() % 256;
    }
}

// Сохранение PDB файла (отладочная инфа для восстановления)
static int save_pdb(const char *output_name, const uint8_t *key, int key_len, 
                    size_t text_len, const char *original_ext) {
    char pdb_path[512];
    snprintf(pdb_path, sizeof(pdb_path), "%s%s", output_name, PDB_SUFFIX);
    
    FILE *f = fopen(pdb_path, "wb");
    if (!f) return BSD_ERR_FILE;
    
    // Магия PDB
    uint32_t magic = 0x50444200; // "PDB\0"
    fwrite(&magic, 4, 1, f);
    
    // Версия
    uint32_t version = (BSD_VERSION_MAJOR << 16) | (BSD_VERSION_MINOR << 8) | BSD_VERSION_PATCH;
    fwrite(&version, 4, 1, f);
    
    // Ключ
    fwrite(key, 1, key_len, f);
    
    // Длина текста
    fwrite(&text_len, sizeof(size_t), 1, f);
    
    // Оригинальное расширение
    fwrite(original_ext, 1, strlen(original_ext) + 1, f);
    
    // Контрольная сумма (простая XOR всех байт ключа)
    uint8_t checksum = 0;
    for (int i = 0; i < key_len; i++) checksum ^= key[i];
    fwrite(&checksum, 1, 1, f);
    
    fclose(f);
    return BSD_OK;
}

// Попытка восстановить текст из PDB
static int recover_from_pdb(const char *input_name, char **recovered_text) {
    char pdb_path[512];
    strcpy(pdb_path, input_name);
    
    // Меняем расширение на _dump.pdb
    char *dot = strrchr(pdb_path, '.');
    if (dot) *dot = '\0';
    strcat(pdb_path, PDB_SUFFIX);
    
    FILE *f = fopen(pdb_path, "rb");
    if (!f) return BSD_ERR_NO_PDB;
    
    // Проверяем магию
    uint32_t magic, version;
    fread(&magic, 4, 1, f);
    fread(&version, 4, 1, f);
    
    if (magic != 0x50444200) {
        fclose(f);
        return BSD_ERR_INVALID;
    }
    
    // Читаем ключ
    uint8_t key[32];
    fread(key, 1, 32, f);
    
    // Читаем длину
    size_t text_len;
    fread(&text_len, sizeof(size_t), 1, f);
    
    // Выделяем память и читаем зашифрованный файл
    *recovered_text = malloc(text_len + 1);
    if (!*recovered_text) {
        fclose(f);
        return BSD_ERR_MEMORY;
    }
    
    // Читаем оригинальный файл
    FILE *data_f = fopen(input_name, "rb");
    if (!data_f) {
        free(*recovered_text);
        fclose(f);
        return BSD_ERR_FILE;
    }
    
    // Пропускаем заголовок контейнера (20 байт)
    fseek(data_f, 20, SEEK_SET);
    uint8_t *encrypted = malloc(text_len);
    fread(encrypted, 1, text_len, data_f);
    fclose(data_f);
    
    // Расшифровываем
    bsd_cipher_ctx ctx;
    bsd_cipher_init(&ctx, key, 32);
    bsd_cipher_decrypt(&ctx, encrypted, (uint8_t*)*recovered_text, text_len);
    
    (*recovered_text)[text_len] = '\0';
    free(encrypted);
    fclose(f);
    
    return BSD_OK;
}

// Основная функция шифрования текста
int bsd_encode_text(const char *text, const char *output_name, 
                    const char *ext, const char *custom_key) {
    size_t text_len = strlen(text);
    if (text_len > MAX_TEXT_LEN) {
        fprintf(stderr, "Text too long\n");
        return BSD_ERR_INVALID;
    }
    
    // Генерируем или используем кастомный ключ
    uint8_t key[32];
    int key_len = 32;
    
    if (custom_key) {
        // Парсим hex строку
        for (int i = 0; i < 32 && custom_key[i*2]; i++) {
            sscanf(&custom_key[i*2], "%2hhx", &key[i]);
        }
    } else {
        generate_key(key, key_len);
    }
    
    // Шифруем текст
    bsd_cipher_ctx ctx;
    bsd_cipher_init(&ctx, key, key_len);
    
    uint8_t *encrypted = malloc(text_len);
    if (!encrypted) return BSD_ERR_MEMORY;
    
    bsd_cipher_encrypt(&ctx, (const uint8_t*)text, encrypted, text_len);
    
    // Формируем путь выходного файла
    char output_path[512];
    snprintf(output_path, sizeof(output_path), "%s%s", output_name, ext);
    
    // Сохраняем контейнер
    FILE *f = fopen(output_path, "wb");
    if (!f) {
        free(encrypted);
        return BSD_ERR_FILE;
    }
    
    // Пишем магию
    uint32_t magic = BSD_MAGIC_STR;
    fwrite(&magic, 4, 1, f);
    
    // Пишем версию
    uint32_t version = (BSD_VERSION_MAJOR << 16) | (BSD_VERSION_MINOR << 8) | BSD_VERSION_PATCH;
    fwrite(&version, 4, 1, f);
    
    // Пишем длину данных
    fwrite(&text_len, sizeof(size_t), 1, f);
    
    // Резерв (8 байт под будущее)
    uint64_t reserved = 0;
    fwrite(&reserved, 8, 1, f);
    
    // Пишем зашифрованные данные
    fwrite(encrypted, 1, text_len, f);
    fclose(f);
    
    // Сохраняем PDB
    save_pdb(output_name, key, key_len, text_len, ext);
    
    free(encrypted);
    printf("[+] Encrypted: %s\n", output_path);
    printf("[+] PDB saved: %s%s\n", output_name, PDB_SUFFIX);
    
    return BSD_OK;
}

// Функция дешифрования файла
int bsd_decode_file(const char *input_path, const char *output_path) {
    FILE *f = fopen(input_path, "rb");
    if (!f) {
        // Пробуем восстановить из PDB
        char *recovered = NULL;
        int ret = recover_from_pdb(input_path, &recovered);
        if (ret == BSD_OK) {
            printf("[+] Recovered from PDB: %s\n", recovered);
            free(recovered);
            return BSD_OK;
        }
        fprintf(stderr, "Cannot open file and no PDB found\n");
        return BSD_ERR_FILE;
    }
    
    // Читаем заголовок
    uint32_t magic, version;
    size_t text_len;
    uint64_t reserved;
    
    fread(&magic, 4, 1, f);
    fread(&version, 4, 1, f);
    fread(&text_len, sizeof(size_t), 1, f);
    fread(&reserved, 8, 1, f);
    
    if (magic != BSD_MAGIC_STR && magic != BSD_MAGIC) {
        fclose(f);
        return BSD_ERR_INVALID;
    }
    
    // Читаем зашифрованные данные
    uint8_t *encrypted = malloc(text_len);
    fread(encrypted, 1, text_len, f);
    fclose(f);
    
    // Здесь нужен ключ — в реальности его откуда-то берут
    // Для демо просто выводим ошибку
    fprintf(stderr, "Need key to decode. Try using PDB recovery.\n");
    free(encrypted);
    return BSD_ERR_CIPHER;
} 