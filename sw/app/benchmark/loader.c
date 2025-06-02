//
// Created by trist on 19/03/2025.
//
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "loader.h"

uint32_t * generate_random_32bit_words(int num_words)
{
    uint32_t * words = (uint32_t *)malloc(num_words * sizeof(uint32_t));
    if(!words)
    {
        perror("Erreur d'allocation mémoire");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < num_words; i++)
    {
        words[i] = (uint32_t) rand();
    }
    return words;
}


uint64_t * generate_random_64bit_words(int num_words)
{
    uint64_t * words = (uint64_t *)malloc(num_words * sizeof(uint64_t));
    if(!words)
    {
        perror("Erreur d'allocation mémoire");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < num_words; i++)
    {
        words[i] = (uint64_t)rand();
    }
    return words;
}


uint32_t *load_file(const char *filename, size_t *num_words)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        perror("Erreur d'ouverture du fichier");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    rewind(file);

    if(file_size % 4 != 0)
    {
        fprintf(stderr, "Erreur : Taille fichier non multiple de 4\n");
        fclose(file);
        return NULL;
    }

    *num_words = file_size / 4;

    uint32_t *words = (uint32_t *)malloc(*num_words * sizeof(uint32_t));
    if (!words)
    {
        perror("Erreur allocation mémoire");
        fclose(file);
        return NULL;
    }

    if(fread(words, 4, *num_words, file) != *num_words)
    {
        perror("Erreur lecture du fichier");
        free(words);
        fclose(file);
        return NULL;
    }

    fclose(file);
    return words;
}