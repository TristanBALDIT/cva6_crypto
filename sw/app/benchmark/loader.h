//
// Created by trist on 19/03/2025.
//

#ifndef LOADER_H
#define LOADER_H

uint32_t *load_file(const char *filename, size_t *num_words);
uint32_t * generate_random_32bit_words(int num_words);
uint64_t * generate_random_64bit_words(int num_words);

#endif //LOADER_H
