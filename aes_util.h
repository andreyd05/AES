#ifndef AES_UTIL_H
#define AES_UTIL_H

#include <stdint.h>
#include <iostream>

typedef uint8_t byte;
typedef uint16_t hword;
typedef uint32_t word;

extern byte s_box[16][16];
extern byte inv_s_box[16][16];
extern byte GF_2_mult_table[256][256];

byte GF_2_mult(byte, byte);
word sub_word(word);
byte sub_byte(byte);
word rot_word(word);

word *generate_key_schedule(word[], word[], int, int);

byte *sub_bytes(byte[], byte[]);
word *shift_rows(word[]);
word *mix_columns(word[]);
word *add_round_key(word[], word[], int);

#endif