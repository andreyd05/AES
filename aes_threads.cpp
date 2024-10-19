#define NUM_THREADS 12

#include <iostream>
#include <fstream>
#include <time.h>
#include <vector>
#include <string>
#include <thread>
//#include <mutex>
//#include <condition_variable>
#include <stdint.h>
#include <sys/stat.h>
#include "aes_util.h"


typedef uint8_t byte;
typedef uint32_t word;

//std::mutex m;
//std::condition_variable cv;


bool c_strcmp(const char *s1, const char *s2) {
    for(int i = 0; s1[i] || s2[i]; i++) {
        if(s1[i] != s2[i]) { return false; }
    }

    return true;
}

bool c_strcontains(const char *s1, const char *s2) {
    for(int i = 0; s1[i] && s2[i]; i++) {
        if(s1[i] != s2[i]) { return false; }
    }

    return true;
}

void trim_file_ext(std::string &in, std::string &out) {
    int last_dot = 0;
    int len = in.length();

    for(int i = 0; i < len; i++) {
        if(in.at(i) == '.') { last_dot = i; }
    }

    if(c_strcmp(in.c_str() + last_dot + 1, "aes")) {
        for(int i = 0; i < last_dot; i++) {
            out += in.at(i);
        }

    } else {
        out = in + ".dec";
    }
}

void concat_partitions(int num_files, const char *output) {
    std::ofstream o(output, std::ios_base::binary | std::ios_base::app);
    std::string partition;

    for(int i = 0; i < num_files; i++) {
        partition = ".out" + std::to_string(i) + ".aes";
        std::ifstream p(partition.c_str(), std::ios_base::binary);

        o << p.rdbuf();
        p.close();

        remove(partition.c_str());
    }

    o.close();
}

class worker_thread {
    public:
        static const char *input;
        static word key[4];
        static word schedule[44];
    

        static void worker_thread_enc_init(int id, size_t start, size_t end, bool eof) {
            byte state1[16];
            byte state2[16];
            std::string output = ".out" + std::to_string(id) + ".aes";
            FILE *in = fopen(input, "rb");
            FILE *out = fopen(output.c_str() , "wb");
            
            fseek(in, start, SEEK_SET);
            
            while(start <= end) {
                if(start == end && !eof) { break; }

                fread(state1, 1, 16, in);
                start += 16;

                if(eof && start > end) {
                    byte _pad = (start - end ? start - end : 16);
                    
                    for(int i = 0; i < _pad; i++) {
                        state1[15 - i] = _pad;
                    }
                }

                // add_round_key
                for(int i = 0; i < 4; i++) {
                    ((word *) state1)[i] ^= schedule[i];
                }

                for(int r = 0; r < 9; r++) {
                    // sub_bytes
                    for(int i = 0; i < 16; i++) {
                        state1[i] = s_box[state1[i] >> 4][state1[i] & 15];
                    }

                    // shift_rows
                    state2[0] = state1[0];
                    state2[4] = state1[4];
                    state2[8] = state1[8];
                    state2[12] = state1[12];

                    for(int i = 1; i < 4; i++) {
                        state2[i] = state1[5 * i];
                        state2[i + 4] = state1[(5 * i + 4) % 16];
                        state2[i + 8] = state1[(5 * i + 8) % 16];
                        state2[i + 12] = state1[(5 * i + 12) % 16];
                    }

                    // mix_columns
                    for(int i = 0; i < 4; i++) {
                        state1[4 * i] = GF_2_mult_table[2][state2[4 * i]] ^ GF_2_mult_table[3][state2[4 * i + 1]] ^ state2[4 * i + 2] ^ state2[4 * i + 3];
                        state1[4 * i + 1] = GF_2_mult_table[2][state2[4 * i + 1]] ^ GF_2_mult_table[3][state2[4 * i + 2]] ^ state2[4 * i + 3] ^ state2[4 * i];
                        state1[4 * i + 2] = GF_2_mult_table[2][state2[4 * i + 2]] ^ GF_2_mult_table[3][state2[4 * i + 3]] ^ state2[4 * i] ^ state2[4 * i + 1];
                        state1[4 * i + 3] = GF_2_mult_table[2][state2[4 * i + 3]] ^ GF_2_mult_table[3][state2[4 * i]] ^ state2[4 * i + 1] ^ state2[4 * i + 2];
                    }

                    // add_round_key
                    for(int i = 0; i < 4; i++) {
                        ((word *) state1)[i] ^= schedule[4 * (r + 1) + i];
                    }
                }

                // sub_bytes
                for(int i = 0; i < 16; i++) {
                    state1[i] = s_box[state1[i] >> 4][state1[i] & 15];
                }

                // shift_rows
                state2[0] = state1[0];
                state2[4] = state1[4];
                state2[8] = state1[8];
                state2[12] = state1[12];

                for(int i = 1; i < 4; i++) {
                    state2[i] = state1[5 * i];
                    state2[i + 4] = state1[(5 * i + 4) % 16];
                    state2[i + 8] = state1[(5 * i + 8) % 16];
                    state2[i + 12] = state1[(5 * i + 12) % 16];
                }

                // add_round_key
                for(int i = 0; i < 4; i++) {
                    ((word *) state2)[i] ^= schedule[40 + i];
                }
                
                fwrite(state2, 1, 16, out);
            }

            fclose(out);
            fclose(in);
        }

        static void worker_thread_dec_init(int id, size_t start, size_t end, bool eof) {
            byte state1[16];
            byte state2[16];
            std::string output = ".out" + std::to_string(id) + ".aes";
            FILE *in = fopen(input, "rb");
            FILE *out = fopen(output.c_str() , "wb");
            
            fseek(in, start, SEEK_SET);

            while(start < end) {
                fread(state2, 1, 16, in);
                start += 16;

                // inv_add_round_key
                for(int i = 0; i < 4; i++) {
                    ((word *) state2)[i] ^= schedule[40 + i];
                }

                for(int r = 8; r >= 0; r--) {
                    // inv_shift_rows
                    state1[0] = state2[0];
                    state1[4] = state2[4];
                    state1[8] = state2[8];
                    state1[12] = state2[12];

                    for(int i = 1; i < 4; i++) {
                        state1[5 * i] = state2[i];
                        state1[(5 * i + 4) % 16] = state2[i + 4];
                        state1[(5 * i + 8) % 16] = state2[i + 8];
                        state1[(5 * i + 12) % 16] = state2[i + 12];
                    }

                    // inv_sub_bytes
                    for(int i = 0; i < 16; i++) {
                        state1[i] = inv_s_box[state1[i] >> 4][state1[i] & 15];
                    }

                    // inv_add_round_key
                    for(int i = 0; i < 4; i++) {
                        ((word *) state1)[i] ^= schedule[4 * (r + 1) + i];
                    }

                    // inv_mix_columns
                    for(int i = 0; i < 4; i++) {
                        state2[4 * i] = GF_2_mult_table[14][state1[4 * i]] ^ GF_2_mult_table[11][state1[4 * i + 1]] ^ GF_2_mult_table[13][state1[4 * i + 2]] ^ GF_2_mult_table[9][state1[4 * i + 3]];
                        state2[4 * i + 1] = GF_2_mult_table[14][state1[4 * i + 1]] ^ GF_2_mult_table[11][state1[4 * i + 2]] ^ GF_2_mult_table[13][state1[4 * i + 3]] ^ GF_2_mult_table[9][state1[4 * i]];
                        state2[4 * i + 2] = GF_2_mult_table[14][state1[4 * i + 2]] ^ GF_2_mult_table[11][state1[4 * i + 3]] ^ GF_2_mult_table[13][state1[4 * i]] ^ GF_2_mult_table[9][state1[4 * i + 1]];
                        state2[4 * i + 3] = GF_2_mult_table[14][state1[4 * i + 3]] ^ GF_2_mult_table[11][state1[4 * i]] ^ GF_2_mult_table[13][state1[4 * i + 1]] ^ GF_2_mult_table[9][state1[4 * i + 2]];
                    }
                }

                // inv_shift_rows
                state1[0] = state2[0];
                state1[4] = state2[4];
                state1[8] = state2[8];
                state1[12] = state2[12];

                for(int i = 1; i < 4; i++) {
                    state1[5 * i] = state2[i];
                    state1[(5 * i + 4) % 16] = state2[i + 4];
                    state1[(5 * i + 8) % 16] = state2[i + 8];
                    state1[(5 * i + 12) % 16] = state2[i + 12];
                }

                // inv_sub_bytes
                for(int i = 0; i < 16; i++) {
                    state1[i] = inv_s_box[state1[i] >> 4][state1[i] & 15];
                }

                // inv_add_round_key
                for(int i = 0; i < 4; i++) {
                    ((word *) state1)[i] ^= schedule[i];
                }


                if(eof && start >= end) { fwrite(state1, 1, 16 - state1[15], out); }
                else { fwrite(state1, 1, 16, out); }
            }

            fclose(out);
            fclose(in);
        }
};

const char *worker_thread::input;
word worker_thread::key[4];
word worker_thread::schedule[44];

int main(int argc, char *argv[]) {
    int partition_size;
    std::vector<std::thread> thread_list;
    std::string input;
    std::string output;
    bool key_set = false;
    bool out_set = false;
    bool input_set = false;
    char enc = -1;
    struct timespec ts;
    struct stat st;
    
    for(int i = 1; i < argc; i++) {
        if(c_strcmp(argv[i], "-e")) { enc = 1; }
        else if(c_strcmp(argv[i], "-d")) { enc = 0; }
        else if(c_strcontains(argv[i], "--key=")) {
            FILE *k = fopen(argv[i] + 6, "rb");
            fread(worker_thread::key, 4, 4, k);
            fclose(k);
            key_set = true;
        
        } else if(c_strcontains(argv[i], "--out=")) {
            output = argv[i] + 6;
            out_set = true;

        } else {
            input = argv[i];
            input_set = true;
        }
    }

    if(enc < 0) {
        std::cout << "Please include a encrypt/decrypt flag [-e|-d]\n";
        exit(1);

    } else if(!key_set) {
        std::cout << "Please include the key flag [--key=key_file_name]\n";
        exit(1);

    } else if(!input_set) {
        std::cout << "Usage: .\\aes.exe [input_filename] [-e|-d] [--key=key_filename] [(optional) --out=output_filename]\n";
        exit(1);
    }

    worker_thread::input = input.c_str();

    if(!out_set) {
        if(enc) { output = input + ".aes"; }
        else { trim_file_ext(input, output); }
    }
    
    fclose(fopen(output.c_str(), "wb"));    // clear file

    stat(input.c_str(), &st);
    partition_size = ((st.st_size / NUM_THREADS) / 16) * 16;


    // make multiplication table
    for(int i = 0; i < 256; i++) {
        for(int j = 0; j < 256; j++) {
            GF_2_mult_table[i][j] = GF_2_mult(i, j);
        }
    }


    generate_key_schedule(worker_thread::key, worker_thread::schedule, 4, 10);
 
    size_t _offset = 0;

    if(st.st_size < 16 * 16 * NUM_THREADS) {
        thread_list.emplace_back((enc ? worker_thread::worker_thread_enc_init : worker_thread::worker_thread_dec_init), 0, 0, st.st_size, true);

        thread_list[0].join();

        concat_partitions(1, output.c_str());
    
    } else {
        for(int i = 0; i < NUM_THREADS - 1; i++) {
            thread_list.emplace_back((enc ? worker_thread::worker_thread_enc_init : worker_thread::worker_thread_dec_init), i, _offset, _offset + partition_size, false);

            _offset += partition_size;
        }
        
        thread_list.emplace_back((enc ? worker_thread::worker_thread_enc_init : worker_thread::worker_thread_dec_init), NUM_THREADS - 1, _offset, st.st_size, true);
        
        for(int i = 0; i < NUM_THREADS; i++) {
            thread_list[i].join();
        }

        concat_partitions(NUM_THREADS, output.c_str());
    }


    return 0;
}