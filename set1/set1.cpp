#include "set1.h"
#include <cmath>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <vector>

using namespace std;

string* breakSingleKey(string cipher_hex) {
    string* best_key = new string;
    double best_score = 0.;
    for (int i = 0; i < 256; i += 1) {
        string key_hex = "";
        stringstream stream;
        stream << hex << i;
        string key_hex_sub(stream.str());
        while (key_hex_sub.length() < 2) {
            key_hex_sub = '0' + key_hex_sub;
        }
        while (key_hex.length() < cipher_hex.length()) {
            key_hex += key_hex_sub;
        }
        
        string plain_hex = *xorHex(cipher_hex, key_hex);
        double score = *likelihoodScore(plain_hex);
        if (score > best_score) {
            *best_key = key_hex_sub;
            best_score = score;
        }
    }
    return best_key;
}

string* bestSingleKeyCipher(vector<string>& cipher_hex_vec) {
    string* best_cipher_hex = new string;
    double best_score = 0;
    for (string cipher_hex : cipher_hex_vec) {
        string key_hex_sub = *breakSingleKey(cipher_hex);
        string plain_hex = *encryptOrDecryptRepeatingKey(cipher_hex, key_hex_sub);
        double score = *likelihoodScore(plain_hex);
        if (score > best_score) {
            *best_cipher_hex = cipher_hex;
            best_score = score;
        }
    }
    return best_cipher_hex;
}

string* encryptOrDecryptRepeatingKey(string hex, string key) {
    string key_hex = "";
    int key_index = 0;
    while (key_hex.length() < hex.length()) {
        key_hex += key[key_index];
        key_index += 1;
        if (key_index >= key.length()) {
            key_index = 0;
        }
    }
    return xorHex(hex, key_hex);
}

string* breakRepeatingKey(string cipher_hex) {
    int best_key_size = *bestKeySize(cipher_hex);
    vector<string> sub_blocks;
    for (int i = 0; i < cipher_hex.length(); i += 2 * best_key_size) {
        string sub_block = cipher_hex.substr(i, 2 * best_key_size);
        sub_blocks.push_back(sub_block);
    }

    vector<string> split_blocks = vector<string>(best_key_size);
    for (int i = 0; i < best_key_size; i += 1) {
        split_blocks[i] = "";
    }
    for (string sub_block : sub_blocks) {
        for (int i = 0; i < sub_block.length(); i += 2) {
            split_blocks[i / 2] += sub_block.substr(i, 2);
        }
    }

    string* best_key = new string;
    *best_key = "";
    for (string split_block : split_blocks) {
        *best_key += *breakSingleKey(split_block);
    }
    return best_key;
}

int* bestKeySize(string cipher_hex) {
    int* best_key_size = new int;
    double best_key_size_score = 99999.;
    for (int key_size = 2; key_size <= 40; key_size += 1) {
        vector<string> sub_ciphers;
        for (int i = 0; i < 10 * 2 * key_size; i += 2 * key_size) {
            string sub_cipher = cipher_hex.substr(i, 2 * key_size);
            sub_ciphers.push_back(sub_cipher);
        }

        int totalScore = 0;
        for (int i = 0; i < sub_ciphers.size(); i += 1) {
            for (int j = 0; j < i; j += 1) {
                int curr = *hammingDistance(sub_ciphers[i], sub_ciphers[j]);
                totalScore += curr;
            }
        }

        int score = totalScore / (2 * key_size);
        if (score < best_key_size_score) {
            *best_key_size = key_size;
            best_key_size_score = score;
        }
    }
    return best_key_size;
}


/* HELPERS */

string* hexToBase64(string hex) {
    while (hex.length() % 3 != 0) {
        hex = '0' + hex;
    }

    vector<int>* raw = new vector<int>();
    for (int i = 0; i < hex.length(); i += 3) {
        string sub_str = hex.substr(i, 3);
        int sub_int = pow(16, 2) * HEX_TO_INT[sub_str[0]] +
                        pow(16, 1) * HEX_TO_INT[sub_str[1]] +
                        pow(16, 0) * HEX_TO_INT[sub_str[2]];
        (*raw).push_back(sub_int);
    }

    string* base64 = new string;
    *base64 = "";
    for (int sub_int : *raw) {
        string sub_str = "";
        while (sub_int > 0) {
            sub_str = INT_TO_BASE64[sub_int % 64] + sub_str;
            sub_int = floor(sub_int / 64);
        }
        while (sub_str.length() < 2) {
            sub_str = '0' + sub_str;
        }
        *base64 += sub_str;
    }

    delete raw;
    return base64;
}

string* base64ToHex(string base64) {
    while (base64.length() % 2 != 0) {
        base64 = '0' + base64;
    }

    vector<int>* raw = new vector<int>();
    for (int i = 0; i < base64.length(); i += 2) {
        string sub_str = base64.substr(i, 2);
        int sub_int = pow(64, 1) * BASE64_TO_INT[sub_str[0]] +
                        pow(64, 0) * BASE64_TO_INT[sub_str[1]];
        (*raw).push_back(sub_int);
    }

    string* hex = new string;
    *hex = "";
    for (int sub_int : *raw) {
        string sub_str = "";
        while (sub_int > 0) {
            sub_str = INT_TO_HEX[sub_int % 16] + sub_str;
            sub_int = floor(sub_int / 16);
        }
        while (sub_str.length() < 3) {
            sub_str = '0' + sub_str;
        }
        *hex += sub_str;
    }
    *hex = (*hex).substr(0, (*hex).length() - 2);

    delete raw;
    return hex;
}

string* xorHex(string hex1, string hex2) {
    string* result = new string;
    for (int i = 0; i < hex1.length(); i += 1) {
        int c1 = HEX_TO_INT[hex1[i]];
        int c2 = HEX_TO_INT[hex2[i]];
        char cx = INT_TO_HEX[c1 ^ c2];
        *result += cx;
    }
    return result;
}
double* likelihoodScore(string english_hex) {
    if (english_hex.length() % 2 != 0) {
        english_hex = '0' + english_hex;
    }

    vector<char> english_chars;
    for (int i = 0; i < english_hex.length(); i += 2) {
        int sub_hex = stoi(english_hex.substr(i, 2), 0, 16);
        english_chars.push_back((char) sub_hex);
    }

    double* score = new double;
    *score = 0;
    for (char c : english_chars) {
        (*score) += CHAR_FREQUENCIES[c];
    }
    return score;
}

string* hexToASCIIEnglish(string english_hex) {
    string* ascii = new string;
    for (int i = 0; i < english_hex.length(); i += 2) {
        (*ascii) += (char) stoi(english_hex.substr(i, 2), 0, 16);
    }
    return ascii;
}

string* ASCIIEnglishToHex(string english_ascii) {
    string* english_hex = new string;
    for (char c : english_ascii) {
        stringstream stream;
        stream << hex << int (c);
        string hex_sub(stream.str());
        while (hex_sub.length() < 2) {
            hex_sub = '0' + hex_sub;
        }
        *english_hex += hex_sub;
    }
    return english_hex;
}

int* hammingDistance(string hex1, string hex2) {
    int* dist = new int;
    *dist = fabs(hex1.length() - hex2.length());
    for (int i = 0; i < min(hex1.length(), hex2.length()); i += 1) {
        int xorBytes = HEX_TO_INT[hex1[i]] ^ HEX_TO_INT[hex2[i]];
        while (xorBytes > 0) {
            if (xorBytes % 2 == 0) {
                xorBytes /= 2;
            } else {
                xorBytes -= 1;
                xorBytes /= 2;
                *dist += 1;
            }
        }
    }
    return dist;
}