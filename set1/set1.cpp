#include "set1.h"
#include <math.h>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <vector>

using namespace std;

string* breakSingleKey(string cipher_hex) {
    string* best_plain_hex = new string;
    double best_score = 0.;
    for (int i = 0; i < 256; i += 1) {
        string key_hex = "";
        stringstream stream;
        stream << hex << i;
        string key_hex_sub(stream.str());
        while (key_hex.length() < cipher_hex.length()) {
            key_hex += key_hex_sub;
        }
        
        string plain_hex = *xorHex(cipher_hex, key_hex);
        double score = *likelihoodScore(plain_hex);
        if (score > best_score) {
            *best_plain_hex = plain_hex;
            best_score = score;
        }
    }
    return best_plain_hex;
}

string* bestSingleKeyCipher(vector<string>& cipher_hex_vec) {
    string* best_cipher_hex = new string;
    double best_score = 0;
    for (string cipher_hex : cipher_hex_vec) {
        string plain_hex = *breakSingleKey(cipher_hex);
        double score = *likelihoodScore(plain_hex);
        if (score > best_score) {
            *best_cipher_hex = cipher_hex;
            best_score = score;
        }
    }
    return best_cipher_hex;
}

string* encryptRepeatingKey(string plain_hex, string key) {
    string key_hex = "";
    int key_index = 0;
    while (key_hex.length() < plain_hex.length()) {
        key_hex += key[key_index];
        key_index += 1;
        if (key_index >= key.length()) {
            key_index = 0;
        }
    }
    return xorHex(plain_hex, key_hex);
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