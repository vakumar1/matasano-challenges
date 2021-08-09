#include "set1.h"
#include <iostream>
#include <fstream>

using namespace std;

void challenge1() {
    string hex_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    string base64_output = *hexToBase64(hex_input);
    cout << base64_output << endl;
}

void challenge2() {
    string hex1_input = "1c0111001f010100061a024b53535009181c";
    string hex2_input = "686974207468652062756c6c277320657965";
    string xor_output = *xorHex(hex1_input, hex2_input);
    cout << xor_output << endl;
}

void challenge3() {
    string hex_input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    string plain_hex_output = *breakSingleKey(hex_input);
    string plain_english = *hexToASCIIEnglish(plain_hex_output);
    cout << "Plain Hex: " << plain_hex_output << endl;
    cout << "Plain English: " << plain_english << endl;
}

void challenge4() {
    fstream hex_file("challenge4_ciphers.txt");
    string line;
    vector<string> hex_inputs;
    if (hex_file.is_open()) {
        while (getline(hex_file, line)) {
            hex_inputs.push_back(line);
        }
    }
    string cipher_hex_output = *bestSingleKeyCipher(hex_inputs);
    string plain_hex = *breakSingleKey(cipher_hex_output);
    string plain_english = *hexToASCIIEnglish(plain_hex);
    cout << "Cipher Hex: " << cipher_hex_output << endl;
    cout << "Plain Hex: " << plain_hex << endl;
    cout << "Plain English: " << plain_english << endl;
}

void challenge5() {
    string plain_english_input = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal";
    string plain_english_key = "ICE";
    string plain_hex = *ASCIIEnglishToHex(plain_english_input);
    string plain_hex_key = *ASCIIEnglishToHex(plain_english_key);
    string cipher_hex_output = *encryptRepeatingKey(plain_hex, plain_hex_key);
    cout << cipher_hex_output << endl;
}

int main() {
    challenge5();
    return 0;
}