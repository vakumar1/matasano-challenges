#pragma once
#include <string>
#include <vector>
#include <unordered_map>

using namespace std;
string* hexToBase64(string hex);
string* xorHex(string hex1, string hex2);
string* breakSingleKey(string cipher_hex);
string* bestSingleKeyCipher(vector<string>& cipher_hex_vec);
string* encryptRepeatingKey(string plain_hex, string key);
double* likelihoodScore(string english_hex);
string* hexToASCIIEnglish(string english_hex);
string* ASCIIEnglishToHex(string english_ascii);


/* CONSTANTS */
inline unordered_map<char, int> HEX_TO_INT = {
    {'0', 0},
    {'1', 1},
    {'2', 2},
    {'3', 3},
    {'4', 4},
    {'5', 5},
    {'6', 6},
    {'7', 7},
    {'8', 8},
    {'9', 9},
    {'a', 10},
    {'b', 11},
    {'c', 12},
    {'d', 13},
    {'e', 14},
    {'f', 15}
};

inline unordered_map<int, char> INT_TO_HEX = {
    {0, '0'},
    {1, '1'},
    {2, '2'},
    {3, '3'},
    {4, '4'},
    {5, '5'},
    {6, '6'},
    {7, '7'},
    {8, '8'},
    {9, '9'},
    {10, 'a'},
    {11, 'b'},
    {12, 'c'},
    {13, 'd'},
    {14, 'e'},
    {15, 'f'}
};

inline unordered_map<int, char> INT_TO_BASE64 = {
    {0, 'A'},
    {1, 'B'},
    {2, 'C'},
    {3, 'D'},
    {4, 'E'},
    {5, 'F'},
    {6, 'G'},
    {7, 'H'},
    {8, 'I'},
    {9, 'J'},
    {10, 'K'},
    {11, 'L'},
    {12, 'M'},
    {13, 'N'},
    {14, 'O'},
    {15, 'P'},
    {16, 'Q'},
    {17, 'R'},
    {18, 'S'},
    {19, 'T'},
    {20, 'U'},
    {21, 'V'},
    {22, 'W'},
    {23, 'X'},
    {24, 'Y'},
    {25, 'Z'},
    {26, 'a'},
    {27, 'b'},
    {28, 'c'},
    {29, 'd'},
    {30, 'e'},
    {31, 'f'},
    {32, 'g'},
    {33, 'h'},
    {34, 'i'},
    {35, 'j'},
    {36, 'k'},
    {37, 'l'},
    {38, 'm'},
    {39, 'n'},
    {40, 'o'},
    {41, 'p'},
    {42, 'q'},
    {43, 'r'},
    {44, 's'},
    {45, 't'},
    {46, 'u'},
    {47, 'v'},
    {48, 'w'},
    {49, 'x'},
    {50, 'y'},
    {51, 'z'},
    {52, '0'},
    {53, '1'},
    {54, '2'},
    {55, '3'},
    {56, '4'},
    {57, '5'},
    {58, '6'},
    {59, '7'},
    {60, '8'},
    {61, '9'},
    {62, '+'},
    {63, '/'}
};

inline unordered_map<char, double> CHAR_FREQUENCIES = {
    {'a', 0.08167}, 
    {'b', 0.01492}, 
    {'c', 0.02782}, 
    {'d', 0.04253}, 
    {'e', 0.12702}, 
    {'f', 0.02228}, 
    {'g', 0.02015}, 
    {'h', 0.06094}, 
    {'i', 0.06966}, 
    {'j', 0.00153}, 
    {'k', 0.00772}, 
    {'l', 0.04025}, 
    {'m', 0.02406}, 
    {'n', 0.06749},
    {'o', 0.07507},
    {'p', 0.01929},
    {'q', 0.00095},
    {'r', 0.05987},
    {'s', 0.06327},
    {'t', 0.09056},
    {'u', 0.02758},
    {'v', 0.00978},
    {'w', 0.02360},
    {'x', 0.00150},
    {'y', 0.01974},
    {'z', 0.00074},
    {' ', 0.15}
};