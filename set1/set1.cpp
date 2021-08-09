#include "set1.h"
#include <math.h>
#include <iostream>
#include <unordered_map>
#include <vector>

using namespace std;

unordered_map<char, int> HEX_TO_INT = {
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

unordered_map<int, char> INT_TO_BASE64 = {
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

string* hexToBase64(string hex) {
    vector<int>* raw = hexToRaw(hex);
    return rawToBase64(raw);
}

vector<int>* hexToRaw(string hex) {
    while (hex.length() % 3 != 0) {
        hex = '0' + hex;
    }

    vector<int>* res = new vector<int>();
    for (int i = 0; i < hex.length(); i += 3) {
        string sub_str = hex.substr(i, 3);
        int sub_int = pow(16, 2) * HEX_TO_INT[sub_str[0]] +
                        pow(16, 1) * HEX_TO_INT[sub_str[1]] +
                        pow(16, 0) * HEX_TO_INT[sub_str[2]];
        (*res).push_back(sub_int);
    }
    return res;
}

string* rawToBase64(vector<int>* raw) {
    string* res = new string;
    (*res) = "";
    for (int sub_int : (*raw)) {
        string sub_str = "";
        while (sub_int > 0) {
            sub_str = INT_TO_BASE64[sub_int % 64] + sub_str;
            sub_int = floor(sub_int / 64);
        }
        while (sub_str.length() < 2) {
            sub_str = '0' + sub_str;
        }
        (*res) += sub_str;
    }
    return res;
}