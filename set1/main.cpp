#include "set1.h"
#include <iostream>

using namespace std;

int main() {
    // PROBLEM 1
    string hex_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    string base64_output = *hexToBase64(hex_input);
    cout << base64_output << endl;
    return 0;
}