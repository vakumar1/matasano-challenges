#pragma once
#include <string>
#include <vector>

using namespace std;

string* hexToBase64(string hex);
vector<int>* hexToRaw(string hex);
string* rawToBase64(vector<int>* raw);