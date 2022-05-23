/*
 * Author: Rayan Contuliano Bravo
 * Date: 1-05-2022
 * N°: 000537050
 * Fil with all the function called by attack.cpp and decrypt.cpp
 * */


#include "iostream"
#include "string"
#include "vigenere.hpp"
#include "vector"
#include "tuple"
#include <fstream>
#include <algorithm>
#include <cctype>
#include <cstdlib>

using namespace std;


File::File(std::string filename, std::string plain):_filename(std::move(filename)), _plain(std::move(plain)), _lines(File::read_file(_filename)){}

struct Clef *trouve_candidat(const File &myFile, const size_t &l) {
    char *tempTable = new char[l];
    vector<string> columns;
    float error = 0;
    columns = myFile.divideText(l);    // Vector with the columns of the text
    size_t idx = 0;
    size_t realSize = 0;
    Clef *newClef = new Clef;

    for (string myString: columns) {   //Parse the vector and create a password with the most common letters in each col
        if (!myString.empty()) {
            tuple<char, float> res = (findMostOccurence(myString));
            tempTable[idx] = char((int(get<0>(res)) - 69)%26 + 65 );
            idx++;
            error += get<1>(res);
            realSize++;
        }
    }
    if (realSize != l){
        char *realTable = new char[realSize];
        for (idx=0;idx<realSize;idx++){
            realTable[idx] = tempTable[idx];
        }
        newClef->clef = realTable;
        newClef->longueur = realSize;
        newClef->erreur = error / float(realSize);
    }else {
        newClef->clef = tempTable;
        newClef->longueur = l;
        newClef->erreur = error / float(l);
    }
    return newClef;
}


void attack(const File& myFile, const size_t &l) {
    Clef myKey{};   //Key considered as better candidat
    myKey.erreur = 10.0;
    for (size_t idx = 1; idx <= l; idx++) {
        Clef *newKey = new Clef(*trouve_candidat(myFile, idx));
        if (newKey->erreur < myKey.erreur) {    // useless to test a key that have a bigger error that the current key
            if (idx >5  and myKey.clef[0] == newKey->clef[0]){  //maybe delete that if if it's too cheaty
                string tempKey, currentKey;
                for (size_t index = 0; index < newKey->longueur; index++) {
                    if (index < myKey.longueur){
                        currentKey.push_back(myKey.clef[index]);
                    }
                    tempKey.push_back(newKey->clef[index]);
                }
                string patterMyKey = findRepeatedString(currentKey);
                size_t count = findOccurenceWord(tempKey, patterMyKey);
                if (count * patterMyKey.size() == tempKey.size()) {
                    delete newKey;
                    break;          //same pw
                }
            }
            myKey.clef = newKey->clef;
            myKey.erreur = newKey->erreur;
            myKey.longueur = newKey->longueur;
            delete newKey;
        }
        else{
            delete newKey;
        }
    }
    myFile.decode(&myKey);

}

size_t findOccurenceWord(const string &text, const string &word){
    size_t lenText = text.size();
    size_t lenWord = word.size();
    size_t idx = 0;
    size_t res = 0;
    while (idx < lenText) {
        string sub = text.substr(idx, lenWord);
        if (sub != word) {
            break;
        }
        res++;
        idx += lenWord;
    }
    return res;
}
string findRepeatedString(const string &text) {
    size_t lenText = text.size();
    size_t idx = 1;
    while (idx <= lenText / 2) {
        string sub = text.substr(0, idx);
        size_t count = findOccurenceWord(text, sub);
        if (count * sub.size() == lenText) {
            return sub;
        }
        idx ++;
    }
    return text;
}

vector<string> File::divideText(const size_t &size) const{
    vector<string> column(size);
    size_t idx = 0;     //Index of the letter
    for (const char &letter: get<0>(_lines)){
        size_t columnIdx = idx%size;
        if (65 <= int(letter) and int(letter) <= 90){
            column[columnIdx].push_back(letter);
            idx ++;
        }
    }
    return column;
}

tuple<char, float> findMostOccurence(string &myString) {
    size_t count = 0;
    size_t size = myString.size();
    char *chosenLetter = nullptr;
    vector<char> allLetters(
            {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
             'V', 'W', 'X', 'Y', 'Z'});
    for (char& letter: allLetters){
        size_t newCount = size_t(std::count(myString.begin(), myString.end(), letter)); //Freq of the letter in the string
        if (newCount > count) {
            chosenLetter =&letter;
            count = newCount;
        }
    }
    double error;
    error = float(count) / float(size);
    error = abs(error - 0.17115);
    return {*chosenLetter, error};
}


tuple<string, vector<size_t>> File::read_file(const string &filename) {
    string temp;
    vector<size_t> lengthPhrase;  // initiate the vector that will stock the length of the line
    fstream read(filename, ios::in);
    if (read.is_open()) {
        string line;
        while (getline(read, line)) {
            line.erase(remove(line.begin(), line.end(), '\r'), line.end());
            temp.append(line);
            lengthPhrase.push_back(line.size());   // Push the length of line in the vector
        }
        read.close();
    } else cerr << "Impossible d'ouvrir le fichier " << filename << endl;
    return {temp, lengthPhrase};
}


void File:: decode(const struct Clef *clef) const {
    size_t idxMdp = 0;
    size_t lenPw = clef->longueur;
    ofstream file(_plain, ios::out);
    size_t idxLine = 0;
    size_t idxVector = 0;
    if (file.is_open()){
        char decrypted;
        for (const char &letter: get<0>(_lines)){
            if (int(letter) >= 65 and int(letter) <= 90){
                decrypted = char((((letter - clef->clef[idxMdp]) + 26) % 26) + 'A');
                idxMdp++;
            }else{
                decrypted = letter;
            }
            if (idxMdp == lenPw){
                idxMdp = 0;
            }
            if (idxLine == get<1>(_lines)[idxVector]-1){
                file << decrypted << endl;
                idxVector++;
                idxLine =0;
            }else{
                file << decrypted;
                idxLine++;
            }
            if (get<1>(_lines)[idxVector] == 0){
                file << endl;
                idxVector++;
            }
        }
    }
}

