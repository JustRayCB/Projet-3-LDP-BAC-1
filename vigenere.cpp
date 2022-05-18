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


struct Clef {
    char *clef;
    size_t longueur;
    float erreur;
};

string decryptedText(const string &cypher, struct Clef *clef) {
    /*string myMdp;
    for (size_t idx = 0; idx < clef->longueur; idx++) {
        myMdp.push_back(clef->clef[idx]);
    }*/

    string realPswd = associate_pw(cypher, clef);

    string decrypted = decrypt(cypher, realPswd);

    return decrypted;
}

void decode(const string &cypher, struct Clef *clef, string &plain) {

    string decrypted = decryptedText(cypher, clef);

    write_file(plain, decrypted, lines);
}

struct Clef *trouve_candidat(const string &cypher, const size_t &l) {
    char *tempTable = new char[l];
    vector<string> columns;
    float error = 0;
    columns = divideText(cypher, l);    // Vector with the columns of the text
    size_t idx = 0;
    for (string myString: columns) {   //Parse the vector and create a password with the most common letters in each col
        tuple<char, float> res = (findMostOccurence(myString));
        tempTable[idx] = transformLetter(get<0>(res));
        idx++;
        error += get<1>(res);
    }
    Clef *newClef = new Clef;
    newClef->clef = tempTable;
    newClef->longueur = l;
    newClef->erreur = error / float(l);
    return newClef;
}


void attack(const string &cypher, string &plain, const size_t &l) {
    Clef myKey{};   //Key considered as better candidat
    myKey.erreur = 100.0;
    for (size_t idx = 1; idx <= l; idx++) {
        Clef *newKey = trouve_candidat(cypher, idx);
        if (idx >=20){
            string patternMyKey = findRepeatedString(myKey.clef);
            cout << patternMyKey << endl;
            string key;
            if (!patternMyKey.empty()) {
                for (size_t index = 0; idx < newKey->longueur; index++) {
                    key.push_back(newKey->clef[index]);
                }
                size_t count = findOccurenceWord(key, patternMyKey);
                if (count * patternMyKey.size() == key.size()) {
                    cout<<"here" << endl;
                    break;          //same pw
                }
            }

        }
        if (newKey->erreur < myKey.erreur) {    // useless to test a key that have a bigger error that the current key
            myKey.clef = newKey->clef;
            myKey.erreur = newKey->erreur;
            myKey.longueur = newKey->longueur;
        }
        else{
            delete[] newKey;
        }
    }
    decode(cypher, &myKey, plain);

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
    while (idx < lenText / 2) {
        string sub = text.substr(0, idx);
        size_t count = findOccurenceWord(text, sub);
        if (count * sub.size() == lenText) {
            return sub;
        }
        idx ++;
    }
    return "";
}

vector<string> divideText(const string &cypher, const size_t &size) {
    vector<string> column(size);
    size_t idx = 0;     //Index of the letter
    for (char letter: cypher){
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
    char chosenLetter = ' ';
    vector<char> allLetters(
            {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
             'V', 'W', 'X', 'Y', 'Z'});
    for (char& letter: allLetters){
        size_t new_count = size_t(std::count(myString.begin(), myString.end(), letter)); //Freq of the letter in the string
        if (new_count > count) {
            chosenLetter = letter;
            count = new_count;
        }
    }
    double error;
    error = float(count) / float(size);
    error = abs(error - 0.17115);
    return {chosenLetter, error};
}

char transformLetter(char &letter) {
    int delta = int(letter) - int('E');
    if (delta > 0) {
        return char(int('A') + delta);
    }
    if (delta < 0) {
        return char(int('Z') + delta + 1);
    } else {
        return 'A';
    }
}


tuple<string, vector<size_t>> read_file(const string &filename) {
    string temp;
    vector<size_t> lengthPhrase;  // initiate the vector that will stock the length of the line
    fstream read(filename, ios::in);
    if (read.is_open()) {
        string line;
        while (getline(read, line)) {
            line.erase(remove(line.begin(), line.end(), '\r'), line.end());
            temp.append(line + " ");
            lengthPhrase.push_back(line.size());   // Push the length of line in the vector
        }
        read.close();
    } else cerr << "Impossible d'ouvrir le fichier " << filename << endl;
    return {temp, lengthPhrase};
}

string associate_pw(const string &text, const string& pw) {
    size_t idx = 0;
    string newPw;
    size_t lenPw = pw.size();
    for (char letter: text){
        if (int(letter) >= 65 and int(letter) <= 90){
            newPw+=pw[idx];
            idx ++;
        }
        else{
            newPw += letter;
        }
        if (idx == lenPw){
            idx = 0;
        }
    }
    return newPw;
}

string associate_pw(const string &text, const struct Clef *clef) {
    size_t idx = 0;
    string newPw;
    size_t lenPw = clef->longueur;
    for (char letter: text) {
        if (int(letter) >= 65 and int(letter) <= 90) {
            newPw += clef->clef[idx];
            idx++;
        } else {
            newPw += letter;
        }
        if (idx == lenPw) {
            idx = 0;
        }
    }
    return newPw;
}

char associate_letter(const char &key, const char &crypt) {
    int delta;
    if (int(crypt) < int(key)){
        delta = 91 - int(key) + int(crypt) - 64;

    }else{
        delta = int(crypt) - int(key)+1;
    }
    return char(64+delta);
}

string decrypt(const string &text, const string &mdp) {
    string res;
    for (size_t idx = 0; idx < text.length(); idx++) {  // parse the text with index
        if (isalpha(mdp[idx])) {
            res += associate_letter(mdp[idx], text[idx]);   // associate a letter
        } else {
            res += mdp[idx];
        }
    }
    return res;
}

void write_file(const string &filename, string text, const vector<size_t> &length) {
    ofstream file(filename, ios::out);
    if (file.is_open()) {
        for (size_t idx: length) {    // While there is a data in the list we have  to write a line
            string phrase = text.substr(0, idx);    // text[:idx] to have only what we want to write
            file << phrase << endl;     // write in the file
            text = text.substr(idx + 1, text.length());     // Remove the wrote part of the text
        }
    }
}
