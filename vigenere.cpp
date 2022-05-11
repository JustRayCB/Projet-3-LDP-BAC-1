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
    string myMdp;
    for (size_t idx = 0; idx < clef->longueur; idx++) {
        myMdp.push_back(clef->clef[idx]);
    }
    cout << myMdp << endl;

    string realPswd = associate_pw(cypher, myMdp);

    string decrypted = decrypt(cypher, realPswd);

    return decrypted;
}

void decode(const string &cypher, struct Clef *clef, string &plain) {

    string decrypted = decryptedText(cypher, clef);

    write_file(plain, decrypted, lines);
}

struct Clef *trouve_candidat(const string &cypher, size_t l) {
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

double findOcuurencee(const string &cypher) {
    size_t lenText = 0;
    size_t nbE = 0;     //Number of E
    for (const char &letter: cypher) {
        if (65 <= int(letter) and int(letter) <= 90) {
            lenText++;
            if (int(letter) == 69) {
                nbE++;
            }
        }
    }
    double frequency = (double(nbE) / double(lenText)) * 100;
    return frequency;
}

void attack(const string &cypher, string &plain, const size_t l) {
    Clef myKey{};   //Key considered as better candidat
    Clef temp{};    //temporary key
    myKey.erreur = 100.0;

    double myDelta = 100.0;
    for (size_t idx = 1; idx <= l; idx++) {
        Clef *newKey = trouve_candidat(cypher, idx);
        if (newKey->erreur < myKey.erreur) {    // useless to test a key that have a bigger error that the current key
            temp.clef = newKey->clef;
            temp.erreur = newKey->erreur;
            temp.longueur = newKey->longueur;
            string decrypted = decryptedText(cypher, &temp);    //Decrypted text
            double percentE = findOcuurencee(decrypted);      //Frequency of the E in decrypted
            double generalPercentE = 17.115;                        // General percentage of E in a string in French
            double delta = abs(generalPercentE - percentE);
            if (delta < myDelta) {
                myKey.clef = temp.clef;
                myKey.erreur = temp.erreur;
                myKey.longueur = temp.longueur;
                myDelta = delta;
            } else {
                delete[] newKey;
            }
        }
        else{
            delete[] newKey;
        }
    }
    decode(cypher, &myKey, plain);

}

vector<string> divideText(const string &cypher, const size_t size) {
    string temp = cypher;
    temp.erase(remove(temp.begin(), temp.end(), ' '), temp.end());    // remove all spaces in the string
    vector<string> column(size);
    size_t idx = 0;     //Column index we are currently on
    size_t taille = temp.size();
    size_t parse = 0;   // Index letter we are currently on
    while (parse < taille) {
        size_t letter = idx % size;     // Column index we want to insert the letter
        if (65 <= int(temp[parse]) and int(temp[parse]) <= 90) {
            column[letter].push_back(temp[parse]);
            idx++;
        }
        parse++;
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

string associate_pw(const string &text, string pw) {
    string temp = text;
    temp.erase(remove(temp.begin(), temp.end(), ' '), temp.end());  // remove all the spaces of the string
    string sepPw;
    size_t idx = 0;         // will be the index of the letter in the password (pw)
    size_t lenPw = pw.size();
    for (char &letter: temp) {    // will be used to associate a pw according the length and the diff char of the pswrd

        if (65 <= int(letter) and int(letter) <= 90) {   // if letter is alphabetic
            sepPw += pw[idx]; // add a letter to sep_pw from pw
            idx += 1;
        } else if (not isalpha(letter)) {
            sepPw += letter;
        }

        if (idx == lenPw) { // if we reached the en of pw
            idx = 0;       // we return to the beginning of pw
        }
    }
    size_t lenSep = sepPw.size();
    pw = "";
    idx = 0;
    for (char i: text) {        // will be used to create the real pswrd with spaces, special characters etc...
        char myLetter;
        myLetter = i;
        if (isspace(myLetter)) {
            pw += " ";
        } else if (!isspace(myLetter)) {
            pw += sepPw[idx];
            idx += 1;
        }
        if (idx == lenSep) {
            idx = 0;
        }
    }
    return pw;
}

char associate_letter(char key, char crypt) {
    crypt = char(toupper(crypt));     // upper case letter
    key = char(toupper(key));         // upper case letter
    vector<char> allLetters(
            {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
             'V', 'W', 'X', 'Y', 'Z'}); // vector with all the alphabetic characters
    auto found = find(allLetters.begin(), allLetters.end(), key);     // find the key index in the vector
    vector<char> my_line_1(allLetters.begin() + distance(allLetters.begin(), found),
                           allLetters.end());     // key --> end of vector
    vector<char> my_line_2(allLetters.begin(), allLetters.begin() + distance(allLetters.begin(),
                                                                               found));    // Beginning of vector --> key -1
    my_line_1.insert(my_line_1.end(), my_line_2.begin(), my_line_2.end());      // Combine the two vector into one
    auto found_crypt = find(my_line_1.begin(), my_line_1.end(), crypt);
    return allLetters[size_t(distance(my_line_1.begin(), found_crypt))];       //The decrypted letter in the vector
}

string decrypt(string text, string mdp) {
    string res;
    for (long unsigned int idx = 0; idx < text.length(); idx++) {  // parse the text with index
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
