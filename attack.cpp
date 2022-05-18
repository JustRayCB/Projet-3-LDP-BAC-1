/*
 * Author: Rayan Contuliano Bravo
 * Date: 1-05-22
 * N°: 000537050
 * Main file that will make the Vigenere attack
 */

#include "vigenere.hpp"
#include "iostream"
#include <cctype>
#include <vector>
#include <tuple>
#include "vigenere.cpp"

using namespace std;
vector<size_t> lines;

int main(int argc, char *argv[]) {
    /*if (argc < 4) {
        cout << "Utilisation: ./attack.cpp <nom_fichier_chiffre> <long_max_clé> <nom_fichier_dechiffre>" << endl;
        return 1;
    }*/

    string nomFichierChiffre = "C:\\Users\\Craya\\CLionProjects\\real_ldp3\\chiffre\\chiffre_6.txt";
    size_t realKey = 100;
    string nomFichierDechiffre = "C:\\Users\\Craya\\CLionProjects\\real_ldp3\\dechiffre1.txt";

    tuple<string,vector<size_t>> to_decrypt = read_file(nomFichierChiffre);
    lines = get<1>(to_decrypt);     // Global Variable that will contain the length of the line in the files
    attack(get<0>(to_decrypt), nomFichierDechiffre, realKey);
}