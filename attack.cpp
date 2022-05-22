/*
 * Author: Rayan Contuliano Bravo
 * Date: 1-05-22
 * N°: 000537050
 * Main file that will make the Vigenere attack
 */

#include "vigenere.hpp"
#include "iostream"
#include <cctype>


using namespace std;

int main(int argc, char *argv[]) {
    if (argc < 4)   {
        cout << "Utilisation: ./attack.cpp <nom_fichier_chiffre> <long_max_clé> <nom_fichier_dechiffre>" << endl;
        return 1;
    }
    string nomFichierChiffre = argv[1];
    size_t realKey = size_t(stoi(argv[2]));
    string nomFichierDechiffre = argv[3];
    File nv = File(nomFichierChiffre, nomFichierDechiffre);
    attack(nv, realKey);
}