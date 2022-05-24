/*
 * Author: Rayan Contuliano Bravo
 * Date: 1-05-2022
 * N°: 000537050
 * Main file to decrypt a text
 */
#include <iostream>

#include <vector>

#include "vigenere.hpp"

using namespace std; //global Variable with the length of the lines in the file

int main(int argc, char *argv[]) {
    if (argc < 4) {
        cout << "Utilisation: ./decrypt <nom_fichier_chiffre> <mot_de_passe> <nom_fichier_dechiffre>" << endl;
        return 1;
    }
    string nomFichierChiffre = argv[1];
    string motDePasse = argv[2];
    string nomFichierDechiffre = argv[3];
    File myFile = File(nomFichierChiffre, nomFichierDechiffre);
    Clef newClef{};     // make the password a struct Clef
    newClef.longueur = motDePasse.size();
    newClef.erreur = 0.0;
    char *mdpTable = new char[newClef.longueur];
    for (size_t idx = 0; idx < newClef.longueur; idx++){
        mdpTable[idx] = motDePasse[idx];
    }
    newClef.clef = mdpTable;

    myFile.decode(&newClef);
    delete[] newClef.clef;
    return 0;
}


