/*
 * Author: Rayan Contuliano Bravo
 * Date: 1-05-2022
 * N°: 000537050
 * Main file to decrypt a text
 */
#include <iostream>
#include <cctype>
#include <vector>
#include <tuple>
#include "vigenere.hpp"

using namespace std;
vector<size_t> lines;       //global Variable with the length of the lines in the file

int main(int argc, char *argv[]) {
    if (argc < 4) {
        cout << "Utilisation: ./decrypt <nom_fichier_chiffre> <mot_de_passe> <nom_fichier_dechiffre>" << endl;
        return 1;
    }
    string nom_fichier_chiffre = argv[1];
    string mot_de_passe = argv[2];
    string nom_fichier_dechiffre = argv[3];

    tuple<string,vector<size_t>> to_decrypt = read_file(nom_fichier_chiffre);
    lines = get<1>(to_decrypt);
    string real_password = associate_pw(get<0>(to_decrypt),mot_de_passe);

    string decrypted = decrypt(get<0>(to_decrypt), real_password);

    write_file(nom_fichier_dechiffre, decrypted, get<1>(to_decrypt));


    return 0;
}

