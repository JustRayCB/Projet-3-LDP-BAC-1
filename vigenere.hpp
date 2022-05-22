/*
 * Header of the attack.cpp and decrypt.cpp files
 */
#include <string>
#include <vector>
#include "tuple"


class File{
    std::string _filename;
    std::string _plain;
    std::tuple<std::string, std::vector<size_t>> _lines;
public:
    File(std::string  filename, std::string  plain);
    static std::tuple<std::string, std::vector<size_t>> read_file(const std::string& filename);
    void decode(const struct Clef *clef) const;
    //std::vector<std::string> divideText(const size_t &size);
    const std::string *getCypher()const;
    const std::vector<size_t> *getLines()const;


};

struct Clef {
    char *clef;
    size_t longueur;
    float erreur;
};

/**
 * Etant donné le message chiffré, renvoi une clé de type struct
 * Clef (cfr. l'énoncé pour sa déclaration)
 *
 * @param cypher Le message chiffré
 * @param l la longueur de la clé
 * @return A pointer to a struct Clef
 */
struct Clef *trouve_candidat(const std::string &cypher, const size_t &l);

/**
 * Déchiffre un message encodé à l'aide du chiffre de Vigenère sans avoir
 * connaissance du mot de passe
 *
 * @param cypher Le message à déchiffrer
 * @param plain String qui contiendra le message déchiffré après l'appel
 * @param l Chiffre que l'utilisateur à choisi pour faire l'attaque du chiffre de Vigenere
 * @return None
 */
void attack(const File &myFile, const size_t &l);


//      ****Function to find a candidate****

/**
 * Divide a text in a certain number of columns
 *
 * @param cypher text we will divise
 * @param size Number of column in which we will divide the text
 * @return a vector which all the values are the different column of the divided text
 */
std::vector<std::string> divideText(const std::string& cypher, const size_t &size);

/**
 * Find the most used alphabetic letter in a string
 * @param myString String we will analyze
 * @return A tuple with the most used character and it's error
 */
std::tuple<char, float> findMostOccurence(std::string& myString);


size_t findOccurenceWord(const std::string &text, const std::string &word);

std::string findRepeatedString(const std::string &text);

