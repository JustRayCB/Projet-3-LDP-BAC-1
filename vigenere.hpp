/*
 * Header of the attack.cpp and decrypt.cpp files
 */
#include <string>
#include <vector>
#include "tuple"


class File{
    std::string _filename;
    std::string _plain;
    std::tuple<std::string, std::vector<uint_fast32_t>> _lines;
public:
    File(std::string  filename, std::string  plain);

    /**
     * Read a file named filename
     * @param filename name of the file
     * @return tuple(String of all the lines of the file, a vector with the size of the lines)
     */
    static std::tuple<std::string, std::vector<uint_fast32_t>> readFile(const std::string& filename);

    /**
     * Decrypt a text via clef.clef and write the result in a file
     * @param clef Key to decrypt the file
     */
    void decode(const struct Clef *clef) const;

    /**
     * Divide a texte in size columns
     * @param size Number of columns we want
     * @return vector with the text divided in size columns
     */
    std::vector<std::string> divideText(const uint_fast32_t &size) const;


};

struct Clef {
    char *clef;
    uint_fast32_t longueur;
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
struct Clef *trouveCandidat(const File &myFile, const uint_fast32_t &l);

/**
 * Déchiffre un message encodé à l'aide du chiffre de Vigenère sans avoir
 * connaissance du mot de passe
 *
 * @param cypher Le message à déchiffrer
 * @param plain String qui contiendra le message déchiffré après l'appel
 * @param l Chiffre que l'utilisateur à choisi pour faire l'attaque du chiffre de Vigenere
 * @return None
 */
void attack(const File &myFile, const uint_fast32_t &l);



/**
 * Find the most used alphabetic letter in a string
 * @param myString String we will analyze
 * @return A tuple with the most used character and it's error
 */
std::tuple<char, float> findMostOccurence(const std::string& myString);

/**
 * Find the number of time a string is repeated in another
 * @param text String we want to check if a rotation of word
 * @param word String we want to see if it's inside word and if it's  x*time word = text
 * @return The number of time there is word inside text
 */
uint_fast32_t findOccurenceWord(const std::string &text, const std::string &word);

/**
 * Find if there is a repetitive pattern in the text -> MDPMDPMDP, pattern = MDP
 * @param text String where we want to find a repetitive string
 * @return the pattern
 */
std::string findRepeatedString(const std::string &text);

