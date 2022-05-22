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
 * Dechiffre un message chiffré encodé à l'aide du chiffre de Vigenère et
 * d'une clé connue.
 *
 * @param cypher Le message à déchiffrer
 * @param clef La clef
 * @param plain String qui contiendra le message déchiffré après l'appel
 * @return None
 */
void decode(const std::string &cypher, struct Clef *clef, std::string &plain);

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

//      ****Use to decrypt****


/**
 * Function that read the file named filename and recover the lines and the length of these lines
 *
 * @param filename the name of the file
 * @return tuple with the result of all lines of the file as a string and a vector with the length of the lines' file
 */
std::tuple<std::string, std::vector<size_t>> read_file(const std::string& filename);

/**
 * Function that will associate a password according to the length of text and the spaces in there
 * @param text the string which was in the fil to decrypt
 * @param pw Password to associate
 * @return the associated password as a string
 */
std::string associate_pw(const std::string& text, const std::string& pw);



void writeFile(const std::string &text, const struct Clef *clef, const std::string &filename, const std::vector<size_t> &length);

/**
 * Decrypt the text with the password
 *
 * @param text encrypted text to decrypt
 * @param mdp Password
 * @return string decrypted
 */
std::string decrypt(const std::string &text, const std::string &mdp);

/**
 * Will write a text  line per line in a file
 *
 * @param filename File where we want to write the text
 * @param text Text we want to write in the file
 * @param length List of the line's length to write in the file
 */
void write_file(const std::string& filename, std::string text, const std::vector<size_t>& length);
