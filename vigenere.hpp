/*
 * Header of the attack.cpp and decrypt.cpp files
 */
#include <string>
#include <vector>
#include "tuple"
using std::string;
using  std::vector;
using std::tuple;


extern vector<size_t> lines;    //global variable of the length of the lines in the file

/**
 * Dechiffre un message chiffré encodé à l'aide du chiffre de Vigenère et
 * d'une clé connue.
 *
 * @param cypher Le message à déchiffrer
 * @param clef La clef
 * @param plain String qui contiendra le message déchiffré après l'appel
 * @return None
 */
void decode(const string &cypher, struct Clef *clef, string &plain);

/**
 * Etant donné le message chiffré, renvoi une clé de type struct
 * Clef (cfr. l'énoncé pour sa déclaration)
 *
 * @param cypher Le message chiffré
 * @param l la longueur de la clé
 * @return A pointer to a struct Clef
 */
struct Clef *trouve_candidat(const string &cypher, size_t l);

/**
 * Déchiffre un message encodé à l'aide du chiffre de Vigenère sans avoir
 * connaissance du mot de passe
 *
 * @param cypher Le message à déchiffrer
 * @param plain String qui contiendra le message déchiffré après l'appel
 * @param l Chiffre que l'utilisateur à choisi pour faire l'attaque du chiffre de Vigenere
 * @return None
 */
void attack(const string &cypher, string &plain, size_t l);


//      ****Function to find a candidate****

/**
 * Divide a text in a certain number of columns
 *
 * @param cypher text we will divise
 * @param size Number of column in which we will divide the text
 * @return a vector which all the values are the different column of the divided text
 */
vector<string> divideText(const string& cypher, size_t size);

/**
 * Find the most used alphabetic letter in a string
 * @param myString String we will analyze
 * @return A tuple with the most used character and it's error
 */
tuple<char, float> findMostOccurence(string& myString);

/**
* Transform the letter according to it's place in the alphabet compared with the place of the letter E
* @param letter letter we will transform
* @return the transformed character
*/
char transformLetter(char& letter);

/**
 * Count the frequency of the letter E in the text
 *
 * @param cypher Text we will analyze
 * @return the frequency of the letter E
 */
double findOcuurencee(const string &cypher);


//      ****Use to decrypt****

/**
 * Decrypt the text according to a struct clef without writing
 * the decrypted text in a file
 *
 * @param cypher Text we need to decrypt
 * @param clef Clef that contain the password to decrypt
 * @return The decrypted text
 */
string decryptedText(const string &cypher, struct Clef *clef);

/**
 * Function that read the file named filename and recover the lines and the length of these lines
 *
 * @param filename the name of the file
 * @return tuple with the result of all lines of the file as a string and a vector with the length of the lines' file
 */
tuple<string, vector<size_t>> read_file(const string& filename);

/**
 * Function that will associate a password according to the length of text and the spaces in there
 * @param text the string which was in the fil to decrypt
 * @param pw Password to associate
 * @return the associated password as a string
 */
string associate_pw(const string& text, string pw);

/**
 * * Decrypt a letter with the other
 *
 * @param key Letter to decrypt the encrypted letter
 * @param crypt encrypted letter
 * @return The decrypted letter
 */
char associate_letter(char key, char crypt);

/**
 * Decrypt the text with the password
 *
 * @param text encrypted text to decrypt
 * @param mdp Password
 * @return string decrypted
 */
string decrypt(string text, string mdp);

/**
 * Will write a text  line per line in a file
 *
 * @param filename File where we want to write the text
 * @param text Text we want to write in the file
 * @param length List of the line's length to write in the file
 */
void write_file(const string& filename,string text, const vector<size_t>& length);
