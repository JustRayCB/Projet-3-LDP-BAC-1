import sys


def main():
    if len(sys.argv) < 4:
        print("Utilisation: python encrypt.py <nom_fichier_clair> <mot_de_passe> <nom_fichier_chiffre>",
              file=sys.stderr)
        sys.exit(1)

    nom_fichier_clair: str = sys.argv[1]
    mot_de_passe: str = sys.argv[2].upper()
    nom_fichier_chiffre: str = sys.argv[3]
    to_encrypt = parse_file_claire(nom_fichier_clair)
    print(to_encrypt)
    real_password = associate_pw(to_encrypt[0], mot_de_passe)
    print(real_password)
    crypted = encrpt(to_encrypt[0], real_password)
    print(crypted)
    write_file(nom_fichier_chiffre, crypted, to_encrypt[1])


def parse_file_claire(file_name):
    text = []
    length = []
    for line in open(file_name, encoding='utf-8'):
        text.append(line.strip())
        length.append(len(line.strip()))
    return " ".join(text).upper(), length


def associate_pw(text: str, pw: str):
    sep_pw = ""
    temp = text.replace(" ", "")
    idx = -1
    for letter in range(len(temp)):
        idx += 1
        if (65 <= ord(temp[letter]) <= 90):
            sep_pw += pw[idx]
        elif not (65 <= ord(temp[letter]) <= 90) :
            sep_pw += temp[letter]
            idx -= 1
        if idx == len(pw)-1:
            idx = -1
    pw = ""
    idx = -1
    for letter in range(len(text)):
        my_letter = text[letter]
        if my_letter == " ":
            pw += " "
        elif my_letter != ' ':
            idx += 1
            pw += sep_pw[idx]
        if idx == len(sep_pw)-1:
            idx = -1
    return pw


def associate_letter(key:str, clear:str):
    clear = clear.upper()
    all_letters = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    my_line = all_letters[all_letters.index(key):] + all_letters[:all_letters.index(key)]
    return my_line[all_letters.index(clear)]


def encrpt(text, mdp):
    res = ""
    for idx in range(len(text)):
        try:
            res += associate_letter(mdp[idx], text[idx])
        except ValueError:
            res += mdp[idx]
    return res


def write_file(file_name, text, length):
    with open(file_name, 'w', encoding="utf-8") as fp:
        temp = 0
        for idx in length:
            phrase = text[temp:idx]
            fp.write(phrase + "\n")
            text = text[idx+1:]


if __name__ == "__main__":
    main()

