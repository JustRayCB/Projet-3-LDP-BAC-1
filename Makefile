CXX = g++
CXXFLAGS = -Werror -Wpedantic -Wall -Wextra -Wconversion -Wsign-conversion -Weffc++ \
			-Wstrict-null-sentinel -Wold-style-cast -Wnoexcept -Wctor-dtor-privacy \
			-Woverloaded-virtual -Wsign-promo -Wzero-as-null-pointer-constant \
            -Wsuggest-final-types -Wsuggest-final-methods -Wsuggest-override

all: attack decrypt


attack : attack.o vigenere.o
	$(CXX) $(CXXFLAGS) -o attack attack.o vigenere.o

decrypt: decrypt.o vigenere.o
	$(CXX) $(CXXFLAGS) -o decrypt decrypt.o vigenere.o

decrypt.o: decrypt.cpp
	$(CXX) $(CXXFLAGS) -o decrypt.o -c decrypt.cpp

attack.o : attack.cpp
	$(CXX) $(CXXFLAGS) -o attack.o -c attack.cpp

vigenere.o : vigenere.cpp
	$(CXX) $(CXXFLAGS) -o vigenere.o -c vigenere.cpp

clean:
	rm -rf *.o

mrproper: clean
	rm -rf attack
	rm -rf decrypt
