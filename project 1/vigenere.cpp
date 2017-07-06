//
//  vigenere.cpp
//
//  Vigenere cipher cracker for ASCII encoded languages
//  Theo Ireton (2014)
//

#include <cstdlib>
#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <string>
#include <sstream>
#include <iomanip>
#include <math.h>

using namespace std;

const int ARGUMENT_COUNT = 4;
const int MIN_KEY_LEN = 1;
const int MAX_KEY_LEN = 13;
const int INVALID_KEY = -1;

typedef vector<string> stringVector;
typedef vector<int> intVector;
typedef unordered_map<int, double> intDoubleMap;

fstream openFile(string path, ios_base::openmode mode)
{
    fstream stream;
    
    stream.open(path, mode);
    
    if (!stream.is_open())
    {
        cerr << "Could not open file \"" << path << "\"\n";
        exit(EXIT_FAILURE);
    }
    
    return stream;
}

intVector loadInputFile(string path)
{
    cout << "Trying to load input file \"" << path << "\"";
    cout.flush();
    
    fstream inputFile = openFile(path, ios_base::in);
    
    stringstream buffer;
    buffer << inputFile.rdbuf();
    
    intVector bytes;
    
    string word;
    
    while(buffer >> setw(2) >> word)
    {
        stringstream converter;
        
        unsigned int temp;
        converter << hex << word;
        converter >> temp;
        bytes.push_back(temp);
    }
    
    cout << "\t\tDone\n";
    cout << bytes.size() << " total bytes\n\n";
    cout.flush();
    
    inputFile.close();
    return bytes;
}

void updateFrequencyDistribution(intDoubleMap *frequencyDistribution, int value)
{
    auto character = frequencyDistribution->find(value);
    
    if (character == frequencyDistribution->end())
    {
        // new character
        frequencyDistribution->insert(make_pair(value, 1.0));
    }
    else
    {
        character->second++;
    }
}

double calculateFrequencyDistribution(intDoubleMap *frequency)
{
    double frequencyDistribution = 0.0;
    
    for (auto it = frequency->begin(); it != frequency->end(); ++it)
    {
        frequencyDistribution += pow(it->second, 2.0);
    }
    
    return frequencyDistribution;
}

int calculatePercentileDistribution(intDoubleMap *frequency)
{
    int totalLetterFrequencies = 0;
    
    for (auto it = frequency->begin(); it != frequency->end(); ++it)
    {
        totalLetterFrequencies += it->second;
    }
    
    for (auto it = frequency->begin(); it != frequency->end(); ++it)
    {
        it->second /= totalLetterFrequencies;
    }
    
    return totalLetterFrequencies;
}

intDoubleMap calculateLetterFrequency(stringVector *dictionary)
{
    cout << "Importing and calculating letter frequency";
    cout.flush();
    
    intDoubleMap letterFrequencies;
    
    for (auto it = dictionary->begin(); it != dictionary->end(); ++it)
    {
        string line = *it;
        
        for (auto its = line.begin(); its != line.end(); ++its)
        {
            updateFrequencyDistribution(&letterFrequencies, *its);
        }
    }
    
    int totalLetterFrequencies = calculatePercentileDistribution(&letterFrequencies);
    
    cout << "\t\tDone\n";
    cout << letterFrequencies.size() << " unique characters, " << totalLetterFrequencies << " total characters\n\n";
    cout.flush();
    
    return letterFrequencies;
}

stringVector loadLanguageFile(string path)
{
    cout << "Trying to load dictionary \"" << path << "\"";
    cout.flush();
    
    // open language dictionary
    fstream languageFile = openFile(path, ios_base::in);
    
    intDoubleMap letterFrequencies;
    stringVector dictionary;
    string line;
    
    while (getline(languageFile, line))
    {
        // lower case all characters to ensure that we get a proper distribution for letters
        transform(line.begin(), line.end(), line.begin(), ::tolower);
        dictionary.push_back(line);
    }
    
    cout << "\t\tDone\n";
    cout << dictionary.size() << " words\n\n";
    cout.flush();
    
    languageFile.close();
    return dictionary;
}

int calculateKeyLength(intVector *inputBytes)
{
    cout << "Calculating key length";
    cout.flush();
    
    // determine distribution for key lengths MIN_KEY_LENGTH to MAX_KEY_LENGTH
    double maxFrequencyDistribution = 0.0;
    int length = 0;
    
    for (int i = MIN_KEY_LEN; i <= MAX_KEY_LEN; ++i)
    {
        intDoubleMap frequencies;
        
        for (auto it = inputBytes->begin(); it <= inputBytes->end(); it += i)
        {
            updateFrequencyDistribution(&frequencies, *it);
        }
        
        calculatePercentileDistribution(&frequencies);
        
        double frequencyDistribution = calculateFrequencyDistribution(&frequencies);
        
        if (frequencyDistribution > maxFrequencyDistribution)
        {
            maxFrequencyDistribution = frequencyDistribution;
            length = i;
        }
    }
    
    cout << "\t\tDone\n";
    cout << "Possible key length: " << length << "\n\n";
    cout.flush();
    
    return length;
}

string decrypt(intVector *inputBytes, int keyLength, intDoubleMap *letterFrequency)
{
    cout << "Attempting to find cipher key and decrypt text";
    cout.flush();
    
    string decrypted;
    vector<vector<intVector> > decryptedItems;
    
    for (int i = 0; i < keyLength; ++i)
    {
        vector<intVector> decryptedStream;
        
        for (int j = 0; j < 256; ++j)
        {
            intVector decryptedValues;
            
            for (auto it = inputBytes->begin() + i; it < inputBytes->end(); it += keyLength)
            {
                // xor with char
                int decrChar = *it ^ j;
                
                if (decrChar < 32 || decrChar > 127)
                {
                    decryptedValues.clear();
                    break;
                }
                else
                {
                    decryptedValues.push_back(decrChar);
                }
            }
            
            if (decryptedValues.size() > 0)
            {
                decryptedStream.push_back(decryptedValues);
            }
        }
        
        if (decryptedStream.size() == 0)
        {
            return "";
        }
        
        decryptedItems.push_back(decryptedStream);
    }
    
    if(decryptedItems.size() == 0)
    {
        return "";
    }
    
    vector<intVector> bestStreams;
    
    // run through each possiblity and check against language distribution
    for (auto itemIt = decryptedItems.begin(); itemIt < decryptedItems.end(); ++itemIt)
    {
        double nearestFrequencyDistribution = 0.0;
        intVector bestStream;
        
        for (auto streamIt = itemIt->begin(); streamIt < itemIt->end(); ++streamIt)
        {
            intDoubleMap decryptedStreamFrequency;
            
            for (auto valueIt = streamIt->begin(); valueIt < streamIt->end(); ++valueIt)
            {
                updateFrequencyDistribution(&decryptedStreamFrequency, *valueIt);
            }

            // calculate distribution
            calculatePercentileDistribution(&decryptedStreamFrequency);
            
            double sumDistribution = 0.0;
            
            // compute against language letter frequency
            for (auto valueIt = decryptedStreamFrequency.begin(); valueIt != decryptedStreamFrequency.end(); ++valueIt)
            {
                auto character = letterFrequency->find(valueIt->first);
                
                if (character != letterFrequency->end())
                {
                    // found
                    sumDistribution += character->second * valueIt->second;
                }
            }
            
            if (sumDistribution > nearestFrequencyDistribution)
            {
                bestStream = *streamIt;
                nearestFrequencyDistribution = sumDistribution;
            }
        }
        
        bestStreams.push_back(bestStream);
    }
    
    int stillBusy = keyLength;
    
    stringstream decryptionStream;
    
    size_t index = 0;
    while (stillBusy > 0)
    {
        for (int i = 0; i < keyLength; i++)
        {
            intVector keyStream = bestStreams.at(i);
            
            if(keyStream.size() > index)
            {
                int value = keyStream.at(index);
                decryptionStream << (char)value;
            }
            else
            {
                stillBusy--;
            }
        }
        
        index++;
    }
    
    decrypted = decryptionStream.str();
    
    if (decrypted.length() != inputBytes->size())
    {
        return "";
    }
    
    cout.flush();
    
    cout << "\t\tDone\n";
    cout.flush();
    
    return decrypted;
}

void writeOutFile(string path, string decrypted)
{
    cout << "Writing output file \"" << path << "\"";
    
    // open output file
    fstream outputFile = openFile(path, ios_base::out);
    outputFile << decrypted;
    outputFile.close();
    
    cout << "\t\tDone\n\n";
}

int main(int argc, char *argv[])
{
    if (argc < ARGUMENT_COUNT)
    {
        cerr << "Usage: vigenere input_file output_file language_dictionary\n";
        return EXIT_FAILURE;
    }
    
    // read input file into string
    intVector inputBytes = loadInputFile(argv[1]);
    
    // load the language file into memory
    // dictionary itself is not used in decryption, but could add another level of verification
    stringVector dictionary = loadLanguageFile(argv[3]);
    
    // then calculate letter frequency
    intDoubleMap letterFrequency = calculateLetterFrequency(&dictionary);
    
    // now try to determine key length
    /*
    int keyLength = calculateKeyLength(&inputBytes);
    
    if (keyLength == 0)
    {
        cerr << "Could not determine key length\n";
        return EXIT_FAILURE;
    }
     */
    int keyLength = 31;
    
    // attempt to obtain key and decrypt
    string decrypted = decrypt(&inputBytes, keyLength, &letterFrequency);
    
    if(decrypted.length() == 0)
    {
        cout << "Failed\n\n";
        cout << "Could not decrypt ciphertext\n";
    }
    
    writeOutFile(argv[2], decrypted);
    
    cout << "Decryption complete\n";
    
    return EXIT_SUCCESS;
}
