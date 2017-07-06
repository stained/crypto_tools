//
//  otp.cpp
//
//  Cracking multiple ciphertexts generated using [XOR-base] OTP with same key
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

const int MIN_ARGUMENT_COUNT = 5;

// added once message known
const char KNOWN_MESSAGE[] = "I am planning a secret mission.";
const int KNOWN_MESSAGE_POST = 1;


typedef vector<fstream *> fstreamVector;
typedef vector<int> intVector;
typedef vector<intVector> intVectorVector;

void openFile(fstream *stream, string path, ios_base::openmode mode)
{
    stream->open(path, mode);
    
    if (!stream->is_open())
    {
        cerr << "Could not open file \"" << path << "\"\n";
        exit(EXIT_FAILURE);
    }
}

void writeOutFile(string path, string decrypted)
{
    cout << "Writing output file \"" << path << "\"";
    
    // open output file
    fstream outputFile;
    openFile(&outputFile, path, ios_base::out);
    outputFile << decrypted;
    outputFile.close();
    
    cout << "\t\tDone\n\n";
}

int hexStringToInt(string hexString)
{
    stringstream converter;
    
    unsigned int temp;
    converter << hex << hexString;
    converter >> temp;
    return temp;
}

void decrypt(fstreamVector *streams)
{
    vector <stringstream *> streamBuffers;
    
    for (auto j = streams->begin(); j < streams->end(); ++j)
    {
        fstream *stream = *j;
        stringstream *buffer = new stringstream();
        *buffer << stream->rdbuf();
        streamBuffers.push_back(buffer);
    }
    
    intVector currentByte;
    intVectorVector actualKey;
    intVectorVector cipherTexts;
    
    // average number of key possibilities found to be smaller or equal to AVERAGE_MAX_POSSIBLE_KEYS.
    // Anything higher and we ignore it.
    size_t totalKeyPossiblities = 0;
    
    do
    {
        currentByte.clear();
        
        for (auto i = streamBuffers.begin(); i < streamBuffers.end(); ++i)
        {
            stringstream *buffer = *i;
            string hexVal;
            *buffer >> setw(2) >> hexVal;
            
            if (hexVal.length() == 2)
            {
                int byte = hexStringToInt(hexVal);
                currentByte.push_back(byte);
            }
            else
            {
                break;
            }
        }
        
        if (currentByte.size() > 0)
        {
            intVector possibleKey;
            
            for (int j = 1; j < 255; j++)
            {
                bool invalid = false;
                
                for (auto k = currentByte.begin(); k < currentByte.end(); ++k)
                {
                    int decodedByte = *k ^ j;
                    
                    // do some sanity check to ensure output is within appropriate range
                    if ((decodedByte < 65 && decodedByte != 32) ||
                        (decodedByte >= 91 && decodedByte <= 96) ||
                        decodedByte >= 122)
                    {
                        invalid = true;
                        break;
                    }
                }
                
                if (!invalid)
                {
                    possibleKey.push_back(j);
                }
            }
            
            size_t possibleKeySize = possibleKey.size();
            
            if (possibleKeySize > totalKeyPossiblities)
            {
                totalKeyPossiblities = possibleKeySize;
            }
            
            actualKey.push_back(possibleKey);
            
        }
        
    } while (currentByte.size() > 0);
    
    int streamCounter = 1;
    
    // key if we already know what one of the messages is
    int key[31] = {0};
    
    // try to decrypt based on the key possibilities
    // this will output some semblence of english text, then it's up to human pattern matching
    for (auto j = streams->begin(); j < streams->end(); ++j)
    {
        cout << "Ciphertext " << streamCounter << "\n";
        
        fstream *stream = *j;
        
        for (size_t j = 0; j < totalKeyPossiblities; j++)
        {
            stream->seekg(0);
            stringstream *buffer = new stringstream();
            *buffer << stream->rdbuf();
            
            string hexVal;
            
            int bytePos = 0;
            
            while (*buffer >> setw(2) >> hexVal)
            {
                int byte = hexStringToInt(hexVal);
                
                intVector keyVector = actualKey[bytePos];
                
                int keyByte = 0;
                
                if (keyVector.size() > 0)
                {
                    if (keyVector.size() > j)
                    {
                        keyByte = keyVector[j];
                    }
                    else
                    {
                        keyByte = keyVector[keyVector.size() - 1];
                    }
                    
                    int outByte = keyByte ^ byte;
                    
                    char outByteChar = static_cast<char>(outByte);
                    
                    if (strlen(KNOWN_MESSAGE) > 0)
                    {
                        if (streamCounter == KNOWN_MESSAGE_POST && KNOWN_MESSAGE[bytePos] == outByteChar)
                        {
                            key[bytePos] = keyByte;
                        }
                    }
                    
                    cout << outByteChar;
                }
                else
                {
                    // don't know what it is
                    cout << "_";
                }
                
                bytePos++;
            }
            
            cout << "\n";
        }
        
        cout << "\n";
        ++streamCounter;
    }
    
    // if we've already found the key we can just decrypt them all
    if(key[0] != 0)
    {
        
        streamCounter = 1;
        
        for (auto j = streams->begin(); j < streams->end(); ++j)
        {
            fstream *stream = *j;
            
            stream->seekg(0);
            stringstream *buffer = new stringstream();
            *buffer << stream->rdbuf();
            
            string hexVal;
            
            int bytePos = 0;
            
            while (*buffer >> setw(2) >> hexVal)
            {
                int byte = hexStringToInt(hexVal);
                
                intVector keyVector = actualKey[bytePos];
                
                int keyByte = key[bytePos];
                int outByte = keyByte ^ byte;
                char outByteChar = static_cast<char>(outByte);
                cout << outByteChar;
                bytePos++;
            }
            cout << "\n";
            
            ++streamCounter;
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc < MIN_ARGUMENT_COUNT)
    {
        cerr << "Usage: otp in_file1 in_file2 in_file3 ...in_fileN\n";
        
        return EXIT_FAILURE;
    }

    fstreamVector streams;
    
    for (int i = 1; i < argc - 1; ++i)
    {
        cout << "Loading file " << argv[i] << "\n";
        fstream *stream = new fstream();
        openFile(stream, argv[i], ios_base::in);
        streams.push_back(stream);
    }
    
    cout << "Files loaded\n\n";
    cout << "Decrypting streams\n";

    decrypt(&streams);
    
    cout << "Decryption complete\n";
    
    return EXIT_SUCCESS;
}
