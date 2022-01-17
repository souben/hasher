#include <iostream>
#include "include/keccak.h"
#include <fstream>
#include "boost/property_tree/ptree.hpp"
#include "boost/property_tree/json_parser.hpp"

using namespace std;



string read_file(string path)
{
    boost::property_tree::ptree root = {};
    boost::property_tree::read_json(path, root);
    std::string output  = root.get<std::string>("result", "not found");
    return output;
}

void keccakf_test()
{
    uint64_t st[25];
    for (uint64_t i=0; i< 25;i++)
    {
        st[i] = i;
    } 

    keccakf(st);

    std::string result;
    for (uint64_t i=0; i< 25;i++)
    {
        result += to_string(st[i]) + " ";
    }

    string file_output = read_file("../keccakf_go.json");
    
    if (file_output == result) 
    {
        cout << "KECCAKF : TEST PASSED" << endl;;
    }else
    {
        cout << "KECCAKF : TEST FAILED" << endl;;
    }
}


void keccak_test(string input, int sz=32)
{ 
    uint8_t md0[sz];
    keccak((const uint8_t*)input.data(), input.size(), md0, sz); 

    std::string result;
    for (uint64_t i=0; i < sz;i++)
    {
        result += to_string(md0[i]) + " ";
    }
    
    string file_output = read_file("../keccak_go.json");
    if (file_output == result) 
    {
        cout << "KECCAK : TEST PASSED" << endl;
    }else
    {
        cout << "KECCAK : TEST FAILED" << endl;
    }
}



int main()
{

    // keccakf test
    keccakf_test();

    // keccak test
    keccak_test("", 32);
}


