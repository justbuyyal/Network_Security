#include <stdlib.h>
#include <stdio.h>
#include <error.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <string>
#include <fstream>
#include <iostream>

using namespace std;

int main(void){
    cout << "<html><head><title>View</title></head><body>";
    fstream input("insert_cgi.txt", ios::in);
    if(!input){
        cout << "File Not Found !<br>";
        cout << "You can try 'localhost:port/insert.cgi' input something<br>";
        exit(1);
    }
    string temp;
    while(getline(input, temp)){
        cout << temp << "<br>";
    }
    cout << "</body></html>";
    input.close();
}