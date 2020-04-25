#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <sstream>
#include <iostream>
#include <string>
#include <fstream>

int main()
{
    int unread;
    char *buf;

    // wait for stdin
    while(unread<1){
        if(ioctl(STDIN_FILENO, FIONREAD,&unread)){
            perror("ioctl");
            exit(EXIT_FAILURE);
        }
    }
    buf = (char*)malloc(sizeof(char)*(unread+1));

    // read from stdin fd , get socket
    read(STDIN_FILENO, buf, unread);
    int socket = atoi(buf);

    std::cout << "<html>";
    std::cout << "<head>";
    std::cout << "<title>Post Method</title>";
    std::cout << "</head>";
    std::cout << "<body>";
    std::cout << "<form method = 'post'>";
    std::cout << "Your name : <input type='text' name='Name' />Your age : <input type='text' name='Age' /><input type='submit' name='btn' value='Submit'></input>";
    std::cout << "</form>";

    int msgLen=0;
    char buffer[1024];
    memset (buffer,'\0', 1024);
    if ((msgLen = recv(socket, buffer, 1024, 0)) == -1)
    {
        printf("Error handling incoming request");
        return -1;
    }
    // std::cout << "Request =" << std::endl << buffer << std::endl;
    std::string name, age;
    std::string temp = strstr(buffer, "Name=");
    std::string temp_2 = strstr(temp.c_str(), "&Age=");
    std::string temp_3 = strstr(temp_2.c_str(), "&btn=");
    while(strcmp(temp.c_str(), temp_2.c_str()) != 0){
        name.insert(name.end(), temp[0]);
        temp.erase(temp.begin());
    }
    name.erase(name.begin(), name.begin()+5);
    // std::cout << name;
    while(strcmp(temp_2.c_str(), temp_3.c_str()) != 0){
        age.insert(age.end(), temp_2[0]);
        temp_2.erase(temp_2.begin());
    }
    age.erase(age.begin(), age.begin()+5);
    // std::cout << age;

    std::fstream output;
    output.open("insert_cgi.txt", std::ios::app);
    output << "This is insert.cgi test file\n\n";
    output << "Name = " << name << "\n" << "Age = " << age << "\n\n";
    output.close();
}