#include <stdio.h>
char Response[] = 
"HTTP/1.1 200 OK\r\n"
"Content-Type: text/html\r\n"
"charset=UTF-8\r\n\r\n";

char webPage[] = 
"<!DOCTYPE html>\r\n"
"<html><head><title>my simple HTTPS</title></head><body><h2>Welcome to My Home Page</h2><br>"
"<h3>You Can Use The Below URL To Access My Web</h3><br>"
"<h4>1. localhost:port/view : view file list from server</h4><br>"
"</body></html>";

char viewPage_1[] = 
"<html><head><title>View List and Choose File To Copy</title></head><body>"
"<h3>";

char viewPage_2[] =
"</h3>"
"</body></html>";

char copy[] =
"<form method= 'post'>Input FileName You Want To Copy : <input type='text', name='Name', value='helloworld.c'></input></form><br>";

char file_not_found[] =
"<html><head><title>File Not Found</title></head><body><h3>Please Refresh Page to input a correct File Name !!</h3></body></html>";

char wrong_page[] =
"<html><head><title>Wrong webpage</title></head><body><h1>404 Not Found</h1></body></html>";

char download_1[] =
"<!DOCTYPE html><html><body><h1>Here is Your File</h1>"
"<p>Click to Download<p>"
"<a href='/Download/";

char download_2[] =
"' download>";