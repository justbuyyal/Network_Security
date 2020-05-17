#include <stdio.h>
char Response[] = 
"HTTP/1.1 200 OK\r\n"
"Content-Type: text/html\r\n"
"charset=UTF-8\r\n\r\n";

char webPage[] = 
"<!DOCTYPE html>\r\n"
"<html><head><title>my simple HTTPS</title></head><h2>Welcome to My Home Page</h2></body></html>";

char viewPage_1[] = 
"<html><head><title>View List</title></head><body>"
"<h3>";

char viewPage_2[] =
"</h3>"
"</body></html>";