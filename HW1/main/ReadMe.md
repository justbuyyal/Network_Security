# 網路安全 Homework 1
## Simple Web Server
---
### 1. 建置環境與使用說明
* **Visual Code**
* **WSL(Ubuntu 16.04)**
* **C / C++**
* **Test Command**
```
make // build
make test // ./main
make clean // remove all file which is made
```
---
### 2. 重要程式碼說明

#### main.cpp

1. socket 轉換
```cpp=
    /*
        Get socket and change to char* sending to CGI
    */
    stringstream strs;
    strs << socket;
    string temp_str = strs.str();
    char* Wsk = (char*) temp_str.c_str();
```
* **把socket從int轉換成string要傳給CGI使用**

2. 找對應url
```cpp=
string urls[4] ={"./", "./program.cgi", "./insert.cgi", "./view.cgi"};

uri.insert(uri.begin(), '.');
bool flag = false;
// Find the correspond cgi program from urls array
for(int i = 0; i < sizeof(urls)/sizeof(urls[0]); i++){
    if(strcmp(uri.c_str(), urls[i].c_str()) == 0){
        flag = true;
        if(i == 0){
            execlp("./host.cgi", "./host.cgi", NULL);
        }
        else{
            execlp(uri.c_str(), uri.c_str(), NULL);
        }
        break;
    }
}
// Error URL
if(!flag){
    std::string error("Status: 404 Not found\r\n\r\n");
        n = send(socket, error.c_str(), error.size(), 0);
}
```
* **根據urls陣列找尋對應的url在執行相對應的CGI program, 找不到會顯示錯誤**

3. CGI導向socket
```cpp=
// receive the message from the CGI program
while (read(cgiOutput[0], &c, 1) > 0)
{
    /* output the message to socket(web) */
    write(socket, &c, 1);
}
```
* **將從CGI傳送出來的訊息導向socket, 原始是導向STDOUT**
---
#### view.c

1. 讀檔並輸出
```cpp=
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
```
* ***讀取insert_cgi.txt檔案並輸出, CGI的STDOUT會導向socket, 所以要包含html語法**

#### program.c

1. 取得main.cpp傳送的資料並顯示在網頁
```cpp=
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

// read from stdin fd
read(STDIN_FILENO, buf, unread);

// output to stdout
printf("<HTML><HEAD><meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\n");
printf("<TITLE>I'm a example</TITLE>\n");
printf("<BODY>parameter: %s</BODY></HTML>\n",buf);
```
* **main.cpp 會傳送資訊給CGI(傳送socket), CGI的STDOUT會導向socket, 所以要包含html語法**

#### insert.c

1. 讀取從main.cpp傳送資料
```cpp=
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

// read from stdin fd
read(STDIN_FILENO, buf, unread);
int socket = atoi(buf);
```
* **讀取從STDIN從送資料(socket), 並把字串轉換成整數**

2. 建立可以輸入的網頁
```cpp=
std::cout << "<html>";
std::cout << "<head>";
std::cout << "<title>Post Method</title>";
std::cout << "</head>";
std::cout << "<body>";
std::cout << "<form method = 'post'>";
std::cout << "Your name : <input type='text' name='Name' />Your age : <input type='text' name='Age' /><input type='submit' name='btn' value='Submit'></input>";
std::cout << "</form>";
```
* **CGI的STDOUT會導向socket, 所以會顯示出可以輸入的網頁**

3. 讀取socket的Request
```cpp=
int msgLen=0;
char buffer[1024];
memset (buffer,'\0', 1024);
if ((msgLen = recv(socket, buffer, 1024, 0)) == -1)
{
    printf("Error handling incoming request");
    return -1;
}
```
* **從取得的socket再次接收Request並存到buffer**

4. 處理Request並擷取需要的字串
```cpp=
std::string name, age;
std::string temp = strstr(buffer, "Name=");
std::string temp_2 = strstr(temp.c_str(), "&Age=");
std::string temp_3 = strstr(temp_2.c_str(), "&btn=");
// Get name
while(strcmp(temp.c_str(), temp_2.c_str()) != 0){
    name.insert(name.end(), temp[0]);
    temp.erase(temp.begin());
}
name.erase(name.begin(), name.begin()+5);
// Get age
while(strcmp(temp_2.c_str(), temp_3.c_str()) != 0){
    age.insert(age.end(), temp_2[0]);
    temp_2.erase(temp_2.begin());
}
age.erase(age.begin(), age.begin()+5);
```
* **函數strstr()會回傳讀取到條件字串以後的所有內容, 使用strcmp()取的需要的字串再拿掉變數名得到資訊**
* **strstr() example: "xxxxName=test&Age=17" => temp = "Name=test&Age=17", temp_2 = "&Age=17"**

5. 將讀取資訊輸出到本地
```cpp=
std::fstream output;
output.open("insert_cgi.txt", std::ios::app);
output << "This is insert.cgi test file\n\n";
output << "Name = " << name << "\n" << "Age = " << age << "\n\n";
output.close();
```
* **建立insert_cgi.txt檔案並設定從檔案結尾繼續寫入, 不會覆蓋檔案**

### 3. 設計架構與功能說明
* **設計架構**
![](https://i.imgur.com/4LN2iUz.png)

* **建置步驟 :**
1. 建立socket(TCP)
2. 連線
3. 確認連線
4. 接收Request
5. 處理Request
6. 回應Request

* **設計功能**
1. GET:
    * **在localhost:port後加入url導向對應CGI**
    * **For example: localhost:8787/view.cgi**
2. POST:
    * **在某對應CGI下有可輸入網頁, 輸入後可以透過CGI program取得輸入資訊儲存到本地檔案**

### 4. 成果截圖

1. Web Host
![](https://i.imgur.com/GsRb5fV.png)

2. program.cgi(顯示從main.cpp取得的socket資訊)
![](https://i.imgur.com/gNnrEPj.png)

3. view.cgi(顯示本地端insert_cgi.txt檔案內容, 若無此檔案就顯示File Not Found)
* **File Not Found**
![](https://i.imgur.com/ubRzmS6.png)
* **File Found**
![](https://i.imgur.com/4fzkqw5.png)

4. insert.cgi
![](https://i.imgur.com/NQZhY3e.png)
* **insert.cgi test**
![](https://i.imgur.com/fzipnUU.png)
![](https://i.imgur.com/hLPpfvx.jpg)

---
### 5. 困難與心得
* **一開始比較困難的是獲取url, 原本使用環境變數接url但接不到所以直接把整個Request抓下來用stringstream擷取。**
* **第二是父子程序之間的導向問題, 先前不知道要如何將CGI的STDOUT輸出到網頁, 之後有發現要修改main.cpp父程序接收子程序回傳的訊息導向(write)。**
* **個人認為最困難的部分是POST實作方式, 若只能透過一個CGI程式完成就要把socket資訊傳給子程序進行解析, 因此我用main.cpp傳送socket給insert.c, insert.c在接收一次socket資訊的到POST的資訊, 再對文字做擷取以及輸出成檔案。**
* **在C / C++ 混用的狀況下很容易搞混一些函數的使用或資料型態。**