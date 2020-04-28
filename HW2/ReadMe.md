# 網路安全 Homework 2
[TOC]
* B10615026
## TLS/SSL Server and Client
---
### 1. 建置環境與使用說明
* **Visual Code**
* **WSL(Ubuntu 16.04)**
* **C**
* **Key and Certification Generation**
```
// Build CA key
openssl genrsa -des3 -out ca.key 4096
// Build CA ca.crt
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt
// private key
openssl genrsa -out *.key 4096
// Generate CSR file(Context can not be the same as CA)
openssl req -new -key *.key -subj "/C=TW/ST=Taiwan/L=Taipei City/O=MyOrg/OU=MyUnit/CN=my.domain" -sha256 -out *.csr
// Use CA to generate certification *.crt
openssl x509 -req -in *.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out *.crt -days 30 -sha256
```
* **Key and Certification Verify**
```
// Verify key and csr
openssl req -in *.csr -noout -verify -key *.key
// Verify crt
openssl verify *.crt
```
* **Test Command**
```
make // build
make run // sudo ./main 1024
make test // ./client localhost 1024
make del // remove all file which is made
```
---
### 2. 重要程式碼說明

#### main.c

1. 確認最高權限
```cpp=
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}
```
* **使用getuid()函數確認使用者權限**
2. Server端載入key與Crt檔案
```cpp=
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
```
* **使用openssl內建函數將key file跟自己的certification file加到目前server的context並驗證key**
3. void Servlet() 解析client送過來的訊息
```cpp=
strcpy(buf_temp, buf);
char *fileName = NULL;
int flag, copy;
flag = copy = 0;
char *ptr = strtok(buf_temp, " ");
while(ptr != NULL)
{
        flag += 1;
        if(flag == 1 && strcmp(ptr, "cp") == 0) copy = 1;
        if(flag == 2 && copy == 1){ // Save file name
                fileName = malloc(sizeof(char) * strlen(ptr));
                strcpy(fileName, ptr);
        }                
        ptr = strtok(NULL, " ");
}
free(ptr);
```
* **先複製接收訊息, 用strtok將訊息用空白分開, 判斷訊時是否為檔案複製或一般Shell指令, 若為檔案複製則紀錄檔案名稱到fileName**
4. 執行檔案複製或shell指令
```cpp=
FILE *fp;
if(flag == 2 && copy)
{
    // Deal with fileName with newline at end
    fileName = strtok(fileName, "\n");
    /* File Copy */
    printf("FileName = \"%s\"\n", fileName); // debug
    fp = fopen(fileName, "rb"); // read binary
    if(fp == NULL)
    {
        SSL_write(ssl, FileNotFound, strlen(FileNotFound)); // file not found
        printf("%s\n", FileNotFound);
    }
    else
    {
        long filelen;
        char *buffer = NULL;
        printf("Reading File\n"); // debug
        fseek(fp, 0, SEEK_END); // Jump to the end of file
        filelen = ftell(fp); // Get current byte offset in the file
        rewind(fp); // Jump back to the beginning of the file
        buffer = (char *)malloc(filelen * sizeof(char));
        fread(buffer, filelen, 1, fp); // read entire file
        SSL_write(ssl, buffer, strlen(buffer)); // send file to client
        printf("File Context = \"%s\"\n", buffer); // debug
        free(buffer);
    }
    fclose(fp);
}
else
{
    printf("system command : \"%s\"\n", strtok(buf, "\n")); // debug
    /* Simple Shell */
    fp = popen(buf, "r"); /* open the command for reading */
    while(fgets(temp, sizeof(temp) -1, fp) != NULL)
    {
        strcat(reply, temp);
    }
    pclose(fp);
    SSL_write(ssl, reply, strlen(reply)); // reply to client
    if(system(buf) < 0) SSL_write(ssl, ErrorCommand, strlen(ErrorCommand));
}
free(fileName);
```
* **if: 做檔案複製, 先將檔案名去除換行才找的到檔案, 以binary讀取檔案資料並放到buffer, 回送buffer給client**
* **else: 以popen()函數讀取Shell指令, while()執行將shell指令output聯集到**
5. main() 要求client送Certification file
```cpp=
SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL);
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL );
SSL_CTX_set_verify_depth(ctx, 1);
```
* **載入CA的憑證來做驗證依據, 要求連線的客戶要送憑證(一般預設客戶不會送, 就算有載入自己的憑證), 驗證深度為一層**
---
#### client.c
1. 載入certification file跟key
```cpp=
LoadCertificates(ctx, "client.crt", "client.key"); /* load certs */
```
2. client輸入訊息
```cpp=
/* Simple Shell */
printf("Input Your shell command below :\n");
fgets(msg, 1024, stdin);
SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
```
* **fgets一行從terminal輸入的指令傳送給server**
3. 判斷輸入訊息
```cpp=
bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
buf[bytes] = 0;
if(flag == 2 && copy)
{
    /* File Copy */
    cpy = malloc(sizeof(char) * (strlen(fileName) + 5));
    strcpy(cpy, "copy_");
    printf("filena = %s\n", cpy);
    strcat(cpy, fileName); // Create new fileName
    cpy = strtok(cpy, "\n");
    printf("file name = \"%s\"\n", cpy); // debug
    FILE *output;
    output = fopen(cpy, "w+b");
    fwrite(buf, strlen(buf), 1, output);
    fclose(output);
    printf("Copy Done !\n");
}
else
{
    printf("%s\n", buf);
}
```
* **if: 輸入為檔案複製, 取得檔案名稱並命名新的複製檔, 將從server接收到的訊息寫進新檔案裡完成複製**
* **else: 輸出shell指令結果**
---
### 3. 設計架構與功能說明
* **設計架構**
![](https://i.imgur.com/Kv8V5RU.png)

* **建置步驟 :**
1. 建立socket(TCP)
2. 連線
3. 確認連線
4. Client Hello
5. Server Hello
6. HandShake with certificate request
7. Exchange Message

* **設計功能**
1. File Copy:
    * **在Client端輸入指令'cp fileName'**
    * **檔案必須是在server端存在的檔案**
2. Simple Remote Shell without cd:
    * **Client端輸入system指令如(ls, rm, mkdir, cat)**
    * **顯示server端的結果**
---
### 4. 成果截圖

1. File Copy
![](https://i.imgur.com/W8zCMhw.jpg)

2. Simple Shell
* **ls and ls -al**
![](https://i.imgur.com/eLBegt9.jpg)
* **cat file**
![](https://i.imgur.com/NON6Ijl.jpg)
* **rm file**
![](https://i.imgur.com/K1xBSHB.jpg)
* **mkdir dir**
![](https://i.imgur.com/ilYONBr.jpg)
---
### 5. 困難與心得
* **一開始在建立Certification上有遇到問題, 就明明是用CA簽出來的程式卻顯示錯誤說是自簽的, 後來發現.crt檔案中設定一些參數例如(State, Country等)要與CA的certification不一樣才不會被判定是自簽的**
* **有時候在測試時會跳出Segment Fault但程式本身看不出甚麼問題, 有時候是微小的問題像是''跟""的不同, 不然就要看噴出的warning訊息去判斷**
* **由於Server端的檔案複製是用動態buffer去存的跟Client接收的固定陣列不同, 所以client要夠大的陣列才可以複製一些比較大的檔案例如(*.key)**
* **一般SSL溝通都只有Server會送憑證過去而client不會, 且client端預設不會主動送憑證給Server, 因此需要加入一些函數在Server端要求client要提供憑證作驗證, 我們只有用一個.crt file所以深度只有一層**
* **為了要接收執行'ls -al'結果, 接收buf如果不夠大就會造成某些函數的stack爆掉**