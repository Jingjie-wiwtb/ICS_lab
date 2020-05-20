#include <stdio.h>
#include "csapp.h"
#include <limits.h>

/* Recommended max cache and object sizes */
#define MAX_CACHE_SIZE 1049000
#define MAX_OBJECT_SIZE 102400

/* max maximum number of active connections */
#define T 10

/* header */
static const char *user_agent_header = "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.3) Gecko/20120305 Firefox/10.0.3\r\n";
static const char *conn_header = "Connection: close\r\n";
static const char *proxy_header = "Proxy-Connection: close\r\n";

//static const char *prox_hdr = "Proxy-Connection: close\r\n";


/* 函数声明 */
void doit(int connfd);
void parse_uri(char *uri,char *hostname,char *path,int *port);
int connect_server(char *hostname,int port,char *path);
void *thread(void *vargp);

/* cache */

typedef struct{
	char uri[MAXLINE];
	char content[MAX_OBJECT_SIZE];
	int time;
	int valid;	//有效位：1-占用
	sem_t cnt_mutex;	//信号量  保护对readcnt 的访问
	int readcnt;
	sem_t lock;
	
}cache_block;

cache_block cache[T];


void cache_init();
int cache_search(char *uri, int connfd);
//void cache_read(int index, char *read_content);
int cache_place();
void cache_write(char *content, char *uri);
void cache_read_pre(int index);
void cache_read_suc(int index);

void cache_init(){	// 同步对有限缓冲区并发访问   p706
	for(int i = 0; i < T; i++){
		cache[i].uri[0] = '\0';
		cache[i].content[0] = '\0';

		cache[i].valid = 0;
		cache[i].time = 0; 
		cache[i].readcnt = 0;
		Sem_init(&cache[i].cnt_mutex, 0 , 1);
		Sem_init(&cache[i].lock, 0 , 1);
	}
}

/* reader —— writer */   //p707  读者优先


	
int main(int argc,char **argv){

    int listenfd, *connfdp;
    char hostname[MAXLINE],port[MAXLINE];
	socklen_t  clientlen;
    struct sockaddr_storage clientaddr;
	pthread_t tid;

/* Check command-line args */
    if(argc != 2){
        fprintf(stderr,"usage :%s <port> \n",argv[0]);
        exit(1);
    }

	//初始化缓存器
	cache_init();
	
	  Signal(SIGPIPE,SIG_IGN);
//服务器创建一个监听描述符，准备好接受连接请求
    listenfd = Open_listenfd(argv[1]);
	
	while(1){
        clientlen = sizeof(clientaddr);
	
		/* 接受连接请求 */	
		connfdp = Malloc(sizeof(int));
        *connfdp = Accept(listenfd,(SA *)&clientaddr,&clientlen);
	
		//getnameinfo():将一个套接字地址结构转换成相应的主机和服务名字符串，并复制到host和service缓冲区； P658
		Getnameinfo((SA *)&clientaddr, clientlen, hostname, MAXLINE, port, MAXLINE, 0);	//typedef struct sockaddr SA （p653）
		printf("Accepted connection from (%s, %s)\n", hostname, port);
		
		/* 为每一个请求创建一个线程 */		//书p695 基于线程的并发echo服务器
		Pthread_create(&tid, NULL, thread, connfdp);	//注意第四个参数传的是参数的指针
	}
    return 0;
}

/* Thread routine */
void *thread(void *vargp){
	int connfd = *((int *)vargp);
	Pthread_detach(pthread_self());
	
	//判断请求是否相同
	
	//判断内容是否还在缓存区
	
	/* Pthread_detach(): 分离线程
	 * 线程： 可结合/分离
	 * 可结合：能被其他线程回收和杀死，被回收之前内存不释放
	 * 可分离：不能   内存在终止时自动释放
	 */
	Free(vargp);
	
	/* 处理事务 */
	doit(connfd);

	/* 关闭连接 */
	Close(connfd);
	
	return NULL;
}


/* doit() 处理一个http事务
 * 1. 读和解析行，判断请求类型（GET），若为其他方法发送错误信息并返回主程序，主程序关闭连接并等待下一个连接请求
 * 2. 对URL进行分析，获取服务器的 hostname，post；
 * 3. 修改客户端的HTTP Header， 让proxy充当客户端将信息转发给正确的服务器，接受服务器的返回并转发给请求客户端。
 */
void doit(int connfd){

    int serverfd;/*the end server file descriptor*/

    char buf[MAXLINE],method[MAXLINE],uri[MAXLINE],version[MAXLINE];

	//char server_header[MAXLINE];  
    char hostname[MAXLINE],path[MAXLINE];

    int port;

    rio_t rio,server_rio;/*rio is client's rio,server_rio is endserver's rio*/

/* 读取请求行信息 */
    Rio_readinitb(&rio,connfd);
    Rio_readlineb(&rio,buf,MAXLINE);	//从读缓存区复制一个文本行
	
	//请求行
    sscanf(buf,"%s %s %s",method,uri,version); /*read the client request line*/

	char uri_org[MAXLINE];
	strcpy(uri_org, uri);
	
    if(strcasecmp(method,"GET")){
        printf("Proxy does not implement the method");
        return;
    }

	//缓存区里查找uri，有则发给客户，return
	int got = cache_search(uri_org, connfd);	
	//缓存区里有，返回
	if(got == 1){
		return;
	}
	
	// 若缓存区中没有：	
		
	//获得 hostname，path，port
	parse_uri(uri, hostname, path, &port);

	//连接服务器、发送请求头， 返回fd
	serverfd = connect_server(hostname, port, path);
	
	if(serverfd <0){	//连接失败
		printf(" Connection failed\n");
		return ;
	 }

	//接收服务器消息
	Rio_readinitb(&server_rio, serverfd);
	
	size_t n;
	int content_size = 0;	//判断接受内容大小是否超出
	char cachebuf[MAX_OBJECT_SIZE];
	
	while((n = Rio_readlineb(&server_rio, buf, MAXLINE)) != 0 ){
		
		content_size += n;
		if(content_size < MAX_OBJECT_SIZE)
			strcat(cachebuf, buf);	//内容拼接
		Rio_writen(connfd, buf, n);
	}
	
	Close(serverfd);
	
	//若大小符合，写入cache
	if(content_size <= MAX_OBJECT_SIZE)
		cache_write(cachebuf,uri_org);

	
}



/*Connect to the end server*/
int connect_server(char *hostname,int port,char *path){

  	//连接服务器
	int proxy_clientfd;
	char port_str[50];
	sprintf(port_str,"%d",port);
	proxy_clientfd = Open_clientfd(hostname, port_str);	//代理服务器作为客户机
	//失败:返回
	if(proxy_clientfd < 0)
		return proxy_clientfd;
	
	/* new header */
	char new_header[MAXLINE],request_header[MAXLINE], host_header[MAXLINE];
	
	//bug: sprintf(a,format,b) 从a的起始处开始写
    sprintf(request_header,"GET %s HTTP/1.0\r\n",path);
    sprintf(host_header,"Host: %s\r\n",hostname);
	
    sprintf(new_header,"%s%s%s%s%s%s",
            request_header,
			host_header,
			conn_header,
			proxy_header,
            user_agent_header,      
           "\r\n");
   	   
	Rio_writen(proxy_clientfd, new_header, strlen(new_header));
    return proxy_clientfd;

}


/*parse the uri to get hostname,file path ,port*/	
void parse_uri(char *uri, char *hostname, char *path, int *port){
	
	*port = 80; // 默认端口
	//跳过http://
	char *host_pos = strstr(uri, "//");	
	char *path_pos;
	if(host_pos != NULL)
		host_pos += 2;
	else
		host_pos = uri;
	//“ :<port> ”  and “/index.html"
	char *port_pos = strstr(host_pos, ":");		//bug: 这里的str1是host_pos不是uri，因为http：//有":"
	//strstr(str1, str2)用于判断str2是否是str1的字串；是:返回首次出现的地址；否则：NULL
	
	//有端口
	if(port_pos != NULL){
		*port_pos = '\0';	//把：处置为‘\0'，使下一步sscanf到这一位截止
		sscanf(host_pos, "%s", hostname);
		sscanf(port_pos + 1, "%d%s", port,path); //path包括'\'
	}
	//无端口
	else{
	    path_pos = strstr(host_pos,"/");
		if(path_pos != NULL){
			*path_pos = '\0';
			sscanf(host_pos,"%s",hostname);
			*path_pos = '/';
			sscanf(path_pos,"%s",path);
		}
		else{
			sscanf(host_pos,"%s",hostname);
		}
	}		
}	
	
//LRU 放置，（已写入uri，time）
int cache_place(){
	int oldest_line;
	int oldest_time = INT_MAX;
	int youngest_time = 0;
	int flag = 0;
	int line;
	
	//寻找空缓存块
	for(int i = 0; i < T; i++){
		cache_read_pre(i);
		
		if( cache[i].valid == 0){
			line = i;
			flag = 1;
			
		}
		int time = cache[i].time;
		if(time < oldest_time)	//找最早行
			oldest_line = i;
		if(time > youngest_time)	//找最新时间
			youngest_time = time;
		cache_read_suc(i);
	}
	
	
	//没有空缓存块，LRU
	if(flag == 0)
		line = oldest_line;
	
	P(&cache[line].lock);
	
//	strcpy(cache[line].uri, uri);
	cache[line].time = youngest_time++;
//	cache[line].valid = 1;
	
	V(&cache[line].lock);
	
	return line;
}

//在缓存区里查找uri
int cache_search(char *uri, int connfd){
	//缓存区里有
	for(int i = 0; i < T; i++){
		if(cache[i].valid && !strcmp(cache[i].uri,uri)){
			//把缓存区内容给客户		
			cache_read_pre(i);
			
			Rio_writen(connfd, cache[i].content ,strlen(cache[i].content));
			
			cache_read_suc(i);
			
			return 1;
		}
	}
	return 0;
}

		
void cache_read_pre(int index){

		P(&cache[index].cnt_mutex);
		cache[index].readcnt++;
		if(cache[index].readcnt == 1)	//第一个读者进入，加锁
			P(&cache[index].lock);			
		V(&cache[index].cnt_mutex);
}

//		strcpy(read_content, cache[index].content);
		
void cache_read_suc(int index){	
		
		
		P(&cache[index].cnt_mutex);
		cache[index].readcnt--;
		if(cache[index].readcnt == 0)	//无读者，解锁
			V(&cache[index].lock);
		V(&cache[index].cnt_mutex);
		return;
}

void cache_write(char* content, char *uri){
	
	int index = cache_place();
	
		P(&cache[index].lock);	//写者进入时加锁，读者无法访问
		
	 //? place放在write里：防止找到块|写块中间被插一脚
		
		strcpy(cache[index].content,content);		
	
		strcpy(cache[index].uri, uri);
	//	cache[line].time = youngest_time++;
		cache[index].valid = 1;
	
		V(&cache[index].lock);

	
}

	