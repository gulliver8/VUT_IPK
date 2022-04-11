#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<ctype.h>

#include<sys/socket.h>
#include<sys/types.h>

#include<netinet/in.h>

//function to find out hostname 
int get_hostname(char response[1024]){
	FILE *hostname;
    	hostname = popen("cat /proc/sys/kernel/hostname", "r");
    	if(hostname == NULL){
        	perror("ERROR: hostname");
		exit(EXIT_FAILURE);
	}
    	fgets(response, 64, hostname);
    	pclose(hostname);
    	return 0;
}

//function to find out cpu name
int get_cpuname(char response[1024]){
    	FILE *cpuname;
    	cpuname = popen("cat /proc/cpuinfo | grep 'model name' | head -n 1 | awk -F': ' '{print $2}'", "r");
    	if(cpuname == NULL){
		perror("ERROR: cpuname");
	    	exit(EXIT_FAILURE);
    	}
    	fgets(response, 64, cpuname);
    	pclose(cpuname);
    	return 0;
}

//function to get cpu statistics parsed into unsigned long array
unsigned long* get_cpustat() {
	char buffer[1024];
	char* controlstring;
	static unsigned long cpu[10];
	//open file with information about cpu
	FILE* cpuload;
	cpuload = popen("cat /proc/stat | awk -F 'cpu' '/cpu/{print $2}'", "r");
	if (cpuload == NULL) {
		perror("ERROR: cpuname");
		exit(EXIT_FAILURE);
	}
	//parse first line of file into separate unsigned long values
	int i = 0;
	int num = 0;
	char x = getc(cpuload);
	//skip whitespaces before first number
	while (isblank(x)) {
		x = getc(cpuload);
	}
	//store values into array
	for (char c = x; (c != EOF) && (c != '\n'); c = getc(cpuload)) {
		if (isblank(c)) {
			cpu[num] = strtoul(buffer, &controlstring, 10);
			memset(buffer, 0, strlen(buffer));
			i = 0;
			num++;
		}else {
			buffer[i] = c;
			i++;
		}
	}
	//close file and return array
	pclose(cpuload);
	return cpu;
}

//function to calculate cpu load -using get_scpustat funcition
int get_cpuload() {
	unsigned long* prev_cpu;
	unsigned long* cpu;
	unsigned long prev_idle, idle, prev_non_idle, non_idle, prev_total, total, d_total, d_idle;
	//get first cpu values
	prev_cpu = get_cpustat();
	prev_idle = prev_cpu[3] + prev_cpu[4];
	prev_non_idle = prev_cpu[0] + prev_cpu[1] + prev_cpu[2] + prev_cpu[5] + prev_cpu[6] + prev_cpu[7];
	prev_total = prev_idle + prev_non_idle;
	sleep(3);
	//get cpu values after sleep
	cpu = get_cpustat();
	idle = cpu[3] + cpu[4];
	non_idle = cpu[0] + cpu[1] + cpu[2] + cpu[5] + cpu[6] + cpu[7];
	total = idle + non_idle;
	d_total = 100 * (total - prev_total);
	d_idle = 100 * (idle - prev_idle);
	return ((d_total - d_idle) / (d_total / 100));
}


int main(int argc, char *argv[]){
	//set port
	char *port;
	port = argv[1];
    
	//create string to store server header and response message
    char response_message[1024];
    char http_header[2048] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";

	//create socket
    int server_socket;
    server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(server_socket <= 0){
		perror("ERROR:socket");
		exit(EXIT_FAILURE);
    }
    
	//set socket options
	int reuse = 1;
	setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, (const char *)&reuse, sizeof(int));

	//bind
	struct sockaddr_in server_address;
	server_address.sin_family = AF_INET;//type
	server_address.sin_port = htons(atoi(port));//port
	server_address.sin_addr.s_addr = INADDR_ANY;//address
	
	
	int binding = bind(server_socket, (struct sockaddr *) &server_address, sizeof(server_address));
	if(binding < 0){
		perror("ERROR: bind");
		exit(EXIT_FAILURE);      
	}
    if ((listen(server_socket, 10))<0){
		perror("ERROR: listen");
        exit(EXIT_FAILURE);
    }
    
	//create request headers for comparison
	char *GET_host = "GET /hostname ";
    char *GET_cpuname = "GET /cpu-name ";
    char *GET_cpuload = "GET /load ";

	int cli_socket;
	//buffer to store request from client
    char buffer[1024];
    int request=1;
    while(1){
		//reset header and response message
		response_message[0] = '\n';
	    	http_header[0] = '\n';
		strcpy(http_header, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n");
		printf("First_ %s", http_header);
		//accept request from client
		cli_socket = accept(server_socket,NULL,NULL);
        request = recv(cli_socket, buffer, 1024,0);
		//check if request is valid and send appropriate response
		if(request > 0){
			if(!(strncmp(GET_host, buffer, 14))){
				get_hostname(response_message);
				strcat(http_header, response_message);
                		//printf("Then_%s",http_header);
				send(cli_socket, http_header, sizeof(http_header),0);
			}else if(!(strncmp(GET_cpuname, buffer, 14))){
				get_cpuname(response_message);
				strcat(http_header, response_message);
                	//	printf("%s",http_header);
				send(cli_socket, http_header, sizeof(http_header),0);
			}else if(!(strncmp(GET_cpuload, buffer, 10))){
				sprintf(response_message,"%d%%", get_cpuload());
				strcat(http_header, response_message);
				//printf("%s",response_message);
				send(cli_socket, http_header, sizeof(http_header),0);
			}else{
			    strcpy(http_header,"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain;\r\n\r\nBad Request");
				send(cli_socket, http_header,sizeof(http_header),0);
			}
		}
		close(cli_socket);
	}
	return 1;
}                                                                                                                                                                                   
