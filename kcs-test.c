#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <crypt.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <termios.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "ipmitool.h"
#include "sdr_dump.h"

/*======================================*/
#define dprintf(fmt, args...) fprintf(stderr, "\x1b[33m""[%s:%d:%s()]: " "\x1b[0m" fmt, \
		__FILE__, __LINE__, __func__, ##args)

/* Setion 9.2 KCS Request Message Format */
typedef struct
{
	unsigned char netfn;  //byte 1 : netfn [8:2], lun[1:0]
	unsigned char lun;
	unsigned char cmd;		//byte 2
	unsigned char data[];		//byte 3:N
} ipmi_req_t;

// IPMI response Structure (IPMI/Section 9.3)
typedef struct
{
	unsigned char netfn;
	unsigned char lun;
	unsigned char cmd;
	unsigned char cc;
	unsigned char data[];
} ipmi_res_t;
typedef struct
{
	unsigned int status;
	unsigned int callback;
	unsigned int link_auth;
	unsigned int ipmi_msg;
	unsigned int priv;
} ipmi_access;

	static void
usage(FILE *fp, int argc, char **argv)
{
	fprintf(fp,
			"Usage: %s [options]\n\n"
			"Options:\n"
			" -h | --help                 Print this message\n"
			" -n | --node                  device node [/dev/ast-kcs.2]\n"
			" -a | --addr                 address [CA2]\n"
			" -d | --debug                  debug mode\n"
			"",
			argv[0]);
}

static const char short_options [] = "hdn:a:";

static const struct option
long_options [] = {
	{ "help",       no_argument,            	NULL,   	'h' },
	{ "node",      required_argument,     	NULL,   	'n' },
	{ "addr",	 required_argument,      NULL,   	'a' },
	{ "debug",		no_argument,		NULL,	'd' },
	{ 0, 0, 0, 0 }
};

static unsigned char devid_data[] = {
	0x20, 0x01, 0x00, 0x48, 0x02, 0x9f, 0x22, 0x03, 0x00, 0x11, 0x43,
	0x00, 0x11, 0x00, 0x04
};

static unsigned char guid_data[] = {
	0x00, 0x01, 0x00, 0x48, 0x02, 0x9f, 0xaa, 0x01,
	0x00, 0x23, 0x00, 0x00, 0x11, 0x00, 0x04, 0x99
};

static unsigned char bt_interface_data[] = {
	0x01, 0x40, 0x40, 0x05, 0x03
};

static unsigned char test_data[] = {
	0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0C, 0x0D, 0x0E,
	0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
	0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
	0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
	0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
	0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36
};

#if 0
0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
	0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
	0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E,
	0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0xff
#endif
	static unsigned char user_data[] = {"ketilinux"};

static unsigned char self_test_data[] = {
	0x55, 0x00
};
static struct {
	long offset;        // 해당 문자열 시작위치
	int len;            // 문자열 길이
} table [MAX_USER] = {};

int entry = 0;

static struct {
	char username[MAX_USERNAME];
	char passwd[MAX_PASSWD];
	char id[MAX_ID];
	int ENABLE;
	int CALLIN;
	int LINK;
	int IPMI;
	int PRIV;
	//char comment[MAX_COMMENT];
} passwd_table[MAX_USER] = {};

int pass_fd;

int debug = 0;

int make_passwd(char *inData)
{
	unsigned long seed[2];
	char salt[] = "$1$........";
	const char *const seedchars =
		"./0123456789ABCDEFGHIJKLMNOPQRST"
		"UVWXYZabcdefghijklmnopqrstuvwxyz";
	char *password;
	int i;

	/* Generate a (not very) random seed.
	   You should do it better than this... */
	seed[0] = time(NULL);
	seed[1] = getpid() ^ (seed[0] >> 14 & 0x30000);

	/* Turn it into printable characters from ‘seedchars’. */
	for (i = 0; i < 8; i++)
		salt[3+i] = seedchars[(seed[i/5] >> (i%5)*6) & 0x3f];

	password = crypt(inData, salt);

	/* Print the results. */
	memset(inData, '\0', MAX_PASSWD);
	strncpy(inData, password, strlen(password));
	return 0;
}

char* GetGatewayForInterface(const char* interface, ipmi_res_t * response) 
{
	char* gateway = NULL;
	int i = 0;
	FILE* fp = popen("netstat -rn", "r");
	char line[256]={0x0};
	char * result;
	int GateAddr[4] = {0};
	while(fgets(line, sizeof(line), fp) != NULL)
	{
		/*
		 * Get destination.
		 */
		char* destination;
		destination = strndup(line, 15);
		/*
		 * Extract iface to compare with the requested one
		 * todo: fix for iface names longer than eth0, eth1 etc
		 */
		char* iface;
		iface = strndup(line + 73, 4);

		// Find line with the gateway
		if(strcmp("0.0.0.0        ", destination) == 0 && strcmp(iface, interface) == 0) {
			// Extract gateway
			gateway = strndup(line + 16, 15);
		}
		free(destination);
		free(iface);
	}
	//  printf("GATE : %s\n", gateway);
	result = strtok(gateway, ".");
	while(result != NULL){
		response->data[i] = atoi(result);
		//    printf("RESULT : %s\n", result);
		result = strtok(NULL, ".");
		i++;
	}
	printf("\n");
	pclose(fp);
}

char * s_getMacAddr(char * input)
{
	const char* ifname = "eth0";

	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if(s < 0) perror("socket fail"); /* TODO 에러처리 */

	struct ifreq ifr;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
		perror("ioctl fail");   /* TODO 에러처리 */

	const unsigned char* mac = ifr.ifr_hwaddr.sa_data;
	//    printf("MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n",
	//           mac[0],
	//           mac[1],
	//           mac[2],
	//           mac[3],
	//           mac[4],
	//           mac[5]);

	int i = 0;
	memcpy(input, mac, sizeof(mac)+2);
	//    printf("MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n",
	//           input[0],
	//          input[1],
	//           input[2],
	//          input[3],
	//           input[4],
	//           input[5]);

	close(s);
}

int s_getNetworkInfo(const char * ifr, unsigned char * out, int SIOParams)
{
	int sockfd;
	struct ifreq ifrq;
	struct sockaddr_in * sin;
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	strcpy(ifrq.ifr_name, ifr);
	if (ioctl(sockfd, SIOParams, &ifrq) < 0) {
		char * ErrorMessage;
		char * Final;
		char * Error_1 = "ioctl() ";
		char * Error_2 = " ERROR";
		switch(SIOParams){
			case SIOCGIFADDR:
				ErrorMessage = "SIOCGIFADDR";
				break;
			case SIOCGIFNETMASK:
				ErrorMessage = "SIOCGIFNETMASK";
				break;
			case SIOCGIFHWADDR:
				ErrorMessage  = "SIOCGIFFWADDR";
				break;
			case SIOCGIFBRDADDR:
				ErrorMessage = "SIOCGIFBRDADDR";
				break;
			case SIOCGIFDSTADDR:
				ErrorMessage  = "SIOCGIFDSTADDR";
				break;
			case SIOCGIFCONF:
				ErrorMessage = "SIOCGIFCONF";
				break;
		}
		strcat(Final, Error_1);
		strcat(Final, ErrorMessage);
		strcat(Final, Error_2);
		perror(Final);
		return -1;
	}
	sin = (struct sockaddr_in *)&ifrq.ifr_addr;
	memcpy (out, (void*)&sin->sin_addr, sizeof(sin->sin_addr));
	close(sockfd);
	return 4;
}

char* get_table_data(int fd, int req, int option, char *indata, int *access)
{
	passwd_update(fd);

	//printf("get table req : %d\n", req);
	/* if(!(req >= 0 && req < entry)) {
	   printf("Wrong number!\n");
	   return NULL;
	   }*/
	if(!(option >= 0 && option <= 3)) {
		printf("Wrong option!\n");
		return NULL;
	}

	switch(option) {
		case GET_NAME:
			//            printf("passwd_table name : %s\n",passwd_table[req].username);
			strcpy(indata, passwd_table[req].username);
			//            printf("indata name = %s\n", indata);
			return passwd_table[req].username;
		case GET_PASSWD:
			return passwd_table[req].passwd;
		case GET_ID:
			return passwd_table[req].id;
		case GET_ACCESS:
			//            printf("GET_USER+ACCESS!!!!\n");
			//            printf("passwd_table access : %d\n",passwd_table[req].ENABLE);
			access[0] = passwd_table[req].ENABLE;
			//	    printf("passwd_table access : %d\n",passwd_table[req].ENABLE);
			access[1] = passwd_table[req].CALLIN;
			access[2] = passwd_table[req].LINK;
			access[3] = passwd_table[req].IPMI;
			access[4] = passwd_table[req].PRIV;
			//return passwd_table[req].comment;
	}
}

int open_shadow()
{
	int fd;

	char *file_name  = "/etc/keti_shadow";
	if (access(file_name, F_OK) == 0) {
		/* Check there is already shadow file */
		if (( fd = open(file_name, O_RDWR)) < 0)
		{
			perror("open");
			return -1;
		}
		table_update(fd);
		/* start write */
	}
	else {
		/* Make new shadow file */
		if ((fd = open(file_name, O_RDWR | O_CREAT , 0644)) < 0)
		{
			perror("open");
			return -1;
		}
		/* start write */
		//write(fd, temp, strlen( temp));
	}
	return fd;
}

int passwd_update(int fd)
{
	int i, j;
	char buf[BUFSIZE];
	char *ptr, *buf_ptr;

	table_update(fd);

	for(i = 0; i < entry; i++) {
		lseek(fd, table[i].offset, 0);
		if(read(fd, buf, table[i].len) <= 0)
			continue;

		buf[table[i].len-1] = '\0';
		buf_ptr = strdup(buf);
		//printf("passwd update buf ptr : %s\n", buf_ptr);
		ptr = strtok(buf_ptr, ":");
		strcpy(passwd_table[i].username, ptr);

		ptr = strtok( NULL, ":");
		strcpy(passwd_table[i].passwd, ptr);

		ptr = strtok( NULL, ":");
		strcpy(passwd_table[i].id, ptr);

		ptr = strtok( NULL, ":");
		passwd_table[i].ENABLE = atoi(ptr);

		ptr = strtok( NULL, ":");
		passwd_table[i].CALLIN = atoi(ptr);

		ptr = strtok( NULL, ":");
		passwd_table[i].LINK = atoi(ptr);

		ptr = strtok( NULL, ":");
		passwd_table[i].IPMI = atoi(ptr);

		ptr = strtok( NULL, ":");
		passwd_table[i].PRIV = atoi(ptr);

	}
	return 0;
}

int table_update(int fd) {
	int n, i, len;
	long offset;
	char buf[BUFSIZE];
	offset = 0; entry = 0; len = 0;
	lseek(fd, 0, SEEK_SET);
	while((n = read(fd, buf, BUFSIZE)) > 0) {
		for(i = 0 ; i < n ; i++) {
			len++; offset++;
			if(len > MAX_PASSWD && buf[i] == '\n') {
				table[entry].len = len;
				len = 0;
				table[++entry].offset = offset;
			}
		}
	}
}

int ipmi_app_handler(ipmi_req_t *req_buf, unsigned char *req_len, ipmi_res_t* res_buf, unsigned char *res_len)
{
	int id = 0;
	int ret = 0;
	int user_id = 0;
	int access = 0;
	char *data;
	char req_data[2] = {'1','2'};
	char *usermod = (char *)malloc(sizeof(char) * 100);

	switch(req_buf->cmd) {
		//for performace test
		case 0xF:
			if(debug) printf("performance test\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = 0xf;
			res_buf->cc = 0;
			*res_len += sizeof(test_data);
			memcpy(&res_buf->data, test_data, sizeof(test_data));
			break;
		case IPMI_GET_DEVICE_ID_CMD:
			if(debug) printf("IPMI_GET_DEVICE_ID_CMD\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = IPMI_GET_DEVICE_ID_CMD;
			res_buf->cc = 0;
			*res_len += sizeof(devid_data);
			memcpy(&res_buf->data, devid_data, sizeof(devid_data));
			break;
		case IPMI_GET_SELF_TEST_RESULTS_CMD:
			if(debug) printf("IPMI_GET_SELF_TEST_RESULTS_CMD\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = IPMI_GET_SELF_TEST_RESULTS_CMD;
			res_buf->cc = 0;
			*res_len += sizeof(self_test_data);
			memcpy(&res_buf->data, self_test_data, sizeof(self_test_data));
			break;
		case IPMI_GET_SYSTEM_GUID_CMD:
			if(debug) printf("IPMI_GET_SYSTEM_GUID_CMD\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = IPMI_GET_SYSTEM_GUID_CMD;
			res_buf->cc = 0;
			*res_len += sizeof(guid_data)-1;
			memcpy(&res_buf->data, guid_data, sizeof(guid_data)-1);
			break;
		case IPMI_GET_BMC_GLOBAL_ENABLES_CMD:
			if(debug) printf("IPMI_GET_BMC_GLOBAL_ENABLES_CMD\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = IPMI_GET_BMC_GLOBAL_ENABLES_CMD;
			res_buf->cc = 0;
			*res_len += 1;
			res_buf->data[0] = 0x00;
			break;
		case IPMI_CLEAR_MSG_FLAGS_CMD:
			if(debug) printf("IPMI_CLEAR_MSG_FLAGS_CMD\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = IPMI_CLEAR_MSG_FLAGS_CMD;
			res_buf->cc = 0;
			*res_len += 1;
			res_buf->data[0] = 0x00;
			break;

		case IPMI_GET_USER_NAME_CMD:
			if(debug) printf("IPMI_GET_USER_NAME_CMD\n");
			passwd_update(pass_fd);
			id = req_buf->data[0];
			if(entry <= 10){
				get_table_data(pass_fd, id-1, GET_NAME, res_buf->data, NULL);
			}
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = IPMI_GET_USER_NAME_CMD;
			res_buf->cc = 0;
			*res_len  += strlen(res_buf->data);
			break;

		case IPMI_GET_USER_ACCESS_CMD:
			if(debug) printf("IPMI_GET_USER_ACCESS_CMD\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = IPMI_GET_USER_ACCESS_CMD;
			res_buf->cc = 0;

			int maxid = 10;
			int loop = 0;
			int access[5] = {0};
			int new_access[5] = {0};
			int re_access = 0;
			int accessid = 0;

			accessid = req_buf->data[1];
			get_table_data(pass_fd, accessid-1, GET_ACCESS, res_buf->data, access);

			new_access[0] = access[1]<<6;
			new_access[1] = access[2]<<5;
			new_access[2] = access[3]<<4;
			new_access[3] = access[4];

			re_access = new_access[0] | new_access[1] | new_access[2] | new_access[3];
			res_buf->data[0] = maxid;
			res_buf->data[1] = access[0];
			res_buf->data[2] = entry;
			res_buf->data[3] = re_access;
			*res_len += 4;
			break;

		case IPMI_SET_USER_NAME_CMD:
			if(debug) printf("IPMI_SET_USER_NAME_CMD\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = IPMI_SET_USER_NAME_CMD;
			res_buf->cc = 0;
			/* usermod USERNAME -n DATA */

			char *new_username = (char *)malloc(sizeof(char) * 17);
			uint8_t req_id;
			uint8_t loopp=0;
			for(loopp = 1 ; loopp < MAX_USERNAME; loopp ++){
				new_username[loopp-1] = req_buf->data[loopp];
			}
			req_id = req_buf->data[0];
			printf("user id is : %d\n", req_id);
			printf("user name is : %s\n", new_username);
			passwd_update(pass_fd);
			sprintf(usermod, "useradd -n %s -i %d -h kcs", new_username, req_id);
			//		printf("cmd : %s\n", usermod);
			system(usermod);
			break;

		case IPMI_SET_USER_ACCESS_CMD:
			if(debug) printf("IPMI_SET_USER_ACCESS_CMD\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = IPMI_SET_USER_ACCESS_CMD;
			res_buf->cc = 0;
			/* usermod USERNAME -c DATA */
			if(debug) /* check requested access data */
				dprintf("ACCES DATA : status : %d, callin callback : %d, link auth : %d, ipmi messaging : %d. priv : %d\n",
						req_buf->data[2], (req_buf->data[0] & 0x40)>>6, (req_buf->data[0] & 0x20)>>5, (req_buf->data[0] & 0x10)>>4, req_buf->data[0]&0x0F);
			char *access_command = (char *)malloc(sizeof(char) * 100);
			char *temp_username = (char *)malloc(sizeof(char) * MAX_USERNAME);
			int access_id = 0;
			access_id = req_buf->data[1];
			passwd_update(pass_fd);
			get_table_data(pass_fd, access_id-1, GET_NAME, temp_username, NULL);
			//	    dprintf("temp user name : %s\n", temp_username);		
			sprintf(access_command, "usermod %s -E %d", temp_username, req_buf->data[2]);
			system(access_command);
			memset(access_command, 0, sizeof(access_command));

			sprintf(access_command, "usermod %s -C %d", temp_username, ((req_buf->data[0])&0x40)>>6);
			system(access_command);
			memset(access_command, 0, sizeof(access_command));

			sprintf(access_command, "usermod %s -L %d", temp_username, ((req_buf->data[0])&0x20)>>5);
			system(access_command);
			memset(access_command, 0, sizeof(access_command));

			sprintf(access_command, "usermod %s -I %d", temp_username, ((req_buf->data[0])&0x10)>>4);
			system(access_command);
			memset(access_command, 0, sizeof(access_command)); 

			sprintf(access_command, "usermod %s -P %d", temp_username, req_buf->data[0]&0x0f);
			system(access_command);
			memset(access_command, 0, sizeof(access_command));
			break;

		case IPMI_SET_USER_PASSWORD_CMD:
			if(debug) printf("IPMI_SET_USER_PASSWORD_CMD\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = IPMI_SET_USER_PASSWORD_CMD;
			res_buf->cc = 0; /* 80h : wrong passwd / 81h : wrong size */
			/* usermod USERNAME -p old_passwd new_passwd */
			/* TODO : but ipmitool only give us new_passwd - need change format */
			char *passwd_command = (char *)malloc(sizeof(char) * 100);
			char *tempp_username = (char *)malloc(sizeof(char) * MAX_USERNAME);
			char input_password[MAX_PASSWD];
			//char *input_password = (char *)malloc(sizeof(char) * MAX_PASSWD);/
			uint8_t id = 0;
			int i = 0;
			id = req_buf->data[0] & 0x0F;
			//	    strcpy(input_password, req_buf->data);
			for(i = 2 ; i < 20 ; i++){
				input_password[i-2] = req_buf->data[i];
			}

			make_passwd(input_password);
			passwd_update(pass_fd);
			get_table_data(pass_fd, id-1, GET_NAME, tempp_username, NULL);

			//	    printf("current password : %s", input_password);
			sprintf(passwd_command, "usermod %s -p %s", tempp_username, input_password);
			system(passwd_command);
			break;

		case 0x52:
			/* ipmi_master_write_read */
			if(debug) printf("0x52\n");
			break;
		case IPMI_SET_USER_PAYLOAD_ACCESS:
			/* ipmi_sol_payload_access */
			if(debug) printf("IPMI_SET_USER_PAYLOAD_ACCESS\n");
			break;
		case IPMI_DEACTIVATE_PAYLOAD:
			/* ipmi_sol_deactivate */
			if(debug) printf("IPMI_DEACTIVATE_PAYLOAD\n");
			break;
		case IPMI_ACTIVATE_PAYLOAD:
			/* ipmi_sol_activate */
			if(debug) printf("IPMI_ACTIVATE_PAYLOAD\n");
			break;

			/* ========================= ipmi_sdr.c ==================== */
			/* TODO : same with IPMI_GET_DEVICE_ID_CMD ???? 
			   case BMC_GET_DEVICE_ID:
			   if(debug) printf("BMC_GET_DEVICE_ID\n");
			   if(debug) printf("ipmi_sdr_start\n");
			// devid = (struct ipm_devid_rsp *) rsp->data;
			break;
			 */
			/*
case :
if(debug) printf("\n");
break;
			 */
		default:
			printf("app unsupport cmd %x \n", req_buf->cmd);
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = req_buf->cmd;
			res_buf->cc = 0xC1;
			break;
	}
	return ret;
}

/* ipmi_lanp.c */
int ipmi_transport_handler(ipmi_req_t *req_buf, unsigned char *req_len, ipmi_res_t* res_buf, unsigned char *res_len)
{
	int ret = 0;
	int i = 0;
	int switchCMD = 0;
	char IPAddr[4] = {0,};
	char GatewayAddr[4] = {0,};
	char SubnetAddr[4] = {0,};
	char MacAddr[6] = {0,}; 
	int IntIP[4] = {0};
	int SubnetIP[4] = {0};
	if(req_buf->cmd == IPMI_LAN_GET_CONFIG_CMD){
		if(debug)
			printf("LAN GET CONFIG\n");
		res_buf->netfn = req_buf->netfn;
		res_buf->lun = req_buf->lun;
		res_buf->cmd = IPMI_LAN_GET_CONFIG_CMD;
		res_buf->cc = 0x00;  /* 0x80 / 0xc9 / 0xcc */

		//printf("%d\n", req_buf->data[1]);
		switch(req_buf->data[1]) {
			case IPMI_LANP_SET_IN_PROGRESS:
				if(debug)
					printf("LANP SET IN PROGRESS");
				res_buf->data[0] = 0;
				*res_len += 1;
				break;

			case IPMI_LANP_AUTH_TYPE:
				if(debug)
					printf("LANP AUTH TYPE\n");
				res_buf->data[0] = 4; // MD5 AUTH TYPE
				*res_len += 1;
				break;

			case IPMI_LANP_AUTH_TYPE_ENABLE:
				printf("LAN AUTH TYPE ENABLE\n");
				break;

			case IPMI_LANP_IP_ADDR_SRC:
				printf("LAN IP ADDR SRC\n");
				break;

			case IPMI_LANP_IP_ADDR:
				if(debug)
					printf("IPMI_LANP_IP_ADDR\n"); 
				if(s_getNetworkInfo("eth0", IPAddr, SIOCGIFADDR)>0){
					for(i=0;i<4;i++){
						res_buf->data[i] = (int)IPAddr[i];
					}
					*res_len += 4;
				}
				break;

			case IPMI_LANP_SUBNET_MASK:
				if(debug)
					printf("IPMI LANP SUBNET MASK\n");
				if(s_getNetworkInfo("eth0", SubnetAddr, SIOCGIFNETMASK)>0){
					//printf("Subnet : %d.%d.%d.%d\n",(int)SubnetAddr[0],(int)SubnetAddr[1],(int)SubnetAddr[2],(int)SubnetAddr[3]);
					for(i = 0 ; i < 4 ; i++){
						res_buf->data[i] = (int)SubnetAddr[i];
					}
					*res_len += 4;
				}
				break;

			case IPMI_LANP_MAC_ADDR:
				if(debug)
					printf("MAC ADDR \n");
				//if(s_getNetworkInfo("eth0", MacAddr, SIOCGIFHWADDR)>0)
				s_getMacAddr(MacAddr);
				for(i = 0 ; i < 6 ; i++){
					res_buf->data[i] = MacAddr[i];
				}
				*res_len += 8;
				break;

			case IPMI_LANP_SNMP_STRING:
				break;

			case IPMI_LANP_IP_HEADER:
				break;

			case IPMI_LANP_BMC_ARP:
				break;

			case IPMI_LANP_GRAT_ARP:
				break;

			case IPMI_LANP_DEF_GATEWAY_IP:
				if(debug)
					printf("IPMI LANP DEF GATEWAY IP\n");
				GetGatewayForInterface("eth0", res_buf);
				//printf("response data : %d %d %d %d", res_buf->data[0], res_buf->data[1], res_buf->data[2], res_buf->data[3]);
				*res_len += 4;

				break;

			case IPMI_LANP_DEF_GATEWAY_MAC:
				break;

			case IPMI_LANP_BAK_GATEWAY_IP:
				break;

			case IPMI_LANP_BAK_GATEWAY_MAC:
				break;

			case IPMI_LANP_VLAN_ID:
				break;

			case IPMI_LANP_VLAN_PRIORITY:
				break;

			case IPMI_LANP_RMCP_CIPHER_SUPPORT:
				break;

			case IPMI_LANP_RMCP_CIPHERS:
				break;

			case IPMI_LANP_RMCP_PRIV_LEVELS:
				break;

			case IPMI_LANP_BAD_PASS_THRESH:
				break;

			default:
				printf("lan get  unsupport cmd %x \n", req_buf->data[1]);
				res_buf->netfn = req_buf->netfn;
				res_buf->lun = req_buf->lun;
				res_buf->cmd = req_buf->cmd;
				res_buf->data[1] = req_buf->data[1];
				res_buf->cc = 0xC1;
				break;
		}
	}

	else if(req_buf->cmd == IPMI_LAN_SET_CONFIG_CMD){
		printf("LAN SET CONFIG\n");
	}

	else if(req_buf->cmd == IPMI_LAN_GET_STAT_CMD){
		printf("LAN GET STAT\n");
	}
	else if(req_buf->cmd == IPMI_GET_USER_PAYLOAD_ACCESS){
		if(debug) printf("IPMI_GET_USER_PAYLOAD_ACCESS\n");
	}
	else if(req_buf->cmd == IPMI_SET_SOL_CONFIG_PARAMETERS){
		/* ipmi_sol_set_param */
		if(debug) printf("IPMI_SET_SOL_CONFIG_PARAMETERS\n");
	}
	else{
		printf("transport unsupport cmd %x \n", req_buf->cmd);
		res_buf->netfn = req_buf->netfn;
		res_buf->lun = req_buf->lun;
		res_buf->cmd = req_buf->cmd;
		res_buf->cc = 0xC1;
	}
	return ret;
}


int ipmi_chassis_handler(ipmi_req_t *req_buf, unsigned char *req_len, ipmi_res_t* res_buf, unsigned char *res_len)
{
	int ret = 0;
	char *data;

	switch(req_buf->cmd) {
		case IPMI_CHASSIS_POWER_STATUS:
			if(debug) printf("IPMI_CHASSIS_POWER_STATUS\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = IPMI_CHASSIS_POWER_STATUS;
			res_buf->cc = 0;
			res_buf->data[0] = 1;  // power is on
			*res_len += 1;//sizeof(res_buf->data[0]);
			break;

		case IPMI_CHASSIS_POWER_CTL:
			if(debug) printf("IPMI_CHASSIS_POWER_CTL\n");
			//please insert code that control chassis power
			switch(req_buf->data[0])
			{
				case IPMI_CHASSIS_CTL_POWER_UP:
					res_buf->data[0] = 0x0;
					break;
				case IPMI_CHASSIS_CTL_POWER_DOWN:
					res_buf->data[0] = 0x1;
					break;
				case IPMI_CHASSIS_CTL_POWER_CYCLE:
					break;
				case IPMI_CHASSIS_CTL_HARD_RESET:
					break;
				case IPMI_CHASSIS_CTL_PULSE_DIAG:
					break;
				case IPMI_CHASSIS_CTL_ACPI_SOFT:
					break;
			}
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = IPMI_CHASSIS_POWER_CTL;
			res_buf->cc = 0;
			*res_len += 1;
			break;

			/*
			   case 0x1:
			   dprintf("chassis power status / chassis status\n");
			   break;
			   case 0x2:
			   dprintf("chassis power control\n");
			   switch(req_buf->data) {
			   case IPMI_CHASSIS_CTL_POWER_UP:
			   break;
			   case IPMI_CHASSIS_CTL_POWER_DOWN:
			   break;
			   case IPMI_CHASSIS_CTL_POWER_CYCLE:
			   break;
			   case IPMI_CHASSIS_CTL_HARD_RESET:
			   break;
			   case IPMI_CHASSIS_CTL_PULSE_DIAG:
			   break;
			   case IPMI_CHASSIS_CTL_ACPI_SOFT:
			   break;
			   }
			   break;
			 */
		case 0x4:
			dprintf("chassis identify / chassis selftest\n");
			/*only when identify : identigy_data : interval / force_on : 1/0*/
			/*
			   switch(req_buf->data) {
			   }
			 */
			break;
		case 0xf:
			dprintf("chassis poh\n");
			break;
		case 0x7:
			dprintf("chassis restart cause\n");
			break;
		case 0x8:
			dprintf("chassis set bootparam\n");
			/* ipmi_chassis_set_bootvalid : flag[5]  need to check data_len */
			/*
			   switch(req_buf->data) {
			   }*/
			break;
		case 0x9:
			dprintf("chassis get bootparam / chassis get bootvalid\n");
			switch(req_buf->data[0]) {
				/* data_len : 3 / data[0] : param_id & 0x7f / data[1],[2] : 0 */
				case 0: break;
				case 1: break;
				case 2: break;
				case 3: break;
				case 4: break;
				case 5: break;
				case 6: break;
				case 7: break;
				default : break;
			}
			/* get bootvalid return : data[2] */
			break;
		case 0x6:
			dprintf("chassis power policy\n");
			switch(req_buf->data[0]) {
				case IPMI_CHASSIS_POLICY_NO_CHANGE:
					break;
				case IPMI_CHASSIS_POLICY_ALWAYS_ON:
					break;
				case IPMI_CHASSIS_POLICY_PREVIOUS:
					break;
				case IPMI_CHASSIS_POLICY_ALWAYS_OFF:
					break;
			}
			break;

		default:
			printf("chassis unsupport cmd %x \n", req_buf->cmd);
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = req_buf->cmd;
			res_buf->cc = 0xC1;
			break;
	}
	return ret;
}


int ipmi_dcmi_handler(ipmi_req_t *req_buf, unsigned char *req_len, ipmi_res_t* res_buf, unsigned char *res_len)
{
	int ret = 0;
	char *data;

	switch(req_buf->cmd) {
		case IPMI_DCMI_COMPAT:
			/* ipmi_dcmi_getcapabilities */
			if(debug) printf("IPMI_DCMI_COMPAT\n");
			break;

		case IPMI_DCMI_GETASSET:
			/* ipmi_dcmi_getassettag */
			if(debug) printf("IPMI_DCMI_GETASSET\n");
			break;

		case IPMI_DCMI_SETASSET:
			/* ipmi_dcmi_setassettag */
			if(debug) printf("IPMI_DCMI_SETASSET\n");

			break;
		case IPMI_DCMI_GETMNGCTRLIDS:
			/* ipmi_dcmi_getmngctrlids */
			if(debug) printf("IPMI_DCMI_GETMNGCTRLIDS\n");
			break;
		case IPMI_DCMI_SETMNGCTRLIDS:
			/* ipmi_dcmi_setmngctrlids */
			if(debug) printf("IPMI_DCMI_SETMNGCTRLIDS\n");
			break;
		case IPMI_DCMI_GETSNSR:
			/* ipmi_dcmi_discvry_snsr */
			if(debug) printf("IPMI_DCMI_GETSNSR\n");
			break;
		case IPMI_DCMI_GETRED:
			/* ipmi_dcmi_pwr_rd */
			if(debug) printf("IPMI_DCMI_GETRED\n");
			break;
		case IPMI_DCMI_GETTERMALLIMIT:
			/* ipmi_dcmi_getthermalpolicy */
			if(debug) printf("IPMI_DCMI_GETTERMALLIMIT\n");
			break;
		case IPMI_DCMI_SETTERMALLIMIT:
			/* ipmi_dcmi_setthermalpolicy */
			if(debug) printf("IPMI_DCMI_SETTERMALLIMIT\n");
			break;

		case IPMI_DCMI_GETTEMPRED:
			/* ipmi_dcmi_get_temp_readings */
			if(debug) printf("IPMI_DCMI_GETTEMPRED\n");
			break;
		case IPMI_DCMI_GETCONFPARAM:
			/* ipmi_dcmi_getconfparam */
			if(debug) printf("IPMI_DCMI_GETCONFPARAM\n");
			break;
		case IPMI_DCMI_SETCONFPARAM:
			/* ipmi_dcmi_setconfparam */
			if(debug) printf("IPMI_DCMI_SETCONFPARAM\n");
			break;
		case IPMI_DCMI_GETLMT:
			/* ipmi_dcmi_pwr_glimit */
			if(debug) printf("IPMI_DCMI_GETLMT\n");
			break;
		case IPMI_DCMI_SETLMT:
			/* ipmi_dcmi_pwr_slimit */
			/* ipmi_dcmi_set_limit */
			if(debug) printf("IPMI_DCMI_SETLMT\n");
			break;
		case IPMI_DCMI_PWRACT:
			/* ipmi_dcmi_pwr_actdeact */
			if(debug) printf("IPMI_DCMI_PWRACT\n");
			break;

		default:
			printf("chassis unsupport cmd %x \n", req_buf->cmd);
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = req_buf->cmd;
			res_buf->cc = 0xC1;
			break;
	}
	return ret;
}

int ipmi_oem_handler(ipmi_req_t *req_buf, unsigned char *req_len, ipmi_res_t* res_buf, unsigned char *res_len)
{
	int ret = 0;
	char *data;

	switch(req_buf->cmd) {
		case IPMI_NM_GET_VERSION:
			/* _ipmi_nm_discover */
			if(debug) printf("IPMI_NM_GET_VERSION\n");
			break;
		case IPMI_NM_GET_CAP:
			/* _ipmi_nm_getcapabilities */
			if(debug) printf("IPMI_NM_GET_CAP\n");
			break;
		case IPMI_NM_GET_POLICY:
			/* _ipmi_nm_get_policy */
			if(debug) printf("IPMI_NM_GET_POLICY\n");
			break;
		case IPMI_NM_SET_POLICY:
			/* _ipmi_nm_set_policy */
			if(debug) printf("IPMI_NM_SET_POLICY\n");
			break;
		case IPMI_NM_LIMITING:
			/* _ipmi_nm_policy_limiting */
			if(debug) printf("IPMI_NM_LIMITING\n");
			break;
		case IPMI_NM_POLICY_CTL:
			/* _ipmi_nm_control */
			if(debug) printf("IPMI_NM_POLICY_CTL\n");
			break;
		case IPMI_NM_GET_STATS:
			/* _ipmi_nm_statistics */
			if(debug) printf("IPMI_NM_GET_STATS\n");
			break;
		case IPMI_NM_RESET_STATS:
			/* _ipmi_nm_reset_stats */
			if(debug) printf("IPMI_NM_RESET_STATS\n");
			break;

		case IPMI_NM_SET_POWER:
			/* _nm_set_range */
			if(debug) printf("IPMI_NM_SET_POWER\n");
			break;

		case IPMI_NM_GET_ALERT_DS:
			/* _ipmi_nm_get_alert */
			if(debug) printf("IPMI_NM_GET_ALERT_DS\n");
			break;

		case IPMI_NM_SET_ALERT_DS:
			/* _ipmi_nm_set_alert */
			if(debug) printf("IPMI_NM_SET_ALERT_DS\n");
			break;

		case IPMI_NM_GET_ALERT_TH:
			/* _ipmi_nm_get_thresh */
			if(debug) printf("IPMI_NM_GET_ALERT_TH\n");
			break;

		case IPMI_NM_SET_ALERT_TH:
			/* _ipmi_nm_set_thresh */
			if(debug) printf("IPMI_NM_SET_ALERT_TH\n");
			break;

		case IPMI_NM_GET_SUSPEND:
			/* _ipmi_nm_get_suspend */
			if(debug) printf("IPMI_NM_GET_SUSPEND\n");
			break;

		case IPMI_NM_SET_SUSPEND:
			/* _ipmi_nm_set_suspend */
			if(debug) printf("IPMI_NM_SET_SUSPEND\n");
			break;

		default:
			printf("chassis unsupport cmd %x \n", req_buf->cmd);
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = req_buf->cmd;
			res_buf->cc = 0xC1;
			break;
	}
	return ret;
}

int ipmi_storage_handler(ipmi_req_t *req_buf, unsigned char *req_len, ipmi_res_t* res_buf, unsigned char *res_len)
{
	int ret = 0;
	char *data;

	switch(req_buf->cmd) {
		case GET_SDR_REPO_INFO:
			if(debug) printf("GET_SDR_REPO_INFO\n");
			if(debug) printf("ipmi_sdr_start\n");
			/* if (itr->use_built_in == 0) */
			/* get sdr repository info */
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = GET_SDR_REPO_INFO;
			res_buf->cc = 0;
			memcpy(&res_buf->data, &sdr_dump[sdr_dump_idx], sizeof(uint8_t) * 15);
			sdr_dump_idx += sizeof(uint8_t) * 15;
			dprintf("%s : %dbyte\n", res_buf->data, sdr_dump_idx);
			*res_len += sizeof(uint8_t) * 15;
			break;

			/* TODO : same with GET_SDR_REPO_INFO ???
			   case GET_DEVICE_SDR_INFO:
			   if(debug) printf("GET_DEVICE_SDR_INFO\n");
			   if(debug) printf("ipmi_sdr_start\n");
			// get device sdr info 
			break;
			 */
		case GET_SDR_RESERVE_REPO:
			if(debug) printf("GET_SDR_RESERVE_REPO\n");
			if(debug) printf("ipmi_sdr_get_reservation\n");
			/* obtain reservation ID */
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = GET_SDR_RESERVE_REPO;
			res_buf->cc = 0;
			memcpy(&res_buf->data, &sdr_dump[sdr_dump_idx], sizeof(uint16_t));
			sdr_dump_idx += sizeof(uint16_t);
			dprintf("%s : %dbyte\n", res_buf->data, sdr_dump_idx);
			*res_len += sizeof(uint16_t);
			break;

		case GET_SDR:
			if(debug) printf("GET_SDR\n");
			if(debug) printf("ipmi_sdr_get_header\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = GET_SDR;
			res_buf->cc = 0;
			/* p.456 Table 35-3 */
			break;

			/* TODO : same with GET_SDR_REPO_INFO ???
			   case IPMI_GET_SDR_REPOSITORY_INFO:
			   if(debug) printf("IPMI_GET_SDR_REPOSITORY_INFO\n");
			   if(debug) printf("ipmi_sdr_get_info\n");
			// ipmi_sdr_print_info 
			break;
			 */
		case 0x27:
			if(debug) printf("0x27\n");
			if(debug) printf("ipmi_sdr_repo_clear\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = 0x27;
			res_buf->cc = 0;
			break;

		case ADD_PARTIAL_SDR:
			if(debug) printf("ADD_PARTIAL_SDR\n");
			if(debug) printf("ipmi_sdr_add_record\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = ADD_PARTIAL_SDR;
			res_buf->cc = 0;
			break;

			/* -------------- SEL ------------------*/
		case IPMI_CMD_GET_SEL_INFO:
			if(debug) printf("IPMI_CMD_GET_SEL_INFO\n");
			if(debug) printf("ipmi_sel_get_info\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = IPMI_CMD_GET_SEL_INFO;
			res_buf->cc = 0;
			break;

			/* -------------- FRU ------------------*/
		case GET_FRU_INFO:
			if(debug) printf("GET_FRU_INFO\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = GET_FRU_INFO;
			res_buf->cc = 0;
			break;
		case GET_FRU_DATA:
			if(debug) printf("GET_FRU_DATA\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = GET_FRU_DATA;
			res_buf->cc = 0;
			break;
		case SET_FRU_DATA:
			if(debug) printf("SET_FRU_DATA\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = SET_FRU_DATA;
			res_buf->cc = 0;
			break;

		default:
			printf("storage unsupport cmd %x \n", req_buf->cmd);
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = req_buf->cmd;
			res_buf->cc = 0xC1;
			break;
	}
	return ret;
}

int ipmi_sensor_event_handler(ipmi_req_t *req_buf, unsigned char *req_len, ipmi_res_t* res_buf, unsigned char *res_len)
{
	int ret = 0;
	char *data;

	switch(req_buf->cmd) {
		case GET_SDR_RESERVE_REPO:
			if(debug) printf("GET_SDR_RESERVE_REPO\n");
			if(debug) printf("ipmi_sdr_get_reservation\n");
			/* obtain reservation ID */
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = GET_SDR_RESERVE_REPO;
			res_buf->cc = 0;
			break;

		case GET_SENSOR_READING:
			if(debug) printf("GET_SENSOR_READING\n");
			if(debug) printf("ipmi_sdr_get_sensor_reading_ipmb\n");
			/*     req.msg.data = &sensor; */
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = GET_SENSOR_READING;
			res_buf->cc = 0;

			break;
		case GET_SENSOR_EVENT_STATUS:
			if(debug) printf("GET_SENSOR_EVENT_STATUS\n");
			if(debug) printf("ipmi_sdr_get_sensor_event_status\n");
			/* ipmi_sdr_print_sensor_event_status */
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = GET_SENSOR_EVENT_STATUS;
			res_buf->cc = 0;
			break;

		case GET_SENSOR_EVENT_ENABLE:
			if(debug) printf("GET_SENSOR_EVENT_ENABLE\n");
			if(debug) printf("ipmi_sdr_get_sensor_event_enable\n");
			/* ipmi_sdr_print_sensor_event_enable */
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = GET_SENSOR_EVENT_ENABLE;
			res_buf->cc = 0;
			break;

		case GET_DEVICE_SDR:
			if(debug) printf("GET_DEVICE_SDR\n");
			if(debug) printf("ipmi_sdr_get_header\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = GET_DEVICE_SDR;
			res_buf->cc = 0;
			/* p.456 Table 35-3 */
			break;

		case GET_SENSOR_THRESHOLDS:
			if(debug) printf("GET_SENSOR_THRESHOLDS\n");
			if(debug) printf("ipmi_sdr_get_sensor_thresholds\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = GET_SENSOR_THRESHOLDS;
			res_buf->cc = 0;
			break;

		case GET_SENSOR_HYSTERESIS:
			if(debug) printf("GET_SENSOR_HYSTERESIS\n");
			if(debug) printf("ipmi_sdr_get_sensor_hysteresis\n");
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = GET_SENSOR_HYSTERESIS;
			res_buf->cc = 0;
			break;
			/*
case :
if(debug) printf("\n");
if(debug) printf("\n");
break;
			 */
		default:
			printf("sensor event unsupport cmd %x \n", req_buf->cmd);
			res_buf->netfn = req_buf->netfn;
			res_buf->lun = req_buf->lun;
			res_buf->cmd = req_buf->cmd;
			res_buf->cc = 0xC1;
			break;
	}
	return ret;
}

unsigned char req_buf[256];
unsigned char res_buf[256];

void *kcs_thread(void *data) {
	ipmi_req_t *req = (ipmi_req_t *) req_buf;
	ipmi_res_t *res = (ipmi_res_t *) res_buf;

	unsigned char req_len, res_len=0;
	unsigned int i = 0;
	int flag = 0;
#ifdef ORG
	int kcs_fd = (int) data;
#elif DEMO
	int fdread, fdwrite;
#endif

	pass_fd = open_shadow();

	while(1) {
get_req:
#ifdef DEMO
		fdread = open("/etc/ipmi_write", O_RDONLY);
		req_len = read(fdread, req_buf, sizeof(req_buf));
		if(req_len == -1){
			perror("req_len error");
		}
		close(fdread);
#elif ORG
		req_len = read(kcs_fd, req_buf, sizeof(req_buf));
#endif
		if (req_len > 0){
			//dump read data
			if(debug) {
				int i = 0;
				printf("req.fn         : 0x%x\n", req->netfn);
				printf("req.lun         : 0x%x\n", req->lun);
				printf("req.cmd        : 0x%x\n", req->cmd);
				printf("req.data       : ");
				while(req->data[i] != '\0')     
					printf("0x%x ", req->data[i++]);    
				printf("\n");	
			}
			res_len = 4;
			switch(req->netfn) {
				case IPMI_APP_NETFN:
					ipmi_app_handler(req, &req_len, res, &res_len);
					break;

				case IPMI_TRANSPORT_NETFN:
					ipmi_transport_handler(req, &req_len, res, &res_len);
					break;

				case IPMI_CHASSIS_NETFN:
					ipmi_chassis_handler(req, &req_len, res, &res_len);
					break;

				case IPMI_GROUP_EXTENSION_NETFN:
					ipmi_dcmi_handler(req, &req_len, res, &res_len);
					break;

				case IPMI_OEM_GROUP_NETFN:
					ipmi_oem_handler(req, &req_len, res, &res_len);
					break;

				case IPMI_STORAGE_NETFN:
					ipmi_storage_handler(req, &req_len, res, &res_len);
					break;

				case IPMI_SENSOR_EVENT_NETFN:
					ipmi_sensor_event_handler(req, &req_len, res, &res_len);
					break;

				default:
					printf("other unsupport cmd %x \n", req->cmd);
					res->netfn = req->netfn;
					res->lun = req-> lun;
					res->cmd = req->cmd;
					res->cc = 0xC1;
					break;
			}
			if(debug){
				int i = 0;
				printf("res.fn         : 0x%x\n", res->netfn);
				printf("res.lun         : 0x%x\n", res->lun);
				printf("res.cmd        : 0x%x\n", res->cmd);
				printf("res.data       : ");
				while(res->data[i] != '\0')     
					printf("%x ", res->data[i++]);    
				printf("\n");
			}
		} else {
			continue;
		}
#ifdef ORG
		res_len = write(kcs_fd, res_buf, res_len);
#elif DEMO
		if(res_len > 0){
			system("rm -r /etc/kcs_write");
			system("touch /etc/kcs_write");
			fdwrite = open("/etc/kcs_write", O_WRONLY | O_TRUNC);
			res_len = write(fdwrite, res_buf, res_len);
			close(fdwrite);
			res_len = 0;
		}
#endif
	}
}

int main(int argc, char *argv[])
{
	int kcs_fd;
	int i;
	long retVal;

	pthread_t thread;

	char option;
	char dev_node[100]="", kcs_addr[100]="";
	unsigned long node_no = 2;
	unsigned long addr = 0xca2;

	while((option=getopt_long(argc, argv, short_options, long_options, NULL))!=(char)-1){
		printf("option is %c\n", option);
		switch(option){
			case 'h':
				usage(stdout, argc, argv);
				exit(EXIT_SUCCESS);
				break;
			case 'n':
				node_no = strtoul(optarg, 0, 0);
				break;
			case 'a':
				strcpy(kcs_addr, optarg);
				if(!strcmp(kcs_addr, "")){
					printf("No input kcs addr\n");
					usage(stdout, argc, argv);
					exit(EXIT_FAILURE);
				}
				break;
			case 'd':
				debug = 1;
				//				printf("debug is %d\n",debug);
				break;
			default:
				usage(stdout, argc, argv);
				exit(EXIT_FAILURE);
		}
	}

	if(debug) printf("kcs node: %d \n", node_no);
	switch(node_no) {
		case 0:
			system("echo 1 > /sys/devices/platform/ast-kcs.0/enable");
			break;
		case 1:
			system("echo 1 > /sys/devices/platform/ast-kcs.1/enable");
			break;
		case 2:
			system("echo 1 > /sys/devices/platform/ast-kcs.2/enable");
			break;
		case 3:
			system("echo 1 > /sys/devices/platform/ast-kcs.3/enable");
			break;
		case 4:
			system("echo 1 > /sys/devices/platform/ast-kcs.4/enable");
			break;
	}

	sprintf(dev_node, "/dev/ast-kcs.%d", node_no);
	printf("ast-kcs.%d, addr : %x\n", node_no, addr);
	if(!strcmp(dev_node, "")){
		printf("No input device node!\n");
		usage(stdout, argc, argv);
		exit(EXIT_FAILURE);
	}
	//	kcs_fd = open(dev_node, O_RDWR);
	sleep(1);

	pthread_create(&thread, NULL, kcs_thread, kcs_fd);

	sleep(1);
	pthread_join(thread, NULL);

	printf("Done.\n");	/* User press Ctrl + C */
	//	close(kcs_fd);
	return 0;
}
