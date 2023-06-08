#include <stdio.h>
#include <error.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>

#define DNS_SERVER "8.8.8.8"
#define DNS_PORT 53
#define A 1
#define NS 2
#define MD 3
#define MF 4
#define CNAME 5
#define SOA 6
#define MB 7
#define MG 8
#define DEBUG do{printf("line:%d,func:%s\n",__LINE__,__FUNCTION__);}while(0)

typedef  unsigned short U16 ; 
typedef unsigned char U8;

static char buf[4096] = {0};

typedef struct UDPHead
{
	U16 ID;
	U16 parse;
	U16 QDCOUNT;
	U16 ANCOUNT;
	U16 NSCOUNT;
	U16 ARCOUNT;
}UDPHead;

typedef struct UDPQuestion
{
	U16 QTYPE;
	U16 QCLASS;
	U16 len;
	char QNAME[];
}UDPQuestion;

typedef struct _record
{
	U8* domain;
	U8* data;
}_record;

typedef struct UDPEntity
{
	U16 type;
	U16 class;
	unsigned int ttl;
	U16 datalen;
	_record content;
}UDPEntity;


void _packUDPHead(UDPHead * head)
{
	if(NULL == head)
		return;
	head->ID = htons(0x1234);
	head->parse = htons(0x0100);
	head->QDCOUNT = htons(1);
	head->ANCOUNT = 0;
	head->NSCOUNT = 0;
	head->ARCOUNT = 0;
}

UDPQuestion* _packUDPQuestion(const char* queryIP)
{
	if(NULL == queryIP)
		return NULL;

	UDPQuestion * query = (UDPQuestion*)malloc(sizeof(UDPQuestion) + strlen(queryIP) + 2);
	if(query == NULL)
	{
		fprintf(stderr,"malloc_error\n");
		exit(-1);
	}
	query->QTYPE = htons(1);
	query->QCLASS = htons(1);

	unsigned int count = 0;
	char * temp = (char*)queryIP;
	unsigned int index = 0;
	while(*(queryIP + count))
	{
		if(*(queryIP + count) == '.')
		{
			query->QNAME[index++] = (queryIP + count - temp)&0xff;
			memcpy(query->QNAME + index,temp,(queryIP + count - temp));			
			index+=(queryIP + count - temp);
			count++;
			temp = (char*)(queryIP + count);
			continue;
		}
		count++;
	}
	query->QNAME[index++] = (queryIP + count - temp)&0xff;
	memcpy(query->QNAME + index,temp,(queryIP + count - temp));			
	index+=(queryIP + count - temp);
	query->QNAME[index++] = 0x00;
	query->len = index;	
	return query;

}

unsigned int _packParse(UDPHead* head,UDPQuestion* query,char* dst,unsigned int length)
{
	if(!head || !query || !buf)
		return -1;

	unsigned int count = 0;
	memcpy(dst + count,(char*)&head->ID,2);
	count+=2;
	memcpy(dst + count,(char*)&head->parse,2);
	count+=2;
	memcpy(dst + count,(char*)&head->QDCOUNT,2);
	count+=2;
	memcpy(dst + count,(char*)&head->ANCOUNT,2);
	count+=2;
	memcpy(dst + count,(char*)&head->NSCOUNT,2);
	count+=2;
	memcpy(dst + count,(char*)&head->ARCOUNT,2);
	count+=2;

	//UDPHEAD size = 12bits

	memcpy(dst+count,(char*)&query->QNAME,query->len);
	count+=query->len;
	memcpy(dst+count,(char*)&query->QTYPE,2);
	count+=2;
	memcpy(dst+count,(char*)&query->QCLASS,2);
	count+=2;

	return count;

}


bool _unpackUDPHead(UDPHead * head,const char* src,unsigned int *retlen)
{
	if(head == NULL || retlen == NULL)
		return false;
	U16 temp = 0;
	unsigned int count = 0;
	memcpy((char*)&temp,src + count,2);
	count+=2;
	head->ID = ntohs(temp);
	memcpy((char*)&temp,src + count,2);
	count+=2;
	head->parse = ntohs(temp);
	memcpy((char*)&temp,src+count,2);
	count+=2;
	head->QDCOUNT = ntohs(temp);
	memcpy((char*)&temp,src+count,2);
	count+=2;
	head->ANCOUNT = ntohs(temp);
	memcpy((char*)&temp,src+count,2);
	count+=2;
	head->NSCOUNT = ntohs(temp);
	memcpy((char*)&temp,src+count,2);
	count+=2;
	head->ARCOUNT = ntohs(temp);

	*retlen = count;

	return true;

}

void _unpackUDPEntityQuestion(UDPEntity* answer,const char* buf,unsigned int *len)
{
	char *ptr = (char*)&buf[12];
	U8 temp = 0;
	U16 count = 0;
	answer->content.domain = (U8*)malloc(*len - 2);
	while(*ptr)
	{
		count = *ptr;
		ptr++;
		for(U16 i = 0; i < count;i++)
		{
			answer->content.domain[temp++] = *ptr;
			ptr++;
			if(*ptr == '\0')
				break;
		}
		answer->content.domain[temp++] = '.';
	}
	
	answer->content.domain[temp-1] = '\0';
	temp = 0;
	memcpy((char*)&temp,ptr,2);
	ptr+=2;
	answer->type =temp;
	memcpy((char*)&temp,ptr,2);
	ptr+=2;
	answer->class = temp;
	printf("domain:%s\n",answer->content.domain);
	printf("type:%d\n",answer->type);
	printf("class:%d\n",answer->class);
	*len = *len + 4;
	free(answer->content.domain);
	answer->content.domain = NULL;
}

void _unpackUDPEntityAnswer(const char* buf,unsigned int nums,unsigned int* offset)
{
	if(buf == NULL)
		return ;
	char* ptr = (char*)(&buf[12] + *offset);
	U8 temp = 0;
	U16 swap = 0;
	for(int i = 0; i < nums;i++)
	{
		int msize = 0;
		memcpy((char*)&temp,ptr,1);
		msize++;
		if(temp&0xff != 0xc0)
		{
			break;
		}
		else
		{
			memcpy((char*)&temp,ptr+1,1);
			msize++;
			memcpy((char*)&swap,ptr+msize,2);
			msize+=2;
			if(ntohs(swap) == CNAME)
			{
				printf("type: CNAME  %u\n",ntohs(swap));
				memcpy((char*)&swap,ptr+msize,2);
				msize+=2;
				printf("class: %u\n",ntohs(swap));
				unsigned  int t = 0;
				memcpy((char*)&t,ptr+msize,4);
				msize+=4;
				printf("ttl: %u\n",ntohl(t));
				memcpy((char*)&swap,ptr+msize,2);
				msize+=2;
				printf("datalen: %u\n",ntohs(swap));
				U8 * addr = (U8*)malloc(sizeof(U8)*swap + 1);
				if(addr == NULL)
					return;
				ptr+=msize;
				U16 index = 0;
				for(U16 i = 0 ;i < ntohs(swap) - 2;i++)
				{
					U8 count = ptr[i];
					i++;
					memcpy((char*)&addr[index],&ptr[i],count);
					index+=count;
					i+=(count-1);
					addr[index++] = '.';
				}
				addr[index] = '\0';
				printf("data: %s\n",addr);
				ptr+= ntohs(swap);
				free(addr);
				addr = NULL;
			}
			else if(ntohs(swap) == A)
			{
				printf("type: CNAME  %u\n",ntohs(swap));
				memcpy((char*)&swap,ptr+msize,2);
				msize+=2;
				printf("class: %u\n",ntohs(swap));
				unsigned  int t = 0;
				memcpy((char*)&t,ptr+msize,4);
				msize+=4;
				printf("ttl: %u\n",ntohl(t));
				memcpy((char*)&swap,ptr+msize,2);
				msize+=2;
				printf("datalen: %u\n",ntohs(swap));
				ptr+=msize;
				printf("Ipv4:");
				for(U16 i = 0; i < ntohs(swap);i++)
				{
					memcpy((char*)&temp,ptr,1);
					printf("%u",temp);
					if(i!=ntohs(swap) - 1)
						printf(".");
					ptr++;
				}
				printf("\n");
				
			}
			else
			{
				printf("No handle\n");
				break;
			}
				
		}
	}
	return ;
}

int main(int argc,char**argv)
{
	if(argc <= 1)
	{
		fprintf(stderr,"eg:./filename IP_ADDRESS\n");
		return 1;
	}
	printf("str:%s\n",argv[1]);

	int sock = socket(AF_INET,SOCK_DGRAM,0);
	if(sock == -1)
	{
		fprintf(stderr,"socket error\n");
		return 1;
	}
	struct sockaddr_in s_dns,dst;

	s_dns.sin_family = AF_INET;
	s_dns.sin_port = htons(DNS_PORT);
	s_dns.sin_addr.s_addr = inet_addr(DNS_SERVER);
	socklen_t addrsize = sizeof(dst);
	UDPHead head;
	UDPQuestion * ptr = NULL;
	memset((char*)&head,0,sizeof(head));
	_packUDPHead(&head);
	ptr = _packUDPQuestion(argv[1]);

	int len = _packParse(&head,ptr, buf, 4096);
	ssize_t sendsize = sendto(sock, (void *)buf, len, 0, (struct sockaddr *)&s_dns, sizeof(s_dns));
	if(sendsize == -1)
	{
		fprintf(stderr,"sendto failed\n");
		return 1;
	}
	printf("sendsuccess,size:%ld\n",sendsize);
	memset(buf,0,len);
	ssize_t recvsize = recvfrom(sock, (void *)buf,4096, 0,
							(struct sockaddr *)&dst, &addrsize);
	if(recvsize == -1)
	{
		fprintf(stderr,"recvfrom failed\n");
		return 1;
	}
	printf("receive success\n");
	printf("IP:%s,port:%d,recvsize:%ld\n",inet_ntoa(dst.sin_addr),ntohs(dst.sin_port),recvsize);


	///////////////////////////////////////////////////////////////
	//unpack respond pack

	UDPHead respondHead;
	int retlen = 0;
	if(!_unpackUDPHead(&head, buf, &retlen))
	{
		fprintf(stderr,"unpackUDPHead failed\n");
		return 1;
	}
	U16 rcode = head.parse & 0xf;
	printf("rcode:%d\n",rcode);
	switch(rcode)
	{
		case 0:
			printf("No error condition\n");
			break;
		case 1:
			printf("Format error\n");
			break;
		case 2:
			printf("Server failure\n");
			break;
		case 3:
			printf("Name error\n");
			break;
		case 4:
			printf("No Implemented\n");//Can't support this parse
			break;
		case 5:
			printf("Server refuse\n");
			break;
		default:
			printf("Undefined rcode\n");
			break;
	}

	printf("Questions     :%d\n",head.QDCOUNT);
	printf("Answer RRs    :%d\n",head.ANCOUNT);
	printf("Authority RRs :%d\n",head.NSCOUNT);
	printf("Additional RRs:%d\n",head.ARCOUNT);

	UDPEntity en;
	unsigned int _len = strlen(argv[1])+2;
	memset((char*)&en,0,sizeof(en));

	_unpackUDPEntityQuestion(&en, buf, &_len);
	
	_unpackUDPEntityAnswer(buf,head.ANCOUNT,&_len);
	free(ptr);
	ptr = NULL;
	return 0;
}
