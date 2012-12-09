#include <pcap.h>
#include <popt.h> 
#include <string.h> 
#include <stdlib.h> 
#include <signal.h>

pcap_t *descr = NULL; 
pcap_dumper_t *dumper = NULL;
static void cleanup(int);
void write_captured_packet(u_char *user_arg,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void usage();

int main(int argc, char *argv[]){
 char errbuf[PCAP_ERRBUF_SIZE], *device="any",*output_filename="/tmp/test.dump",*filter;
 const char *tmp;
 struct bpf_program fcode;
 int count=0;
 int timer=10;
 int c;
 poptContext context;
 struct poptOption optionsTable[] = {
  {"output",	'o',	POPT_ARG_STRING,	&output_filename,	'o'},
  {"count",	'c',	POPT_ARG_INT,		&count,			'c'},
  {"time",	't',	POPT_ARG_INT,		&timer,			't'},
  {NULL,0,0,NULL,0}
 };
 context = poptGetContext(NULL, argc, (const char **) argv, optionsTable, 0);
 poptSetOtherOptionHelp(context, "<tcpdump filter>");
 while (poptGetNextOpt(context) >= 0) {}
 filter = (char *)malloc(256);
 strcpy (filter,"");
 while ((tmp = poptGetArg(context))!=NULL) {
   if (strcmp(filter,"")) filter = strcat(filter," ");
   filter = strcat(filter,tmp);
 }
 if (strcmp(filter,"")==0) filter = "port 3306";
 poptFreeContext(context);

 printf("file=%s, count=%d, time=%d, filter=%s\n",output_filename,count,timer,filter);
 signal(SIGTERM, cleanup);
 signal(SIGALRM, cleanup);
 signal(SIGINT, cleanup);
 memset(errbuf,0,PCAP_ERRBUF_SIZE); 
 
descr = pcap_open_live(device,BUFSIZ,0,100,errbuf);
 if (descr == NULL) {
  fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
  return(2);
 }
 if (pcap_compile(descr, &fcode, filter, 0, 0) < 0){
  fprintf(stderr,"can not analyze filter:%s\n", filter);
  exit(1);
 }
 if (pcap_setfilter(descr,&fcode) == -1) {
  fprintf(stderr, "filter can not use: %s\n", filter);
  exit(1);
 }
 dumper = pcap_dump_open(descr,output_filename);
 alarm(timer);
 pcap_loop(descr,count,write_captured_packet,NULL);
 pcap_close(descr);
 pcap_dump_close(dumper);
 exit(0);
}

static void cleanup(int sig){
 pcap_breakloop(descr); 
}

void write_captured_packet(u_char *user_arg,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
 pcap_dump((unsigned char *)dumper,pkthdr,packet);
}
