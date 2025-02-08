#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>

#define BUF_SIZE 512
#define CACHE_SIZE 1000
#define DNS_TIMEOUT 3 
#define MAX_DNS_SERVERS 3


#define A_RECORD 1
#define AAAA_RECORD 28
#define CNAME_RECORD 5


typedef struct {
    char domain[256];
    uint16_t type;
    unsigned char response[BUF_SIZE];
    int response_size;
    time_t expiry;
    bool valid;
} dns_cache_entry;


typedef struct {
    char ip[16];
    int failures;
    time_t last_check;
} dns_server;

void write_dns_header(unsigned char *buffer, int *offset, uint16_t id, int is_response);
void write_dns_question(unsigned char *buffer, int *offset, const char *domain);
void write_dns_answer(unsigned char *buffer, int *offset, 
                     unsigned char *name, uint16_t type, 
                     unsigned char *rdata);
int forward_dns_query(unsigned char *query, int query_size, unsigned char *response);
int process_dns_query(unsigned char *query, int query_size, unsigned char *response);
void init_dns_cache(void);
void init_dns_servers(void);
bool validate_dns_query(unsigned char *query, int query_size);
bool verify_dns_response(unsigned char *response, int response_size);
void extract_question_details(unsigned char *query, char *domain, uint16_t *type);
uint32_t extract_ttl(unsigned char *response, int response_size);

#endif