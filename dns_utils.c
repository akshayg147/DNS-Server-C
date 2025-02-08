#include "dns_utils.h"
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <pthread.h>


static dns_cache_entry dns_cache[CACHE_SIZE];
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;

static dns_server dns_servers[MAX_DNS_SERVERS] = {
    {"8.8.8.8", 0, 0},    // Google DNS
    {"1.1.1.1", 0, 0},    // Cloudflare DNS
    {"9.9.9.9", 0, 0}     // Quad9 DNS
};


int extract_query_type(unsigned char *query) {
    return (query[12] << 8) | query[13];
}

int process_dns_query(unsigned char *query, int query_size, unsigned char *response) {
    uint16_t query_id = (query[0] << 8) | query[1];
    printf("Query ID: 0x%04x\n", query_id);

    int offset = 12; 
    int response_offset = 0;

    write_dns_header(response, &response_offset, query_id, 1);

    while (offset < query_size && query[offset] != 0) {
        offset += query[offset] + 1;
    }
    offset++; 

    uint16_t query_type = (query[offset] << 8) | query[offset + 1];
    printf("Query type: %d\n", query_type);

    memcpy(response + response_offset, query + 12, offset - 12 + 4);  // Copy question including type and class
    response_offset += offset - 12 + 4;

    if (query_type == A_RECORD) {
        write_dns_answer(response, &response_offset, query + 12, 
                        A_RECORD, (unsigned char*)"\xC0\x00\x02\x01");  // 192.0.2.1
        return response_offset;
    } 
    else if (query_type == AAAA_RECORD) {
        // Example IPv6 address (2001:db8::1)
        unsigned char ipv6[] = {
            0x20, 0x01,  // 2001
            0x0d, 0xb8,  // db8
            0x00, 0x00,  // ::
            0x00, 0x00,  // ::
            0x00, 0x00,  // ::
            0x00, 0x00,  // ::
            0x00, 0x00,  // ::
            0x00, 0x01   // 1
        };
        write_dns_answer(response, &response_offset, query + 12, 
                        AAAA_RECORD, ipv6);
        return response_offset;
    }
    else if (query_type == CNAME_RECORD) {
        unsigned char cname[] = {
            0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
            0x03, 'c', 'o', 'm',                      
            0x00                                       
        };
        write_dns_answer(response, &response_offset, query + 12, 
                        CNAME_RECORD, cname);
        return response_offset;
    }

    return 0; 
}

void write_dns_header(unsigned char *buffer, int *offset, uint16_t id, int is_response) {
    buffer[(*offset)++] = (id >> 8) & 0xFF;  
    buffer[(*offset)++] = id & 0xFF;         

    if (is_response) {
        buffer[(*offset)++] = 0x80;  
        buffer[(*offset)++] = 0x00;  
    } else {
        buffer[(*offset)++] = 0x01; 
        buffer[(*offset)++] = 0x00;  
    }


    buffer[(*offset)++] = 0x00; buffer[(*offset)++] = 0x01;  
    buffer[(*offset)++] = 0x00; buffer[(*offset)++] = 0x01;  
    buffer[(*offset)++] = 0x00; buffer[(*offset)++] = 0x00;  
    buffer[(*offset)++] = 0x00; buffer[(*offset)++] = 0x00;  
}

void write_dns_question(unsigned char *buffer, int *offset, const char *domain) {

    const char *pos = domain;
    while (*pos) {
        const char *dot = strchr(pos, '.');
        if (!dot) dot = pos + strlen(pos);
        int len = dot - pos;
        buffer[(*offset)++] = len;
        memcpy(buffer + *offset, pos, len);
        *offset += len;
        pos = (*dot) ? dot + 1 : dot;
    }
    buffer[(*offset)++] = 0x00; 
    buffer[(*offset)++] = 0x00; 
    buffer[(*offset)++] = A_RECORD; 
    buffer[(*offset)++] = 0x00; 
    buffer[(*offset)++] = 0x01;
}

void write_dns_answer(unsigned char *buffer, int *offset, 
                     unsigned char *name, uint16_t type, 
                     unsigned char *rdata) {

    buffer[(*offset)++] = 0xC0;  
    buffer[(*offset)++] = 0x0C;  


    buffer[(*offset)++] = (type >> 8) & 0xFF;
    buffer[(*offset)++] = type & 0xFF;


    buffer[(*offset)++] = 0x00;
    buffer[(*offset)++] = 0x01;


    buffer[(*offset)++] = 0x00;
    buffer[(*offset)++] = 0x00;
    buffer[(*offset)++] = 0x0E;
    buffer[(*offset)++] = 0x10;


    uint16_t rdlength;
    if (type == A_RECORD) {
        rdlength = 4;  
    } else if (type == AAAA_RECORD) {
        rdlength = 16;  
    } else if (type == CNAME_RECORD) {

        rdlength = 0;
        unsigned char *p = rdata;
        while (*p) {
            rdlength += *p + 1;  
            p += *p + 1;
        }
        rdlength++; 
    }

    buffer[(*offset)++] = (rdlength >> 8) & 0xFF;
    buffer[(*offset)++] = rdlength & 0xFF;


    memcpy(buffer + *offset, rdata, rdlength);
    *offset += rdlength;
}


void init_dns_cache(void) {
    pthread_mutex_lock(&cache_mutex);
    memset(dns_cache, 0, sizeof(dns_cache));
    pthread_mutex_unlock(&cache_mutex);
}


static int check_cache(const char* domain, uint16_t type, unsigned char* response) {
    pthread_mutex_lock(&cache_mutex);
    time_t now = time(NULL);
    
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (dns_cache[i].valid && 
            strcmp(dns_cache[i].domain, domain) == 0 && 
            dns_cache[i].type == type) {
            
            if (dns_cache[i].expiry > now) {
                memcpy(response, dns_cache[i].response, dns_cache[i].response_size);
                int size = dns_cache[i].response_size;
                pthread_mutex_unlock(&cache_mutex);
                return size;
            } else {
                dns_cache[i].valid = false;
            }
        }
    }
    
    pthread_mutex_unlock(&cache_mutex);
    return -1;
}


static void cache_response(const char* domain, uint16_t type, 
                         unsigned char* response, int response_size, uint32_t ttl) {
    pthread_mutex_lock(&cache_mutex);
    

    int slot = -1;
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (!dns_cache[i].valid) {
            slot = i;
            break;
        }
    }
    

    if (slot == -1) {
        time_t oldest = time(NULL);
        for (int i = 0; i < CACHE_SIZE; i++) {
            if (dns_cache[i].expiry < oldest) {
                oldest = dns_cache[i].expiry;
                slot = i;
            }
        }
    }
    

    if (slot != -1) {
        strncpy(dns_cache[slot].domain, domain, 255);
        dns_cache[slot].type = type;
        memcpy(dns_cache[slot].response, response, response_size);
        dns_cache[slot].response_size = response_size;
        dns_cache[slot].expiry = time(NULL) + ttl;
        dns_cache[slot].valid = true;
    }
    
    pthread_mutex_unlock(&cache_mutex);
}


bool validate_dns_query(unsigned char *query, int query_size) {
    if (query_size < 12) return false; 
    

    if (query[2] & 0x80) return false;
    

    if ((query[4] != 0) || (query[5] != 1)) return false;
    
    return true;
}


bool verify_dns_response(unsigned char *response, int response_size) {
    if (response_size < 12) return false;
    

    if (!(response[2] & 0x80)) return false;
    

    if ((response[3] & 0x0F) != 0) return false;
    
    return true;
}


static int get_best_server() {
    time_t now = time(NULL);
    int best = 0;
    int min_failures = dns_servers[0].failures;
    
    for (int i = 1; i < MAX_DNS_SERVERS; i++) {

        if (now - dns_servers[i].last_check > 300) {
            dns_servers[i].failures = 0;
        }
        
        if (dns_servers[i].failures < min_failures) {
            min_failures = dns_servers[i].failures;
            best = i;
        }
    }
    
    return best;
}

int forward_dns_query(unsigned char *query, int query_size, unsigned char *response) {

    if (!validate_dns_query(query, query_size)) {
        return -1;
    }
    

    char domain[256];
    uint16_t type;
    extract_question_details(query, domain, &type);
    

    int cached_size = check_cache(domain, type, response);
    if (cached_size > 0) {
        return cached_size;
    }
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }
    

    struct timeval tv;
    tv.tv_sec = DNS_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    

    int received = -1;
    int server_index = get_best_server();
    
    for (int attempts = 0; attempts < MAX_DNS_SERVERS; attempts++) {
        struct sockaddr_in dns_server;
        memset(&dns_server, 0, sizeof(dns_server));
        dns_server.sin_family = AF_INET;
        dns_server.sin_port = htons(53);
        inet_pton(AF_INET, dns_servers[server_index].ip, &dns_server.sin_addr);
        
        if (sendto(sock, query, query_size, 0, 
                  (struct sockaddr*)&dns_server, sizeof(dns_server)) < 0) {
            server_index = (server_index + 1) % MAX_DNS_SERVERS;
            continue;
        }
        
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        received = recvfrom(sock, response, BUF_SIZE, 0, 
                          (struct sockaddr*)&from, &from_len);
        
        if (received > 0 && verify_dns_response(response, received)) {

            dns_servers[server_index].failures = 0;
            dns_servers[server_index].last_check = time(NULL);
            

            uint32_t ttl = extract_ttl(response, received);
            cache_response(domain, type, response, received, ttl);
            
            break;
        } else {

            dns_servers[server_index].failures++;
            dns_servers[server_index].last_check = time(NULL);
            server_index = (server_index + 1) % MAX_DNS_SERVERS;
        }
    }
    
    close(sock);
    return received;
}


void extract_question_details(unsigned char *query, char *domain, uint16_t *type) {
    int i = 0, j = 0;
    int offset = 12; 


    while (query[offset] != 0) {
        int len = query[offset];
        if (j > 0) domain[j++] = '.';
        offset++;
        for (i = 0; i < len; i++) {
            domain[j++] = query[offset + i];
        }
        offset += len;
    }
    domain[j] = '\0';


    offset++;
    *type = (query[offset] << 8) | query[offset + 1];
}


uint32_t extract_ttl(unsigned char *response, int response_size) {
    int offset = 12; 


    while (offset < response_size && response[offset] != 0) {
        offset += response[offset] + 1;
    }
    offset += 5; 

    offset += 2;
    

    offset += 4;


    uint32_t ttl = (response[offset] << 24) |
                   (response[offset + 1] << 16) |
                   (response[offset + 2] << 8) |
                   response[offset + 3];

    return ttl;
}
