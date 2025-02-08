#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "dns_utils.h"

#define PORT 2053
#define BUF_SIZE 512

void handle_dns_query(int client_socket, struct sockaddr_in *client_addr) {
    unsigned char buffer[BUF_SIZE], response[BUF_SIZE];
    socklen_t addr_len = sizeof(struct sockaddr_in);
    
    int received = recvfrom(client_socket, buffer, BUF_SIZE, 0,
                           (struct sockaddr*)client_addr, &addr_len);
    
    if (received > 0) {
        int response_size = forward_dns_query(buffer, received, response);
        
        if (response_size > 0) {
            sendto(client_socket, response, response_size, 0,
                   (struct sockaddr*)client_addr, addr_len);
        }
    }
}

int main() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Failed to create socket");
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(2053);

    // Add socket option to reuse address
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        return 1;
    }

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Failed to bind");
        return 1;
    }

    printf("DNS server is running on port 2053\n");

    while (1) {
        printf("Waiting for DNS query...\n");
        
        handle_dns_query(sockfd, &server_addr);
    }

    close(sockfd);
    return 0;
}