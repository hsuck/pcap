#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <time.h>
#include <netinet/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/ip_icmp.h>

#define MAC_ADDR_LEN 18

void dump_ethernet( u_int32_t len, const u_char *content );
void dump_ip( struct ip *ip );
void dump_tcp( struct tcphdr *tcp );
void dump_tcp_mini( struct tcphdr *tcp );
void dump_udp( struct udphdr *udp );
void dump_icmp( struct icmp *icmp );
void pcap_callback( u_char* arg, const struct pcap_pkthdr *header, const u_char *content );
char *mac_transfer( u_char *b );
char *ttoa( u_int8_t flag );
char *ftoa( u_int16_t flag );

char *type_name[] = {
    "Echo Reply",               /* Type  0 */
    "Undefine",                 /* Type  1 */
    "Undefine",                 /* Type  2 */
    "Destination Unreachable",  /* Type  3 */
    "Source Quench",            /* Type  4 */
    "Redirect (change route)",  /* Type  5 */
    "Undefine",                 /* Type  6 */
    "Undefine",                 /* Type  7 */
    "Echo Request",             /* Type  8 */
    "Undefine",                 /* Type  9 */
    "Undefine",                 /* Type 10 */
    "Time Exceeded",            /* Type 11 */
    "Parameter Problem",        /* Type 12 */
    "Timestamp Request",        /* Type 13 */
    "Timestamp Reply",          /* Type 14 */
    "Information Request",      /* Type 15 */
    "Information Reply",        /* Type 16 */
    "Address Mask Request",     /* Type 17 */
    "Address Mask Reply",       /* Type 18 */
    "Unknown"                   /* Type 19 */
};

int main( int argc, char **argv ){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    pcap_dumper_t *dumper = NULL;
    
    if( argc < 2 ){
        char *device = "enp0s3";
        handle = pcap_open_live( device, 65535, 1, 1, errbuf );

        if( !handle ){
            fprintf( stderr, "pcap_open_live: %s\n", errbuf );
            exit(1);
        }

        pcap_loop( handle, -1, pcap_callback, NULL );
    }
    else{
        int num = 0;
        char *filename = NULL, *dumpfile = NULL;
        for( int i = 1; i < argc; i++ ){
            if( !strcmp( argv[i], "-n" ) && argv[i + 1] != NULL )
                num = atoi( argv[i + 1] );
            if( !strcmp( argv[i], "-f" ) && argv[i + 1] != NULL )
                filename = argv[i + 1];
            if( !strcmp( argv[i], "-o" ) && argv[i + 1] != NULL )
                dumpfile = argv[i + 1];
        }
        
        if( num != 0 && filename != NULL ){
            handle = pcap_open_offline( filename, errbuf );

            if( !handle ){
                fprintf( stderr, "pcap_open_offline: %s\n", errbuf );
                exit(1);
            }

            if( dumpfile != NULL ){
                dumper = pcap_dump_open( handle, dumpfile );
                if( !dumper ){
                    fprintf( stderr, "pcap_dump_open: %s\n", pcap_geterr( handle ) );
                    pcap_close( handle );
                    exit(1);
                }
                
                pcap_loop( handle, num, pcap_callback, (u_char *)dumper );
            }
            else
                pcap_loop( handle, num, pcap_callback, NULL );
        }
        else if( num == 0 && filename != NULL ){
            handle = pcap_open_offline( filename, errbuf );

            if( !handle ){
                fprintf( stderr, "pcap_open_offline: %s\n", errbuf );
                exit(1);
            }
            
            if( dumpfile != NULL ){
                dumper = pcap_dump_open( handle, dumpfile );
                if( !dumper ){
                    fprintf( stderr, "pcap_dump_open: %s\n", pcap_geterr( handle ) );
                    pcap_close( handle );
                    exit(1);
                }
                
                pcap_loop( handle, num, pcap_callback, (u_char *)dumper );
            }
            else
                pcap_loop( handle, num, pcap_callback, NULL );
        }    
        else if( num != 0 && filename == NULL ){
            char *device = "enp0s3";
            handle = pcap_open_live( device, 65535, 1, 1, errbuf );

            if( !handle ){
                fprintf( stderr, "pcap_open_live: %s\n", errbuf );
                exit(1);
            }

            if( dumpfile != NULL ){
                dumper = pcap_dump_open( handle, dumpfile );
                if( !dumper ){
                    fprintf( stderr, "pcap_dump_open: %s\n", pcap_geterr( handle ) );
                    pcap_close( handle );
                    exit(1);
                }
                
                pcap_loop( handle, num, pcap_callback, (u_char *)dumper );
            }
            else
                pcap_loop( handle, num, pcap_callback, NULL );
        }   
        else{
            fprintf( stderr, "Usage: ./pcap_analysis [option]... [filename]...\n" );
            fprintf( stderr, "-n the number of packet you want to capture\n" );
            fprintf( stderr, "-f pcap filename\n" );
            exit(1);
        } 
    }
    
    if( dumper != NULL ){
        pcap_dump_flush( dumper );
        pcap_dump_close( dumper );
    }
    pcap_close( handle );
}

char *mac_transfer( u_char *b ){
    static char str[MAC_ADDR_LEN];

    snprintf( str, sizeof( str ), "%02x:%02x:%02x:%02x:%02x:%02x"
           , b[0], b[1], b[2], b[3], b[4], b[5] );

    return str;
}

void pcap_callback( u_char* arg, const struct pcap_pkthdr *header, const u_char *content ){
    pcap_dumper_t *dumper = (pcap_dumper_t *)arg;
    if( dumper != NULL ){
        pcap_dump( arg, header, content );
        pcap_dump_flush( dumper );
    }

    static int num = 0;
    struct tm *local = localtime( &header->ts.tv_sec );
    char timestr[16];
    strftime( timestr, sizeof( timestr ), "%H:%M:%S", local );
    
    printf( "No.%d\n", ++num );

    printf( "\tTime: %u %u/%u %s.%.6ld\n"
            , local->tm_year + 1900, local->tm_mon + 1, local->tm_mday
            , timestr ,header->ts.tv_usec );
    printf( "\tLength: %d bytes\n", header->len );
    printf( "\tCapture: length: %d bytes\n", header->caplen );

    dump_ethernet( header->caplen, content );

    printf("\n");
}

void dump_ethernet( u_int32_t len, const u_char *content ){
    struct ether_header *ethernet = (struct ether_header *)content;
    char dst_mac_addr[MAC_ADDR_LEN] = {};
    char src_mac_addr[MAC_ADDR_LEN] = {};
    u_int16_t type;

    // copy header
    strncpy( dst_mac_addr, mac_transfer( ethernet->ether_dhost ), sizeof( dst_mac_addr ) );
    strncpy( src_mac_addr, mac_transfer( ethernet->ether_shost ), sizeof( src_mac_addr ) );
    type = ntohs( ethernet->ether_type );

    if( type <= 1500 )
        printf("IEEE 802.3 Ethernet frame:\n");
    else
        printf("\n\tEthernet frame:\n");

    printf( "\t+-------------------------+-------------------------+\n" );
    printf( "\t| Destination MAC Address:         %17s|\n", dst_mac_addr );
    printf( "\t+-------------------------+-------------------------+\n" );
    printf( "\t| Source MAC Address:              %17s|\n", src_mac_addr );
    printf( "\t+-------------------------+-------------------------+\n" );

    if ( type < 1500 )
        printf( "\t| Length:            %5u|\n", type );
    else
        printf( "\t| Ethernet Type:    0x%04x|\n", type );
    
    printf("\t+-------------------------+\n");

    switch( type ){
        case ETHERTYPE_ARP:
            printf("Next is ARP\n");
            break;
        
        case ETHERTYPE_IP:
            dump_ip( (struct ip *)( content + ETHER_HDR_LEN ) );
            break; 
        
        case ETHERTYPE_REVARP:
            printf("Next is RARP\n");
            break; 
        
        case ETHERTYPE_IPV6:
            printf("Next is IPv6\n");
            break; 
        
        default:
            printf( "Next is %#06x\n", type );
            break; 
    }
}

char *ip_ttoa( u_int8_t flag ){
    static int f[] = { '1', '1', '1', 'D', 'T', 'R', 'C', 'X' };
    static char str[9];
    u_int8_t mask = 1 << 7;

    for( int i = 0; i < 8; i++ ){
        if( flag & mask )
            str[i] = f[i];
        else
            str[i] = '-';
        
        mask = mask >> 1;
    }

    str[8] = '\0';
    
    return str;
}
char *ip_ftoa( u_int16_t flag ){
    static int f[] = { 'R', 'D', 'M' };
    static char str[4];
    u_int16_t mask = 1 << 15;

    for( int i = 0; i < 3; i++ ){
        if( flag & mask )
            str[i] = f[i];
        else
            str[i] = '-';
    
        mask = mask >> 1;
    }

    str[3] = '\0';
    
    return str;
}

void dump_ip( struct ip *ip ){
    /*struct ip *ip = (struct ip *)( content + ETHER_HDR_LEN );*/
    u_int version = ip->ip_v;
    u_int hdr_len = ip->ip_hl << 2;
    u_char tos = ip->ip_tos;
    u_int16_t total_len = ntohs( ip->ip_len );
    u_int16_t id = ntohs( ip->ip_id );
    u_int16_t off = ntohs( ip->ip_off );
    u_char ttl = ip->ip_ttl;
    u_char protocol = ip->ip_p;
    u_int16_t checksum = ntohs( ip->ip_sum );

    printf("\n\tProtocol: IP\n");
    printf("\t+-----+------+--------------+-----------------------+\n");
    printf( "\t| IV:%1u| HL:%2u| TOS: %8s| Total Length: %8u|\n",
           version, hdr_len, ip_ttoa( tos ), total_len );
    printf("\t+-----+------+--------------+-------+---------------+\n");
    printf( "\t| Identifier:          %5u| FF:%3s| FO:      %5u|\n",
           id, ip_ftoa( off ), off & IP_OFFMASK );
    printf("\t+------------+--------------+-------+---------------+\n");
    printf( "\t| TTL:    %3u| Pro:     0x%02x| Header Checksum: %5u|\n",
           ttl, protocol, checksum );
    printf("\t+------------+--------------+-----------------------+\n");
    printf( "\t| Source IP Address:                 %15s|\n",  inet_ntoa( ip->ip_src ) );
    printf("\t+---------------------------------------------------+\n");
    printf( "\t| Destination IP Address:            %15s|\n", inet_ntoa( ip->ip_dst ) );
    printf("\t+---------------------------------------------------+\n");

    char *p = (char *)ip + ( ip->ip_hl << 2 );
    switch( protocol ){
        case IPPROTO_UDP:
            dump_udp( (struct udphdr *)p );
            break;

        case IPPROTO_TCP:
            dump_tcp( (struct tcphdr *)p );
            break;

        case IPPROTO_ICMP:
            dump_icmp( (struct icmp *)p );
            break;

        default:
            printf("Next is %d\n", protocol);
            break;
    }
}

void dump_tcp( struct tcphdr *tcp ){
    /*struct ip *ip = (struct ip *)( content + ETHER_HDR_LEN );
    struct tcphdr *tcp = (struct tcphdr *)( content + ETHER_HDR_LEN + ( ip->ip_hl << 2 ) );*/

    u_int16_t sport = ntohs( tcp->source );
    u_int16_t dport = ntohs( tcp->dest );
    u_int32_t seq = ntohl( tcp->seq );
    u_int32_t ack_seq = ntohl( tcp->ack_seq );
    u_int8_t hdr_len = tcp-> doff << 2;
    u_int16_t window = ntohs( tcp->window );
    u_int16_t checksum = tcp->check;
    u_int16_t urgent = tcp->urg_ptr;

    char flag[9];
    flag[8] = '\0';
    flag[7] = ( tcp->fin ) ? 'F' : '-';
    flag[6] = ( tcp->syn ) ? 'S' : '-';
    flag[5] = ( tcp->rst ) ? 'R' : '-';
    flag[4] = ( tcp->psh ) ? 'P' : '-';
    flag[3] = ( tcp->ack ) ? 'A' : '-';
    flag[2] = ( tcp->urg ) ? 'U' : '-';
    flag[1] = ( tcp->ece ) ? 'E' : '-';
    flag[0] = ( tcp->cwr ) ? 'C' : '-';

    printf("\n\tProtocol: TCP\n");
    printf("\t+-------------------------+-------------------------+\n");
    printf( "\t| Source Port:       %5u| Destination Port:  %5u|\n", sport, dport );
    printf("\t+-------------------------+-------------------------+\n");
    printf( "\t| Sequence Number:                        %10u|\n", seq );
    printf("\t+---------------------------------------------------+\n");
    printf( "\t| Acknowledgement Number:                 %10u|\n", ack_seq );
    printf("\t+------+-------+----------+-------------------------+\n");
    printf("\t| HL:%2u|  RSV  |F:%8s| Window Size:       %5u|\n", hdr_len, flag, window );
    printf("\t+------+-------+----------+-------------------------+\n");
    printf("\t| Checksum:          %5u| Urgent Pointer:    %5u|\n", checksum, urgent);
    printf("\t+-------------------------+-------------------------+\n");
}

void dump_tcp_mini( struct tcphdr *tcp ){
    /*struct ip *ip = (struct ip *)( content + ETHER_HDR_LEN );
    struct tcphdr *tcp = (struct tcphdr *)( content + ETHER_HDR_LEN + ( ip->ip_hl << 2 ) );*/

    u_int16_t sport = ntohs( tcp->source );
    u_int16_t dport = ntohs( tcp->dest );
    u_int32_t seq = ntohl( tcp->seq );
    
    printf("\n\tProtocol: TCP\n");
    printf("\t+-------------------------+-------------------------+\n");
    printf( "\t| Source Port:       %5u| Destination Port:  %5u|\n", sport, dport );
    printf("\t+-------------------------+-------------------------+\n");
    printf( "\t| Sequence Number:                        %10u|\n", seq );
    printf("\t+---------------------------------------------------+\n");
}

void dump_udp( struct udphdr *udp ){
    /*struct ip *ip = (struct ip *)( content + ETHER_HDR_LEN );
    struct udphdr *udp = (struct udphdr *)( content + ETHER_HDR_LEN + ( ip->ip_hl << 2 ) );*/

    u_int16_t sport = ntohs( udp->source );
    u_int16_t dport = ntohs( udp->dest );
    u_int16_t length = ntohs( udp->len );
    u_int16_t checksum = ntohs( udp->check );

    printf("\n\tProtocol: UDP\n");
    printf("\t+-------------------------+-------------------------+\n");
    printf( "\t| Source Port:       %5u| Destination Port:  %5u|\n", sport, dport );
    printf("\t+-------------------------+-------------------------+\n");
    printf( "\t| Length:            %5u| Checksum:          %5u|\n", length, checksum );
    printf("\t+-------------------------+-------------------------+\n");
}

void dump_icmp( struct icmp *icmp ){
    /*struct ip *ip = (struct ip *)( content + ETHER_HDR_LEN );
    struct icmp *icmp = (struct icmp *)( content + ETHER_HDR_LEN + ( ip->ip_hl << 2 ) );*/

    u_int8_t type = icmp->icmp_type;
    u_int8_t code = icmp->icmp_code;
    u_int16_t checksum = ntohs( icmp->icmp_cksum );
    
    if( type < 0 || 20 <= type )
        type -= 1;

    printf( "\n\tProtocol: ICMP (%s)\n", type_name[type] );

    printf("\t+------------+------------+-------------------------+\n");
    printf( "\t| Type:   %3u| Code:   %3u| Checksum:          %5u|\n", type, code, checksum );
    printf("\t+------------+------------+-------------------------+\n");

    if( type == ICMP_ECHOREPLY || type == ICMP_ECHO ){
        printf( "\t| Identification:    %5u| Sequence Number:   %5u|\n", ntohs( icmp->icmp_id ), ntohs( icmp->icmp_seq ) );
        printf("\t+-------------------------+-------------------------+\n");
    }
    else if( type == ICMP_UNREACH ){
        if( code == ICMP_UNREACH_NEEDFRAG ){
            printf( "\t| void:          %5u| Next MTU:          %5u|\n", ntohs( icmp->icmp_pmvoid ), ntohs( icmp->icmp_nextmtu ) );
            printf("\t+-------------------------+-------------------------+\n");
        }
        else{
            printf( "\t| Unused:                                 %10lu|\n", (unsigned long)ntohl( icmp->icmp_void ) );
            printf("\t+-------------------------+-------------------------+\n");
        }
    }
    else if( type == ICMP_REDIRECT ){
        printf( "\t| Router IP Address:                 %15s|\n", inet_ntoa( icmp->icmp_gwaddr ) );
        printf("\t+---------------------------------------------------+\n");
    }
    else if( type == ICMP_TIMXCEED ){
        printf( "\t| Unused:                                 %10lu|\n", (unsigned long)ntohl( icmp->icmp_void ) );
        printf("\t+---------------------------------------------------+\n");
    }


    if( type == ICMP_UNREACH || type == ICMP_REDIRECT || type == ICMP_TIMXCEED ){
        struct ip *ip = (struct ip *)icmp->icmp_data;
        char *p = (char *)ip + ( ip->ip_hl << 2 );
        dump_ip( (struct ip *)p );    
        switch( ip->ip_p ){
            case IPPROTO_TCP:
                if( type == ICMP_REDIRECT )
                    dump_tcp_mini( (struct tcphdr *)p );
                else
                    dump_tcp( (struct tcphdr *)p );
                break;
            case IPPROTO_UDP:
                dump_udp( (struct udphdr *)p );
                break;
        }
    }
}
