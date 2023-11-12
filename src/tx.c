//
// Copyright (C) 2017 - 2022 Vasily Evseenko <svpcom@p2ptech.org>

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 3.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */




#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <sys/resource.h>
#include <pcap/pcap.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/random.h>
#include <inttypes.h>

#include "wifibroadcast.h"
#include "fec.h"

//using namespace std;

#define FEC_MAX_N 32   //!!!!   

uint8_t* block[FEC_MAX_N];


    fec_t* fec_p;
    int fec_k;  // RS number of primary fragments in block
    int fec_n;  // RS total number of fragments in block
    uint64_t block_idx; // (block_idx << 8) + fragment_idx = nonce (64bit)
    uint8_t fragment_idx;
    size_t max_packet_size;
    uint64_t epoch; // Packets from old epoch will be discarded
    uint32_t channel_id; // (link_id << 8) + port_number

    // tx->rx keypair
    uint8_t tx_secretkey[crypto_box_SECRETKEYBYTES];
    uint8_t rx_publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t session_key[crypto_aead_chacha20poly1305_KEYBYTES];
    uint8_t session_key_packet[sizeof(wsession_hdr_t) + sizeof(wsession_data_t) + crypto_box_MACBYTES];
    int current_output;
    uint16_t ieee80211_seq;
//    std::vector<pcap_t*> ppcap;
    pcap_t* ppcap;


uint64_t get_time_ms(void) // in milliseconds
{
    struct timespec ts = {0};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

int open_udp_socket_for_rx(int port, int rcv_buf_size)
{
    struct sockaddr_in saddr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        fprintf(stderr,"Error opening socket: %s", strerror(errno));
        exit(-1);
    }

    const int optval = 1;
    if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(optval)) !=0)
    {
        fprintf(stderr,"Unable to set SO_REUSEADDR: %s", strerror(errno));
        exit(-1);
    }

    if(setsockopt(fd, SOL_SOCKET, SO_RXQ_OVFL, (const void *)&optval , sizeof(optval)) != 0)
    {
        fprintf(stderr,"Unable to set SO_RXQ_OVFL: %s", strerror(errno));
        exit(-1);
    }

    if (rcv_buf_size > 0)
    {
        if(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const void *)&rcv_buf_size , sizeof(rcv_buf_size)) !=0)
        {
            fprintf(stderr,"Unable to set SO_RCVBUF: %s", strerror(errno));
            exit(-1);
        }
    }

    bzero((char *) &saddr, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    saddr.sin_port = htons((unsigned short)port);

    if (bind(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
    {
        fprintf(stderr,"Bind error: %s", strerror(errno));
        exit(-1);
    }
    return fd;
}




void WFB_make_session_key(void)
{
    // init session key
    randombytes_buf(session_key, sizeof(session_key));

    // fill packet header
    wsession_hdr_t *session_hdr = (wsession_hdr_t *)session_key_packet;
    session_hdr->packet_type = WFB_PACKET_KEY;

    randombytes_buf(session_hdr->session_nonce, sizeof(session_hdr->session_nonce));

    // fill packet contents
    wsession_data_t session_data = { .epoch = htobe64(epoch),
                                     .channel_id = htobe32(channel_id),
                                     .fec_type = WFB_FEC_VDM_RS,
                                     .k = (uint8_t)fec_k,
                                     .n = (uint8_t)fec_n,
                                   };

    memcpy(session_data.session_key, session_key, sizeof(session_key));

    if (crypto_box_easy(session_key_packet + sizeof(wsession_hdr_t),
                        (uint8_t*)&session_data, sizeof(session_data),
                        session_hdr->session_nonce, rx_publickey, tx_secretkey) != 0)
    {
        fprintf(stderr,"Unable to make session key!");
        exit(-1);
    }
}




void WFB_inject_packet(const uint8_t *buf, size_t size)
{
    uint8_t txbuf[MAX_PACKET_SIZE];
    uint8_t *p = txbuf;

    assert(size <= MAX_FORWARDER_PACKET_SIZE);

    // radiotap header
    memcpy(p, radiotap_header, sizeof(radiotap_header));
    p += sizeof(radiotap_header);

    // ieee80211 header
    memcpy(p, ieee80211_header, sizeof(ieee80211_header));

    // channel_id
    uint32_t channel_id_be = htobe32(channel_id);
    memcpy(p + SRC_MAC_THIRD_BYTE, &channel_id_be, sizeof(uint32_t));
    memcpy(p + DST_MAC_THIRD_BYTE, &channel_id_be, sizeof(uint32_t));

    // sequence number
    p[FRAME_SEQ_LB] = ieee80211_seq & 0xff;
    p[FRAME_SEQ_HB] = (ieee80211_seq >> 8) & 0xff;
    ieee80211_seq += 16;
    p += sizeof(ieee80211_header);

    // FEC data
    memcpy(p, buf, size);
    p += size;

        // Normal mode
        if (pcap_inject(ppcap, txbuf, p - txbuf) != p - txbuf)
        {
            fprintf(stderr, "Unable to inject packet");
            exit(-1);
        }
    
}


void WFB_send_block_fragment(size_t packet_size)
{
    uint8_t ciphertext[MAX_FORWARDER_PACKET_SIZE];
    wblock_hdr_t *block_hdr = (wblock_hdr_t*)ciphertext;
    long long unsigned int ciphertext_len;

    assert(packet_size <= MAX_FEC_PAYLOAD);

    block_hdr->packet_type = WFB_PACKET_DATA;
    block_hdr->data_nonce = htobe64(((block_idx & BLOCK_IDX_MASK) << 8) + fragment_idx);

    // encrypted payload
    if (crypto_aead_chacha20poly1305_encrypt(ciphertext + sizeof(wblock_hdr_t), &ciphertext_len,
                                             block[fragment_idx], packet_size,
                                             (uint8_t*)block_hdr, sizeof(wblock_hdr_t),
                                             NULL, (uint8_t*)(&(block_hdr->data_nonce)), session_key) < 0)
        {
        fprintf(stderr, "Unable to encrypt packet!");
        exit(-1);
        }

    WFB_inject_packet(ciphertext, sizeof(wblock_hdr_t) + ciphertext_len);
}

void WFB_send_session_key(void)
{
    //fprintf(stderr, "Announce session key\n");
    WFB_inject_packet((uint8_t*)session_key_packet, sizeof(session_key_packet));
}

void WFB_send_packet(const uint8_t *buf, size_t size, uint8_t flags)
{
    wpacket_hdr_t packet_hdr;
    assert(size <= MAX_PAYLOAD_SIZE);

    // FEC-only packets are only for closing already opened blocks
    if (fragment_idx == 0 && flags & WFB_PACKET_FEC_ONLY)
    {
        return;
    }

    packet_hdr.packet_size = htobe16(size);
    packet_hdr.flags = flags;
    memset(block[fragment_idx], '\0', MAX_FEC_PAYLOAD);
    memcpy(block[fragment_idx], &packet_hdr, sizeof(packet_hdr));
    memcpy(block[fragment_idx] + sizeof(packet_hdr), buf, size);

    WFB_send_block_fragment(sizeof(packet_hdr) + size);
    
    max_packet_size = max_packet_size > sizeof(packet_hdr) + size ? max_packet_size : sizeof(packet_hdr) + size;
    
    
    fragment_idx += 1;

    if (fragment_idx < fec_k)  return;

    fec_encode(fec_p, (const uint8_t**)block, block + fec_k, max_packet_size);
    while (fragment_idx < fec_n)
    {
        WFB_send_block_fragment(max_packet_size);
        fragment_idx += 1;
    }
    block_idx += 1;
    fragment_idx = 0;
    max_packet_size = 0;

    // Generate new session key after MAX_BLOCK_IDX blocks
    if (block_idx > MAX_BLOCK_IDX)
    {
        WFB_make_session_key();
        WFB_send_session_key();
        block_idx = 0;
    }
}

// Extract SO_RXQ_OVFL counter
uint32_t extract_rxq_overflow(struct msghdr *msg)
{
    struct cmsghdr *cmsg;
    uint32_t rtn;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_RXQ_OVFL) {
            memcpy(&rtn, CMSG_DATA(cmsg), sizeof(rtn));
            return rtn;
        }
    }
    return 0;
}

void WFB_InitTx(int k, int n, char *keypair, uint64_t epo, uint32_t ch_id, char * wlan)
    {
    fec_k = k;
    fec_n = n;
    block_idx = 0;
    fragment_idx = 0;
    max_packet_size = 0;
    epoch = epo;
    channel_id = ch_id;
    fec_p = fec_new(fec_k, fec_n);

//    block = uint8_t*[fec_n];

    for(int i=0; i < fec_n; i++)
    {
        block[i] = malloc(MAX_FEC_PAYLOAD);
    }

    FILE *fp;
    if ((fp = fopen(keypair, "r")) == NULL)
    {
        fprintf(stderr,"Unable to open %s: %s", keypair, strerror(errno));
        exit(-1);
    }
    if (fread(tx_secretkey, crypto_box_SECRETKEYBYTES, 1, fp) != 1)
    {
        fclose(fp);
        fprintf(stderr,"Unable to read tx secret key: %s", strerror(errno));
        exit(-1);
    }
    if (fread(rx_publickey, crypto_box_PUBLICKEYBYTES, 1, fp) != 1)
    {
        fclose(fp);
        fprintf(stderr,"Unable to read rx public key: %s", strerror(errno));
        exit(-1);
    }
    fclose(fp);

    current_output = 0;
    ieee80211_seq = 0;


    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_create(wlan, errbuf);
    
    if (p == NULL){fprintf(stderr, "Unable to open interface %s in pcap: %s", wlan, errbuf); exit(-1);}
    if (pcap_set_snaplen(p, 4096) !=0) {fprintf(stderr, "set_snaplen failed"); exit(-1);}
    if (pcap_set_promisc(p, 1) != 0) {fprintf(stderr, "set_promisc failed"); exit(-1);}
    if (pcap_set_timeout(p, -1) !=0) {fprintf(stderr, "set_timeout failed"); exit(-1);}
    if (pcap_set_immediate_mode(p, 1) != 0) {fprintf(stderr, "pcap_set_immediate_mode failed: %s", pcap_geterr(p)); exit(-1);}
    if (pcap_activate(p) !=0) {fprintf(stderr, "pcap_activate failed: %s", pcap_geterr(p)); exit(-1);}
       
    ppcap = p;
    
    WFB_make_session_key();
}

void WFB_ClearTx()
{
    for(int i=0; i < fec_n; i++)
    {
        free(block[i]);
    }

    fec_free(fec_p);
    pcap_close(ppcap);
}



void WFB_data_source(int rx_fd, int poll_timeout)
{
    struct pollfd fds = {0};

    if (fcntl(rx_fd, F_SETFL, fcntl(rx_fd, F_GETFL, 0) | O_NONBLOCK) < 0)

        {
        fprintf(stderr, "Unable to set socket into nonblocked mode: %s", strerror(errno));
        exit(-1);
        }

    fds.fd = rx_fd;
    fds.events = POLLIN;

    uint64_t session_key_announce_ts = 0;
    uint32_t rxq_overflow = 0;

    for(;;)
    {
        int rc = poll(&fds, 1, poll_timeout > 0 ? poll_timeout : -1);

        if (rc < 0)
        
        
        {
            if (errno == EINTR || errno == EAGAIN) continue;
            fprintf(stderr, "poll error: %s", strerror(errno));
            exit(-1);
        }

        if (rc == 0) // timeout expired
        {
            WFB_send_packet(NULL, 0, WFB_PACKET_FEC_ONLY);
            continue;
        }

        if (fds.revents & (POLLERR | POLLNVAL))
            {
            fprintf(stderr, "socket error: %s", strerror(errno));
            exit(-1);
            }

        if (fds.revents & POLLIN)
            {
            uint8_t buf[MAX_PAYLOAD_SIZE + 1];
            ssize_t rsize;
            uint8_t cmsgbuf[CMSG_SPACE(sizeof(uint32_t))];


                for(;;)
                {
                    struct iovec iov = { .iov_base = (void*)buf,
                                         .iov_len = sizeof(buf) };

                    struct msghdr msghdr = { .msg_name = NULL,
                                             .msg_namelen = 0,
                                             .msg_iov = &iov,
                                             .msg_iovlen = 1,
                                             .msg_control = &cmsgbuf,
                                             .msg_controllen = sizeof(cmsgbuf),
                                             .msg_flags = 0 };

                    memset(cmsgbuf, '\0', sizeof(cmsgbuf));

                    if ((rsize = recvmsg(rx_fd, &msghdr, 0)) < 0)
                    {
                        break;
                    }

                    if (rsize > (ssize_t)MAX_PAYLOAD_SIZE)
                    {
                        fprintf(stderr, "Incoming packet size > %u and will be truncated\n", MAX_PAYLOAD_SIZE);
                        rsize = MAX_PAYLOAD_SIZE;
                    }

                    uint32_t cur_rxq_overflow = extract_rxq_overflow(&msghdr);
                    
                    if (cur_rxq_overflow != rxq_overflow)
                    {
                        fprintf(stderr, "UDP rxq overflow: %u packets dropped\n", cur_rxq_overflow - rxq_overflow);
                        rxq_overflow = cur_rxq_overflow;
                    }

                    uint64_t cur_ts = get_time_ms();
                    if (cur_ts >= session_key_announce_ts)
                    {
                        // Announce session key
                        WFB_send_session_key();
                        session_key_announce_ts = cur_ts + SESSION_KEY_ANNOUNCE_MSEC;
                    }
                    WFB_send_packet(buf, rsize, 0);
                }
                if (errno != EWOULDBLOCK)
                    {
                    fprintf(stderr, "Error receiving packet: %s", strerror(errno));
                    exit(-1);
                    }
                
           // }
        }
    }
}


int main(int argc, char * const *argv)
{
    int opt;
    uint8_t k=8, n=12, radio_port=0;
    uint32_t link_id = 0x0;
    uint64_t epoch = 0;
    int udp_port=5600;

    int bandwidth = 20;
    int short_gi = 0;
    int stbc = 0;
    int ldpc = 0;
    int mcs_index = 1;
    int poll_timeout = 0;
    int rcv_buf = 0;
    char keypair[32+1] = "tx.key";

    while ((opt = getopt(argc, argv, "K:k:n:u:p:B:G:S:L:M:D:T:i:e:R:f:m")) != -1) {
        switch (opt) {
        case 'K':
            strncpy(keypair, optarg, 32);
            break;
        case 'k':
            k = atoi(optarg);
            break;
        case 'n':
            n = atoi(optarg);
            break;
        case 'u':
            udp_port = atoi(optarg);
            break;
        case 'p':
            radio_port = atoi(optarg);
            break;
        case 'R':
            rcv_buf = atoi(optarg);
            break;
        case 'B':
            bandwidth = atoi(optarg);
            break;
        case 'G':
            short_gi = (optarg[0] == 's' || optarg[0] == 'S') ? 1 : 0;
            break;
        case 'S':
            stbc = atoi(optarg);
            break;
        case 'L':
            ldpc = atoi(optarg);
            break;
        case 'M':
            mcs_index = atoi(optarg);
            break;
//        case 'D':
//            debug_port = atoi(optarg);
//            break;
        case 'T':
            poll_timeout = atoi(optarg);
            break;
        case 'i':
            link_id = ((uint32_t)atoi(optarg)) & 0xffffff;
            break;
        case 'e':
            epoch = atoll(optarg);
            break;
        case 'm':
            // mirror = true;
            break;
        case 'f':
            if (strcmp(optarg, "data") == 0)
            {
                fprintf(stderr, "Using data frames\n");
                ieee80211_header[0] = FRAME_TYPE_DATA;
            }
            else if (strcmp(optarg, "rts") == 0)
            {
                fprintf(stderr, "Using rts frames\n");
                ieee80211_header[0] = FRAME_TYPE_RTS;
            }
            else
            {
                fprintf(stderr, "Invalid frame type: %s\n", optarg);
                exit(1);
            }
            break;
        default: /* '?' */
        show_usage:
            fprintf(stderr, "Usage: %s [-K tx_key] [-k RS_K] [-n RS_N] [-u udp_port] [-R rcv_buf] [-p radio_port] [-B bandwidth] [-G guard_interval] [-S stbc] [-L ldpc] [-M mcs_index] [-T poll_timeout] [-e epoch] [-i link_id] [-f { data | rts }] [ -m ] interface1 [interface2] ...\n",
                    argv[0]);
            fprintf(stderr, "Default: K='%s', k=%d, n=%d, udp_port=%d, link_id=0x%06x, radio_port=%u, epoch=%" PRIu64 ", bandwidth=%d guard_interval=%s stbc=%d ldpc=%d mcs_index=%d, poll_timeout=%d, rcv_buf=system_default, frame_type=data, mirror=false\n",
                    keypair, k, n, udp_port, link_id, radio_port, epoch, bandwidth, short_gi ? "short" : "long", stbc, ldpc, mcs_index, poll_timeout);
            fprintf(stderr, "Radio MTU: %lu\n", (unsigned long)MAX_PAYLOAD_SIZE);
            fprintf(stderr, "WFB-ng pure C version\n");

            exit(1);
        }
    }

    if (optind >= argc) {
        goto show_usage;
    }

    // Set flags in radiotap header
    {
        uint8_t flags = 0;
        switch(bandwidth) {
        case 20:
            flags |= IEEE80211_RADIOTAP_MCS_BW_20;
            break;
        case 40:
            flags |= IEEE80211_RADIOTAP_MCS_BW_40;
            break;
        default:
            fprintf(stderr, "Unsupported bandwidth: %d\n", bandwidth);
            exit(1);
        }

        if (short_gi)
        {
            flags |= IEEE80211_RADIOTAP_MCS_SGI;
        }

        switch(stbc) {
        case 0:
            break;
        case 1:
            break;
            flags |= (IEEE80211_RADIOTAP_MCS_STBC_1 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT);
        case 2:
            flags |= (IEEE80211_RADIOTAP_MCS_STBC_2 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT);
            break;
        case 3:
            flags |= (IEEE80211_RADIOTAP_MCS_STBC_3 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT);
            break;
        default:
            fprintf(stderr, "Unsupported STBC type: %d\n", stbc);
            exit(1);
        }

        if (ldpc)
        {
            flags |= IEEE80211_RADIOTAP_MCS_FEC_LDPC;
        }

        radiotap_header[MCS_FLAGS_OFF] = flags;
        radiotap_header[MCS_IDX_OFF] = mcs_index;
    }

    {
        int fd;
        int c;

        if ((fd = open("/dev/random", O_RDONLY)) != -1) {
            if (ioctl(fd, RNDGETENTCNT, &c) == 0 && c < 160) {
                fprintf(stderr, "This system doesn't provide enough entropy to quickly generate high-quality random numbers.\n"
                        "Installing the rng-utils/rng-tools, jitterentropy or haveged packages may help.\n"
                        "On virtualized Linux environments, also consider using virtio-rng.\n"
                        "The service will not start until enough entropy has been collected.\n");
            }
            (void) close(fd);
        }
    }

    if (sodium_init() < 0)
    {
        fprintf(stderr, "Libsodium init failed\n");
        return 1;
    }

        int rx_fd;
        char wlan[32+1];
        int fd = open_udp_socket_for_rx(udp_port, rcv_buf);

        strncpy (wlan, argv[optind], 32);
        rx_fd = fd;
        fprintf(stderr, "Pure C wfb_tx port\n");
        fprintf(stderr, "Listen on %d for %s\n", udp_port, wlan);
            



        uint32_t channel_id = (link_id << 8) + radio_port;

        WFB_InitTx(k, n, keypair, epoch, channel_id, wlan);
        WFB_data_source(rx_fd, poll_timeout);
        WFB_ClearTx();   // не выполняется на аварийном выходе !!!

    return 0;
}
