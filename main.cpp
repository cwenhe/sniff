
#include <arpa/inet.h>
#include <google/protobuf/util/json_util.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#include "filters.pb.h"

static const auto TCP  = 0x06;
static const auto UDP  = 0x11;
static const auto ICMP = 0x01;
static const auto GRE  = 0x2f;
static const auto ESP  = 0x50;
static const auto IPIP = 0x94;

void printHeader(const struct ip *message, Filters *filter) {
    bool need_print = nullptr != filter;
    if (filter) {
        for (auto f : filter->datas()) {
            if (!f.dst_ip().empty() && f.dst_ip() != inet_ntoa(message->ip_dst)) {
                return;
            }
        }
        need_print = true;
    }

    if (need_print) {
        if (TCP == message->ip_p) {
            auto tcp      = (struct tcphdr *)(message + 1);
            auto src_port = ntohs(tcp->th_sport);
            auto dst_port = ntohs(tcp->th_dport);
            std::stringstream data;
            data << "IP verion = " << message->ip_v << ", Header Lenth:" << message->ip_hl * 4 << ", Type of Service:" << message->ip_tos
                 << ", Total Length:" << ntohs(message->ip_len) << ", TTL:" << (int)message->ip_ttl << ", Protocol:" << (int)message->ip_p
                 << ", Source IP:" << inet_ntoa(message->ip_src) << ":" << src_port << ", Destination IP:" << inet_ntoa(message->ip_dst) << ":" << dst_port
                 << "\n";

            std::cout << data.str();
        }
    }
}

std::unique_ptr<Filters> loadConf() {
    auto conf_file = std::string("./filter.json");
    if (std::filesystem::exists(conf_file)) {
        std::fstream stream(conf_file, std::ios::in | std::ios::binary);
        auto f = std::make_unique<Filters>();
        // if (f->ParseFromIstream(&stream)) {
        std::string data((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        // std::cout << data;
        if (google::protobuf::util::JsonStringToMessage(data, f.get()).ok())
            return f;
    }
    return {};
}

int main(int argc, char *argv[]) {
    // auto f = std::make_unique<Filters>();
    // Filter ff;
    // ff.set_dst_ip("dst_ip");
    // ff.set_src_ip("src_ip");
    // f->mutable_datas()->Add(std::move(ff));

    // auto conf_file = std::string("./filter.conf");
    // std::fstream stream(conf_file, std::ios::out | std::ios::binary);
    // std::string x;
    // google::protobuf::util::MessageToJsonString(*f, &x);
    // std::cout << x;

    // return 0;

    auto conf = loadConf();
    // std::string x;
    // google::protobuf::util::MessageToJsonString(*conf, &x);
    // std::cout << x;

    // ETH_P_ALL
    auto sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    assert(-1 != sock_fd);

    struct sockaddr_ll addr;
    addr.sll_family   = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex  = if_nametoindex("ens192");

    // 绑定到具体端口
    bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr));

    // 设置ring buffer大小，开启抓包功能
    // int rx_ring_size = 1000;
    // setsockopt(sock_fd, SOL_PACKET, PACKET_RX_RING, &rx_ring_size, sizeof(rx_ring_size));
    // int opt = 1;
    // ioctl(sock_fd, PACKET_MR_PROMISC, &opt);
    size_t count = 0;
    while (true) {
        char buf[4096];
        struct sockaddr_ll from;
        socklen_t from_len = sizeof(from);
        auto len           = recvfrom(sock_fd, buf, sizeof(buf), 0, (sockaddr *)&from, &from_len);
        if (len < 0) {
            continue;
        }
        auto x = (struct ip *)(buf + sizeof(ether_header));
        if (0 != x->ip_hl) {
            // if (++count > 100) {
            //     break;
            // }
            printHeader(x, conf.get());
        }
    }
    return 0;
}
