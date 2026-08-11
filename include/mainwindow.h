#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <vector>
#include <QTableWidget>
#include <memory>
#include "getthread.h"
#include "arpattack.h"
#include "sendarp.h"
#include "ip_info.h"
#include "icmpflood.h"
#include "smurf.h"
#include "network_utils.h"
#include "ip_location_service.h"

#include <qfileinfo.h>
#include <QJsonParseError>

struct Packet_Info{
    int row;
    int proto_flag;
    QString srcmac;
    QString desmac;

    QString srcip;
    QString desip;
    QString ipversion;
    QString TTL;
    QString iplength;
    QString ipchecksum;

    QString arp_HardwareType;
    QString arp_ProtocolType;

    QString srcport;
    QString desport;
    QString udp_length;
    QString tcp_udp_checksum;
    QString tcp_acknum;
    QString tcp_seq;
    QString tcp_windowsize;

    QString icmp_type;
    QString icmp_code;
    QString icmp_checksum;
};

// Packet count statistics
struct count_info{
    long total;
    long ip_num;
    long arp_num;
    long tcp_num;
    long udp_num;
    long icmp_num;
};

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    getthread thread;
    arpAttack arpthread;
    sendarp spkt;
    std::unique_ptr<icmpflood> icmpf;
    std::unique_ptr<smurf> smf;
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    // Override timer event
     void timerEvent(QTimerEvent *);
     void get_ip_bydomin();
     void show_hosts();
     void init_UI();
     void init_data();
private slots:
     void on_startbtn_clicked();
     void on_stopbtn_clicked();
     void on_getallbtn_clicked();
     void on_usebtn_clicked();
     void on_btn_des_mac_reset_clicked();
     void on_btn_src_ip_gateway_clicked();
     void on_btn_src_mac_local_clicked();
     void on_btn_arp_start_clicked();
     void on_btn_arp_end_clicked();
     void on_btn_reflush_ips_clicked();
     void on_btn_clear_ips_clicked();
     void on_btn_default_ips_clicked();
     void on_btn_q_query_clicked();
     void on_btn_clear_log_clicked();
     void on_btn_clear_sniffer_clicked();
     void on_btn_icmpflood_clicked();
     void on_btn_icmp_localhost_clicked();
     void on_btn_smurf_start_clicked();
     void changeString(int,QVariant,QVariant,QVariant,QVariant,QVariant,QVariant);
     void changeHost(QString);
     void writelog();
     void on_tableWidget_itemClicked(QTableWidgetItem *item);
     void on_hosts_itemClicked(QTableWidgetItem *item);
     // Slot for IP location query results
     void onIpInfoReady(const ipinfo& info);
     void onIpQueryFailed(const QString& errorMsg);
private:
    Ui::MainWindow *ui;
    std::vector<Packet_Info> packet_vector;
    std::vector<std::vector<std::string>>  hosts_vector;
    count_info packet_count;
    char gateway_addr[15]={0};
    unsigned char if_mac[6];
    char src_ip[20];
    char des_ip[20];
    char* if_dev;
    QString current_date;
    // IP location service (extracted from MainWindow)
    IpLocationService* m_ipLocationService;
};

#endif // MAINWINDOW_H
