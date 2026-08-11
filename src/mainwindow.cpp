/*
* Module: Main window implementation
* Author: muzinan
* Refactored: Network utils and IP location service extracted to separate classes,
*             signal/slot modernized, smart pointers for attack objects
*/
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "getthread.h"
#include "arpattack.h"
#include "protocol_headers.h"
#include "network_utils.h"
#include "ip_location_service.h"

#include <QFile>
#include <QTextStream>
#include <QVariant>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QLabel>
#include <QMessageBox>
#include <QDebug>
#include <arpa/inet.h>
#include <sstream>
#include <QString>
#include <QTableWidget>
#include <iostream>
#include <pcap.h>
#include <QDateTime>

#include <QMouseEvent>
#include <QMovie>
#include <QIcon>
#include <QString>
#include <qfileinfo.h>
#include <QUrlQuery>

#include <QProxyStyle>
#include <QPainter>
using namespace std;

class GradientButtonStyle : public QProxyStyle
{
public:
    GradientButtonStyle(QStyle* style = nullptr) : QProxyStyle(style) {}

    void drawPrimitive(PrimitiveElement element, const QStyleOption* option, QPainter* painter, const QWidget* widget) const override
    {
        if (element == PE_PanelButtonCommand)
        {
            const QStyleOptionButton* buttonOption = qstyleoption_cast<const QStyleOptionButton*>(option);

            if (buttonOption && buttonOption->features & QStyleOptionButton::Flat)
            {
                QRect rect = buttonOption->rect;
                QColor color1(170, 0, 0);
                QColor color2(255, 170, 0);
                QLinearGradient gradient(rect.topLeft(), rect.bottomLeft());
                gradient.setColorAt(0, color1);
                gradient.setColorAt(1, color2);

                painter->save();
                painter->setBrush(gradient);
                painter->setPen(Qt::NoPen);
                painter->drawRoundedRect(rect.adjusted(0, 0, -1, -1), 5, 5);
                painter->restore();
            }

            return;
        }

        QProxyStyle::drawPrimitive(element, option, painter, widget);
    }
};

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{

    resize(900,800);

    setFixedSize(900,800);

    ui->setupUi(this);

    setWindowIcon(QIcon(":/new/imgs/img/10001.png"));

    setWindowTitle("one-eye@muzinan");

    //set timer
    startTimer(1000);
    //init ui
    init_UI();
    //init data
    init_data();

       connect(ui->actionsave,&QAction::triggered,this,[=](){
               if(QMessageBox::Save== QMessageBox::question(this,"ques","save packets？",QMessageBox::Save|QMessageBox::Cancel,QMessageBox::Cancel )){
                   cout<<"save file"<<endl;
               }
       });

        qRegisterMetaType<QVariant>("QVariant");

        // Modernized signal/slot connections (function pointer style)
        connect(&thread, &getthread::stringChanged,
           this, &MainWindow::changeString);

        connect(&arpthread, &arpAttack::get_host, this, &MainWindow::changeHost);
        connect(&spkt, &sendarp::writelog, this, &MainWindow::writelog);

        packet_count={0,0,0,0,0,0};

        // IP location service (extracted from MainWindow)
        m_ipLocationService = new IpLocationService(this);
        connect(m_ipLocationService, &IpLocationService::ipInfoReady, this, &MainWindow::onIpInfoReady);
        connect(m_ipLocationService, &IpLocationService::queryFailed, this, &MainWindow::onIpQueryFailed);
}
void MainWindow::init_UI(){
    //set table
    ui->tableWidget->setColumnCount(4);
    ui->tableWidget->setHorizontalHeaderLabels(QStringList()<<"Source"<<"Destination"<<"length"<<"Protocol");
    ui->tableWidget->setRowCount(0);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tableWidget->setColumnWidth(0,150);
    ui->tableWidget->setColumnWidth(1,150);
    ui->tableWidget->setColumnWidth(2,150);
    ui->tableWidget->setColumnWidth(3,150);
    //set table
    ui->hosts->setColumnCount(6);
    ui->hosts->setHorizontalHeaderLabels(QStringList()<<"IP address"<<"HW_type"<<"Flags"<<"HW_address"<<"Mask"<<"Device");
    ui->hosts->setRowCount(0);
    ui->hosts->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->hosts->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->hosts->setColumnWidth(0,150);
    ui->hosts->setColumnWidth(1,150);
    ui->hosts->setColumnWidth(2,50);
    ui->hosts->setColumnWidth(3,150);
    ui->hosts->setColumnWidth(4,150);
    ui->hosts->setColumnWidth(5,150);
}
void MainWindow::init_data(){
    //get interface ip and mask
        char error_content[PCAP_ERRBUF_SIZE];
        struct in_addr net_ip_address;
        struct in_addr net_mask_address;
        char* net_interface;
        char* net_ip_string;
        char* net_mask_string;
        u_int32_t net_ip;
        u_int32_t net_mask;
        net_interface = pcap_lookupdev(error_content);
        QString network=QString(QLatin1String(net_interface));
        pcap_lookupnet(net_interface,&net_ip,&net_mask,error_content);
        net_ip_address.s_addr=net_ip;
        net_ip_string=inet_ntoa(net_ip_address);
        QString ip=QString(QLatin1String(net_ip_string));
        net_mask_address.s_addr=net_mask;
        net_mask_string=inet_ntoa(net_mask_address);
        QString mask=QString(QLatin1String(net_mask_string));

        //get interface
       connect(ui->actionnet_interface,&QAction::triggered,this,[=](){
             QMessageBox::question(this,"tips","network interface:"+network+"\n"+"Network IP Address:"
                                    +ip+"\n"+"Network Mask Address:"+mask);
        });
}
QString Qstringtomac(QString mac){
    char res[18]={0};
    char* src=const_cast<char*>(mac.toStdString().c_str());
    int num=0;
    int len=strlen(src);
    if(len<12){
        return "";
    }
    int index=0;
    if(len){
        while(len!=0){
            if(num==2){
                res[index]=':';
                index++;
                num=0;
                continue;
            }
            res[index]=*src;
            src++;
            index++;
            num++;
            len--;
            if(len<2)num=0;
        }
        res[index]='\0';
    }
    QString str(res);
    return str;
}
QString mactoQstring(u_int8_t ether_shost[6])
{
    QString str="";
    u_char* temp;
    temp=ether_shost;
    char*mac;
    char mac_string[2];
    for(int i=0;i<5;i++)
    {
        sprintf(mac_string,"%02x",*temp);
        str+=mac_string[0];
        str+=mac_string[1];
        temp++;
    }
    sprintf(mac_string,"%02x",*temp);
    str+=mac_string[0];
    str+=mac_string[1];
    return str;
}
void MainWindow::on_btn_clear_sniffer_clicked(){
    while (ui->tableWidget->rowCount()>0)
    {
        ui->tableWidget->removeRow(0);
    }
    packet_vector.clear();
    packet_count={0,0,0,0,0,0};

    QString qstr("");
    qstr=QString::number(packet_count.arp_num);
    ui->ct_arp->setText(qstr);

    qstr=QString::number(packet_count.total);
    ui->ct_total->setText(qstr);

    qstr=QString::number(packet_count.icmp_num);
    ui->ct_icmp->setText(qstr);

    qstr=QString::number(packet_count.ip_num);
    ui->ct_ip->setText(qstr);

    qstr=QString::number(packet_count.tcp_num);
    ui->ct_tcp->setText(qstr);

    qstr=QString::number(packet_count.udp_num);
    ui->ct_udp->setText(qstr);
}
void MainWindow::on_btn_clear_log_clicked(){
    ui->list_log->clear();
}
void MainWindow::on_btn_des_mac_reset_clicked(){
    ui->line_des_mac->setText(QString(""));
}
void MainWindow::on_btn_src_ip_gateway_clicked(){
    // Gateway logic extracted to NetworkUtils::getGateway()
    QString gateway = NetworkUtils::getGateway();
    strcpy(gateway_addr, gateway.toLatin1().data());
    qDebug()<<gateway_addr<<endl;
    ui->line_src_ip->setText(gateway_addr);
}
void MainWindow::on_btn_src_mac_local_clicked(){
    QString dev=ui->all->currentText();
    NetworkUtils::getMAC((char*)if_mac, string(dev.toStdString()).c_str());
    ui->line_src_mac->setText(QString((char*)if_mac));
}
void MainWindow::on_btn_arp_start_clicked(){
        ui->btn_arp_start->setEnabled(false);
        ui->btn_arp_end->setEnabled(true);
        QString dev=ui->all->currentText();
        if_dev=const_cast<char*>(dev.toStdString().c_str());
        if(!this->spkt.isRunning())
        {
             char op;
             if(ui->comboBox->currentText() == "unicast")
             {
                    op = 'a';
                    qDebug()<<"unicast"<<endl;
             }
             else if(ui->comboBox->currentText() == "broadcast")
             {
                    op = 'c';
                    ui->line_des_mac->setText("FF:FF:FF:FF:FF:FF");
                    qDebug()<<"broadcast"<<endl;
             }
             else {
                 op = 'b';
                 qDebug()<<"broadcast_req"<<endl;
             }
             QString old_eth_dst_mac=ui->line_des_mac->text();
             if(old_eth_dst_mac.length()<16){
                 ui->line_des_mac->setText(Qstringtomac(old_eth_dst_mac));
             }
             QString old_src_mac=ui->line_src_mac->text();
             if(old_src_mac.length()<16){
                 ui->line_src_mac->setText(Qstringtomac(old_src_mac));
             }
             unsigned char eth_src_mac[6],eth_dst_mac[6],src_mac[6] = {0};
             spkt.Qs2uc(ui->att_mac->text(),eth_src_mac);//localmac
             spkt.Qs2uc(ui->line_des_mac->text(),eth_dst_mac);
             spkt.Qs2uc(ui->line_src_mac->text(),src_mac);
             char* src_ip_str = const_cast<char*>(ui->line_src_ip->text().toStdString().c_str());
             char* dst_ip_str = const_cast<char*>(ui->line_des_ip->text().toStdString().c_str());
             spkt.getParam(this->if_dev,op,src_mac,src_ip_str,eth_dst_mac,dst_ip_str,eth_dst_mac,eth_src_mac);
             spkt.start();
      }
}
void MainWindow::on_btn_arp_end_clicked(){
    if(spkt.isRunning())
    {
        spkt.terminate();
    }
    ui->btn_arp_start->setEnabled(true);
    ui->btn_arp_end->setEnabled(false);
}
void MainWindow::on_btn_reflush_ips_clicked(){
    while (ui->hosts->rowCount()>0)
    {
        ui->hosts->removeRow(0);
    }
    if(!ui->line_ip_seg->text().isEmpty())
    {
        qDebug()<<"start scan ips"<<endl;
        arpthread.setscan_ips(const_cast<char*>(ui->line_ip_seg->text().toStdString().c_str()));
        if(!arpthread.isRunning()){
            arpthread.start();
        }
    }
    else
    {

        arpthread.reflush_ips();
    }
}

void MainWindow::on_btn_default_ips_clicked(){
    arpthread.reflush_ips();
}
void MainWindow::on_btn_clear_ips_clicked(){
    while (ui->hosts->rowCount()>0)
    {
        ui->hosts->removeRow(0);
    }
}
void MainWindow::timerEvent(QTimerEvent *)
{
    static int num=1;
    QDateTime current_date_time =QDateTime::currentDateTime();
    current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz ddd");
    ui->label_time->setText(current_date);
}
void MainWindow::on_startbtn_clicked(){
    QString filter_str =  ui->textEdit->toPlainText();
    thread.set_filter(filter_str);
    if (!thread.isRunning()){
        thread.start();
    }
    ui->startbtn->setEnabled(false);
    ui->stopbtn->setEnabled(true);
}
void MainWindow::on_stopbtn_clicked(){
    if(thread.isRunning())
    {
        thread.stop();
    }
    ui->startbtn->setEnabled(true);
    ui->stopbtn->setEnabled(false);

}
void MainWindow::changeString(int protocol_flag,QVariant ipdata,QVariant arpdata,QVariant tcpdata,QVariant udpdata,QVariant icmpdata,QVariant etherdata)
{
    ip_header Ipdata=ipdata.value<ip_header>();
    arp_header Arpdata=arpdata.value<arp_header>();
    tcp_header Tcpdata=tcpdata.value<tcp_header>();
    udp_header Udpdata=udpdata.value<udp_header>();
    icmp_header Icmpdata=icmpdata.value<icmp_header>();
    ether_header Etherdata=etherdata.value<ether_header>();

    Packet_Info packet_info;
    stringstream stream;
    QString qstr("");

    int row=ui->tableWidget->rowCount();
    ui->tableWidget->insertRow(row);

    if(protocol_flag==ip || protocol_flag ==tcp || protocol_flag == udp || protocol_flag == icmp  )
    {
        stream.str("");
        stream<< inet_ntoa(Ipdata.ip_source_address);
        qstr=QString::fromStdString(stream.str());
        ui->tableWidget->setItem(row,0,new QTableWidgetItem(qstr));
        packet_info.srcip=qstr;

        stream.str("");
        stream<< inet_ntoa(Ipdata.ip_destination_address);
        qstr=QString::fromStdString(stream.str());
        ui->tableWidget->setItem(row,1,new QTableWidgetItem(qstr));
        packet_info.desip=qstr;

        stream.str("");
        stream<<(int)Ipdata.ip_version;
        qstr=QString::fromStdString(stream.str());
        packet_info.ipversion=qstr;

        stream.str("");
        stream<<(int)Ipdata.ip_length;
        qstr=QString::fromStdString(stream.str());
        ui->tableWidget->setItem(row,2,new QTableWidgetItem(qstr));
        packet_info.iplength=qstr;

        stream.str("");
        stream<<(int)Ipdata.ip_checksum;
        qstr=QString::fromStdString(stream.str());
        packet_info.ipchecksum=qstr;

    }
    else if(protocol_flag == arp)
    {
        stream.str("");
        stream<<(int)Arpdata.arp_hardware_type;
        qstr=QString::fromStdString(stream.str());
        packet_info.arp_HardwareType=qstr;

        stream.str("");
        stream<<(int)Arpdata.arp_protocol_type;
        qstr=QString::fromStdString(stream.str());
        packet_info.arp_ProtocolType=qstr;

        stream.str("");
        stream<< inet_ntoa(Arpdata.arp_source_ip_address);
        qstr=QString::fromStdString(stream.str());
        ui->tableWidget->setItem(row,0,new QTableWidgetItem(qstr));
        packet_info.srcip=qstr;

        stream.str("");
        stream<< inet_ntoa(Arpdata.arp_destination_ip_address);
        qstr=QString::fromStdString(stream.str());
        ui->tableWidget->setItem(row,1,new QTableWidgetItem(qstr));
        packet_info.desip=qstr;

        ui->tableWidget->setItem(row,2,new QTableWidgetItem(QString::number(28)));
    }
    packet_count.total++;

    switch(protocol_flag)
    {
    case ip:
        ui->tableWidget->setItem(row,3,new QTableWidgetItem(QString("ip")));
        packet_count.ip_num++;
        break;
    case arp:
        ui->tableWidget->setItem(row,3,new QTableWidgetItem(QString("arp")));
        packet_count.arp_num++;
        break;
    case tcp:
        ui->tableWidget->setItem(row,3,new QTableWidgetItem(QString("tcp")));
        packet_count.tcp_num++;
        packet_count.ip_num++;
        break;
    case udp:
        ui->tableWidget->setItem(row,3,new QTableWidgetItem(QString("udp")));
        packet_count.udp_num++;
        packet_count.ip_num++;
        break;
    case icmp:
        ui->tableWidget->setItem(row,3,new QTableWidgetItem(QString("icmp")));
        packet_count.icmp_num++;
        packet_count.ip_num++;
        break;
    default:
        ui->tableWidget->setItem(row,3,new QTableWidgetItem(QString("other")));
        break;
    }

    packet_info.proto_flag=protocol_flag;
    packet_info.srcmac=mactoQstring(Etherdata.ether_shost);
    packet_info.desmac=mactoQstring(Etherdata.ether_dhost);

    if(protocol_flag==tcp){
        stream.str("");
        stream<<(int)Tcpdata.tcp_source_port;
        qstr=QString::fromStdString(stream.str());
        packet_info.srcport=qstr;

        stream.str("");
        stream<<(int)Tcpdata.tcp_destination_port;
        qstr=QString::fromStdString(stream.str());
        packet_info.desport=qstr;

        stream.str("");
        stream<<(u_int)Tcpdata.tcp_ack;
        qstr=QString::fromStdString(stream.str());
        packet_info.tcp_seq=qstr;

        stream.str("");
        stream<<(u_int)Tcpdata.tcp_acknowledgement;
        qstr=QString::fromStdString(stream.str());
        packet_info.tcp_acknum=qstr;

        stream.str("");
        stream<<(u_int)Tcpdata.tcp_checksum;
        qstr=QString::fromStdString(stream.str());
        packet_info.tcp_udp_checksum=qstr;

        stream.str("");
        stream<<(u_int)Tcpdata.tcp_checksum;
        qstr=QString::fromStdString(stream.str());
        packet_info.tcp_udp_checksum=qstr;

        stream.str("");
        stream<<(u_int)Tcpdata.tcp_windows;
        qstr=QString::fromStdString(stream.str());
        packet_info.tcp_udp_checksum=qstr;
    }else if(protocol_flag==udp)
    {
        stream.str("");
        stream << (int)Udpdata.udp_source_port;
        qstr = QString::fromStdString(stream.str());
        packet_info.srcport=qstr;

        stream.str("");
        stream << (int)Udpdata.udp_destination_port;
        qstr = QString::fromStdString(stream.str());
        packet_info.desport=qstr;

        stream.str("");
        stream << (int)Udpdata.udp_checksum;
        qstr = QString::fromStdString(stream.str());
        packet_info.tcp_udp_checksum=qstr;

        stream.str("");
        stream << (int)Udpdata.udp_length;
        qstr = QString::fromStdString(stream.str());
        packet_info.udp_length=qstr;
    }
    else if(protocol_flag==icmp)
    {
        stream.str("");
        stream<<(int)Icmpdata.icmp_type;
        qstr=QString::fromStdString(stream.str());
        packet_info.icmp_type=qstr;

        stream.str("");
        stream<<(int)Icmpdata.icmp_code;
        qstr=QString::fromStdString(stream.str());
        packet_info.icmp_code=qstr;
    }

    packet_vector.push_back(packet_info);

    qstr=QString::number(packet_count.arp_num);
    ui->ct_arp->setText(qstr);

    qstr=QString::number(packet_count.total);
    ui->ct_total->setText(qstr);

    qstr=QString::number(packet_count.icmp_num);
    ui->ct_icmp->setText(qstr);

    qstr=QString::number(packet_count.ip_num);
    ui->ct_ip->setText(qstr);

    qstr=QString::number(packet_count.tcp_num);
    ui->ct_tcp->setText(qstr);

    qstr=QString::number(packet_count.udp_num);
    ui->ct_udp->setText(qstr);
}
void MainWindow::changeHost(QString line){
    vector<string> vec;
    string s=line.toStdString();
    int row=ui->hosts->rowCount();
    ui->hosts->insertRow(row);
    const char *d = " ";
    char *p;
    p = strtok(const_cast<char*>(s.c_str()),d);
    int col=0;
    while(p)
    {
        ui->hosts->setItem(row,col,new QTableWidgetItem(QString(p)));
        col++;
        vec.push_back(string(p));
        p=strtok(nullptr,d);
    }
    hosts_vector.push_back(vec);
}
void MainWindow::on_hosts_itemClicked(QTableWidgetItem *item){
    int row=ui->hosts->row(item);
    ui->line_src_ip->setText(QString::fromStdString(hosts_vector[row][0]));
    ui->line_src_mac->setText(QString::fromStdString(hosts_vector[row][3]));
}
void MainWindow::on_tableWidget_itemClicked(QTableWidgetItem *item)
{
    int row=ui->tableWidget->row(item);
    stringstream stream;
    ui->listWidget->clear();
    ui->listWidget->addItem( "------------ Ethernet Protocol (Link Layer) -----------" );
    ui->listWidget->addItem("Mac Source Address is:");
    ui->listWidget->addItem(packet_vector[row].srcmac);
    ui->listWidget->addItem("Mac Destination Address is :");
    ui->listWidget->addItem(packet_vector[row].desmac);

    if(packet_vector[row].proto_flag==ip||packet_vector[row].proto_flag==tcp||
            packet_vector[row].proto_flag==udp||packet_vector[row].proto_flag==icmp)
   {
        ui->listWidget->addItem( "-----------------IP portocol (network layer)-------------------------");
        ui->listWidget->addItem("Source address:");
        ui->listWidget->addItem(packet_vector[row].srcip);
        ui->listWidget->addItem("Destination address:");
        ui->listWidget->addItem(packet_vector[row].desip);
        ui->listWidget->addItem("IP Version:");
        ui->listWidget->addItem(packet_vector[row].ipversion);
        ui->listWidget->addItem("TLL"+packet_vector[row].TTL);
        ui->listWidget->addItem("Total length"+packet_vector[row].iplength);
        ui->listWidget->addItem("Header checksum:"+packet_vector[row].tcp_udp_checksum);

    }
    else if(packet_vector[row].proto_flag==arp)
    {
         ui->listWidget->addItem("-----------------ARP portocol (network layer)-------------------------");
         ui->listWidget->addItem("Source Ip address:"+packet_vector[row].srcip);
         ui->listWidget->addItem("Destination Ip address:"+packet_vector[row].desip);
         ui->listWidget->addItem("ARP Hardware Type:"+packet_vector[row].arp_HardwareType);
         ui->listWidget->addItem("ARP Protocol Type:"+packet_vector[row].arp_ProtocolType);
    }

    if (packet_vector[row].proto_flag==tcp)
    {
        ui->listWidget->addItem("------- TCP Protocol (Transport Layer) -------") ;
        ui->listWidget->addItem("Source Port:"+packet_vector[row].srcport);
        ui->listWidget->addItem("Destination Port:"+packet_vector[row].desport);
        ui->listWidget->addItem("Sequence Number:"+packet_vector[row].tcp_seq);
        ui->listWidget->addItem("Acknowledgement Number:"+packet_vector[row].tcp_acknum);
        ui->listWidget->addItem("Checksum:"+packet_vector[row].tcp_udp_checksum);
        ui->listWidget->addItem("Window Size:"+packet_vector[row].tcp_windowsize);
    }
    else if(packet_vector[row].proto_flag==udp)
    {

        ui->listWidget->addItem("------- UDP Protocol (Transport Layer) -------") ;
        ui->listWidget->addItem("Source port:"+packet_vector[row].srcport);
        ui->listWidget->addItem("Destination port:"+packet_vector[row].desport);
        ui->listWidget->addItem("Total Length:"+packet_vector[row].udp_length);
        ui->listWidget->addItem("Checksum:"+packet_vector[row].tcp_udp_checksum);

    }
    else if(packet_vector[row].proto_flag==icmp){
        ui->listWidget->addItem("------- ICMP Protocol (Transport Layer) -------") ;
        ui->listWidget->addItem("ICMP Type:"+packet_vector[row].icmp_type);
        ui->listWidget->addItem("ICMP Code:"+packet_vector[row].icmp_code);
        ui->listWidget->addItem("ICMP Checksum:"+packet_vector[row].icmp_checksum);
    }

    ui->listWidget->setEditTriggers(QAbstractItemView::AllEditTriggers);
    for (int i = 0; i < ui->listWidget->count(); i++)
    {
        ui->listWidget->item(i)->setFlags(Qt::ItemIsEditable | Qt::ItemIsSelectable | Qt::ItemIsEnabled);
    }
}

void MainWindow::on_getallbtn_clicked(){
    char error_content[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldev;

    if(pcap_findalldevs(&alldev,error_content)==-1){
        qDebug()<<"Error in findalldev"<<endl;

    }
    pcap_if_t* d;
    for(d=alldev;d;d=d->next)
    {
        qDebug()<<d->name<<endl;
        ui->all->addItem(QString(d->name));
    }
    pcap_freealldevs(alldev);
}
void MainWindow::on_usebtn_clicked(){
    QString dev=ui->all->currentText();
    if_dev=const_cast<char*>(dev.toStdString().c_str());
    qDebug()<<"now use"<<if_dev<<endl;
    ui->att_dev->setText(dev);
    char mac[20];
    NetworkUtils::getMAC(mac, string(dev.toStdString()).c_str());
    ui->att_mac->setText(QString((char*)mac));
    char ip[20];
    NetworkUtils::getIP(ip, string(dev.toStdString()).c_str());

    ui->att_ip->setText(QString((char*)ip));

    if(!ui->line_ip_seg->text().isEmpty())
    {
        qDebug()<<"start scan ips"<<endl;
        arpthread.setscan_ips(const_cast<char*>(ui->line_ip_seg->text().toStdString().c_str()));
    }
}

void MainWindow::on_btn_icmpflood_clicked(){
    // Use smart pointer (replaces raw pointer assignment)
    icmpf = std::make_unique<icmpflood>(const_cast<char*>(ui->line_icmp_src_ip->text().toStdString().c_str()),
                        const_cast<char*>(ui->line_icmp_dst_ip->text().toStdString().c_str()),
                        const_cast<char*>(ui->line_icmp_id->text().toStdString().c_str()),
                        const_cast<char*>(ui->line_icmp_start_seq->text().toStdString().c_str()),
                        const_cast<char*>(ui->line_icmp_endseq->text().toStdString().c_str()),
                        const_cast<char*>(ui->line_icmp_threads->text().toStdString().c_str())
                        );
    qDebug()<<"icmp send over"<<endl;
}
void MainWindow::on_btn_icmp_localhost_clicked(){
    ui->line_icmp_src_ip->setText(ui->att_ip->text());
}
void MainWindow::on_btn_smurf_start_clicked(){
    // Use smart pointer (replaces raw pointer assignment)
    smf = std::make_unique<smurf>(const_cast<char*>(ui->line_icmp_dst_ip->text().toStdString().c_str()));
}
void MainWindow::show_hosts(){
    arpthread.reflush_ips();
}
void MainWindow::writelog(){
    ui->list_log->addItem(new QListWidgetItem("----------start arp attack-----------"));
    ui->list_log->addItem(new QListWidgetItem(current_date));
    QString arp_send_ip="send_ip"+ui->line_src_ip->text();
    ui->list_log->addItem(new QListWidgetItem(arp_send_ip));
    QString arp_send_mac="send_mac"+ui->line_src_mac->text();
    ui->list_log->addItem(new QListWidgetItem(arp_send_mac));
    QString arp_target_ip="target_ip"+ui->line_des_ip->text();
    ui->list_log->addItem(new QListWidgetItem(arp_target_ip));
    QString arp_target_mac="target_mac"+ui->line_des_mac->text();
    ui->list_log->addItem(new QListWidgetItem(arp_target_mac));
    ui->list_log->addItem(new QListWidgetItem("----------end arp attack-----------"));
}
MainWindow::~MainWindow()
{
   delete ui;
}

// IP location query result handler (moved from parseJson/onReplied)
void MainWindow::onIpInfoReady(const ipinfo& info)
{
    ui->line_q_ip_2->setText(info.ip);
    ui->line_q_continent->setText(info.continent);
    ui->line_q_country->setText(info.country);
    ui->line_q_countrycode->setText(info.countrycode);
    ui->line_q_countryenglish->setText(info.countryenglish);
    ui->line_q_district->setText(info.district);
    ui->line_q_city->setText(info.city);
    ui->line_q_isp->setText(info.isp);
    ui->line_q_areacode->setText(info.areacode);
    ui->line_q_latitude->setText(info.latitude);
    ui->line_q_longitude->setText(info.longitude);
    ui->line_q_province->setText(info.province);
}

void MainWindow::onIpQueryFailed(const QString& errorMsg)
{
    QMessageBox::warning(this, "ip", errorMsg, QMessageBox::Ok);
}

void MainWindow::on_btn_q_query_clicked(){
     m_ipLocationService->queryIpInfo(ui->line_q_ip->text());
}

void MainWindow::get_ip_bydomin(){
    // Placeholder for domain-to-IP resolution (not yet implemented)
}
