/*
* 本模块的功能：回调函数的实现
* 作者：muzinan
*/
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "getthread.h"
#include "arpattack.h"
#include<QFile>
#include<QTextStream>
#include<QVariant>
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
#include <libnet.h>
#include <QDateTime>
//协议函数类型定义AF—inet
#include<netinet/in.h>
//地址转换函数 inet_addr()等
#include<arpa/inet.h>
//socket
#include<sys/socket.h>
#include<sys/types.h>

//标准输入输出
#include<cstdio>
#include<cstdlib>
//提供memset等字符串操作函数
#include<cstring>
#include<string.h>
#include<sys/ioctl.h>

//read write execl
#include<unistd.h>

//gethostbyname
#include<netdb.h>

//#include<net/ethernet.h>
#include<net/if.h>   //support ifreq
#include<fstream>

//timeval
#include<sys/time.h>
//#include<netinet/if_ether.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ip_icmp.h>
#include<netinet/in_systm.h>
#include<netinet/ip.h>
#include<netinet/in.h>

#include<time.h>

#include<iostream>
#include<fcntl.h>
#include <unistd.h>
#include <signal.h>


#include<QMessageBox>
#include<QMouseEvent>
#include<QMovie>
#include<QIcon>
#include<QString>
#include<qfileinfo.h>
#include<QDebug>
#include<QDateTime>
#include<QJsonParseError>
#include<QUrlQuery>


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

    //设置计时器
    startTimer(1000);
    //init ui
    init_UI();
    //init data
    init_data();

       connect(ui->actionsave,&QAction::triggered,this,[=](){
               //QMessageBox::critical(this,"critical","错误");
               //提问对话框
               if(QMessageBox::Save== QMessageBox::question(this,"ques","save packets？",QMessageBox::Save|QMessageBox::Cancel,QMessageBox::Cancel )){
                   //用户选择保存
                   cout<<"save file"<<endl;
               }
       });


        qRegisterMetaType<QVariant>("QVariant");
        connect(&thread, SIGNAL(stringChanged(int,QVariant,QVariant,QVariant,QVariant,QVariant,QVariant)),
           this, SLOT(changeString(int,QVariant,QVariant,QVariant,QVariant,QVariant,QVariant)));

        connect(&arpthread,SIGNAL(get_host(QString)),this,SLOT(changeHost(QString)));
        connect(&spkt,SIGNAL(writelog()), this, SLOT(writelog()));

        packet_count={0,0,0,0,0,0};

        mNetAccessManager = new QNetworkAccessManager(this);
        connect(mNetAccessManager, &QNetworkAccessManager::finished, this, &MainWindow::onReplied);
}
void MainWindow::init_UI(){
//    // 设置按钮背景颜色和字体样式
//    ui->startbtn->setStyleSheet("background-color: #007ACC; color: white; font: bold 14px;");
//    // 设置按钮圆角
//    ui->startbtn->setStyleSheet("border-radius: 10px;");
//    // 设置按钮边框样式和宽度
//    ui->startbtn->setStyleSheet("border: 2px solid #007ACC;");
//    // 设置按钮悬停样式
//    ui->startbtn->setStyleSheet("background-color: #008CBA; color: white;");
//    ui->startbtn->setCursor(Qt::PointingHandCursor);
//    // 设置按钮按下样式
//    ui->startbtn->setStyleSheet("background-color: #005F8B; color: white;");

    //set table
    //设置表头
    ui->tableWidget->setColumnCount(4);
    //设置水平表头
    ui->tableWidget->setHorizontalHeaderLabels(QStringList()<<"Source"<<"Destination"<<"length"<<"Protocol");
    //设置行数
    ui->tableWidget->setRowCount(0);
    //单击选择一行
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    //设置只能选择一行，不能多行选中
    ui->tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tableWidget->setColumnWidth(0,150);
    ui->tableWidget->setColumnWidth(1,150);
    ui->tableWidget->setColumnWidth(2,150);
    ui->tableWidget->setColumnWidth(3,150);
    //set table
    //设置表头
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
        struct in_addr net_ip_address;   //网络地址
        struct in_addr net_mask_address;  //掩码地址
        char* net_interface;        //接口名字
        char* net_ip_string;        //网络地址字符串形式
        char* net_mask_string;      //掩码地址字符串形式
        u_int32_t net_ip;           //网络地址
        u_int32_t net_mask;         //掩码地址
        net_interface = pcap_lookupdev(error_content);  //获取网络地址
        QString network=QString(QLatin1String(net_interface));
        pcap_lookupnet(net_interface,&net_ip,&net_mask,error_content);  //获取网络和掩码地址
        //printf("Network Interface is:%s \n",net_interface); //网络接口
        net_ip_address.s_addr=net_ip;//131028
        net_ip_string=inet_ntoa(net_ip_address);   //->string
        QString ip=QString(QLatin1String(net_ip_string));
        //printf("Network IP Address is: %s \n",net_ip_string); //网络地址
        net_mask_address.s_addr=net_mask;//16777215
        net_mask_string=inet_ntoa(net_mask_address); //掩码->string
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
        char buff[256];
        int  nl = 0 ;
        struct in_addr gw;
        int flgs, ref, use, metric;
        unsigned long int d,g,m;
        FILE *fp = nullptr;

        fp = fopen("/proc/net/route", "r");
        if (fp == nullptr)
        {
        }
        nl = 0 ;
        memset(buff, 0,sizeof(buff));
        while( fgets(buff, sizeof(buff), fp) != nullptr )
        {
            if(nl)
            {
                int ifl = 0;
                while(buff[ifl]!=' ' && buff[ifl]!='\t' && buff[ifl]!='\0')
                    ifl++;
                buff[ifl]=0;    /* interface */
                if(sscanf(buff+ifl+1, "%lx%lx%X%d%d%d%lx",
                       &d, &g, &flgs, &ref, &use, &metric, &m)!=7)
                {
                    fclose(fp);
                }

                ifl = 0;        /* parse flags */
                gw.s_addr   = g;

                if(d==0)
                {
                    strcpy(gateway_addr,inet_ntoa(gw));
                    fclose(fp);
                }

            }
            nl++;
        }
        if(fp)
        {
            fclose(fp);
            fp = nullptr;
        }
        qDebug()<<gateway_addr<<endl;
        ui->line_src_ip->setText(gateway_addr);

}
void MainWindow::on_btn_src_mac_local_clicked(){
    QString dev=ui->all->currentText();
    get_mac((char*)if_mac,string(dev.toStdString()).c_str());
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
//        spkt.quit();
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
    //num转qstring
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
        //ui->tableWidget->setItem(row,1,new QTableWidgetItem(qstr));
        packet_info.ipversion=qstr;

        stream.str("");
        stream<<(int)Ipdata.ip_length;
        qstr=QString::fromStdString(stream.str());
        ui->tableWidget->setItem(row,2,new QTableWidgetItem(qstr));
        packet_info.iplength=qstr;

        stream.str("");
        stream<<(int)Ipdata.ip_checksum;
        qstr=QString::fromStdString(stream.str());
        //ui->tableWidget->setItem(row,1,new QTableWidgetItem(qstr));
        packet_info.ipchecksum=qstr;

    }
    else if(protocol_flag == arp)
    {
        stream.str("");
        stream<<(int)Arpdata.arp_hardware_type;
        qstr=QString::fromStdString(stream.str());
        //ui->tableWidget->setItem(row,1,new QTableWidgetItem(qstr));
        packet_info.arp_HardwareType=qstr;

        stream.str("");
        stream<<(int)Arpdata.arp_protocol_type;
        qstr=QString::fromStdString(stream.str());
        //ui->tableWidget->setItem(row,1,new QTableWidgetItem(qstr));
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
//            printf ( "ARP Hardware Length :%d\n" , hardware_length) ;
//            printf ( "ARP Protocol Length :%d\n" , protocol_length) ;
//            printf ( "ARP Operation :%d\n" , operation_code ) ;
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
//    QMessageBox::information(this,"error","Error in findalldev",QMessageBox::Ok);
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
//    memcpy(if_dev,string(dev.toStdString()).c_str(),(size_t)dev.length());
    qDebug()<<"now use"<<if_dev<<endl;
//    QMessageBox::information(this,"use",dev,QMessageBox::Ok);
    ui->att_dev->setText(dev);
    char mac[20];
    get_mac(mac,string(dev.toStdString()).c_str());
//    memcpy(eth_src_mac,mac,sizeof(mac));
    ui->att_mac->setText(QString((char*)mac));
    char ip[20];
    get_ip(ip,string(dev.toStdString()).c_str());

    ui->att_ip->setText(QString((char*)ip));

    if(!ui->line_ip_seg->text().isEmpty())
    {
        qDebug()<<"start scan ips"<<endl;
        arpthread.setscan_ips(const_cast<char*>(ui->line_ip_seg->text().toStdString().c_str()));
    }
}

void MainWindow::on_btn_icmpflood_clicked(){
//    struct in_addr addr;
//    if(inet_aton("192.168.92.141",&addr)==0){
//        qDebug()<<"ip addr error"<<endl;
//        return;
//    }
//    icmpf=new icmpflood("192.168.1.100","192.168.1.1","1234","1","1000");
    icmpf=new icmpflood(const_cast<char*>(ui->line_icmp_src_ip->text().toStdString().c_str()),
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

    smf=new smurf(const_cast<char*>(ui->line_icmp_dst_ip->text().toStdString().c_str()));

}
void MainWindow::get_ip(char* local_ip,const char* eth_name){
    int sock=socket(AF_INET,SOCK_DGRAM,0);
    struct sockaddr_in sin;
    struct ifreq ifr;
    if(sock==-1){
        qDebug()<<"get mac error"<<endl;
        return;
    }

    strcpy(ifr.ifr_name,eth_name);

    if(ioctl(sock,SIOCGIFADDR,&ifr)<0)
    {
        return;
    }
    memcpy(&sin,&ifr.ifr_addr,sizeof(sin));

    sprintf(local_ip,"%s",inet_ntoa(sin.sin_addr));
}
void MainWindow::get_mac(char* mac,const char* eth_name){
    struct ifreq ifr;
    int socketfd=socket(AF_INET,SOCK_DGRAM,0);
    if(socketfd==-1){
        qDebug()<<"get mac error"<<endl;
        return;
    }
    //填入ifr_name字段
    strcpy(ifr.ifr_name,eth_name);
    if(ioctl(socketfd,SIOCGIFHWADDR,&ifr)<0)
    {
       //close();
       return;
    }

    sprintf(mac,"%02x:%02x:%02x:%02x:%02x:%02x",
            (unsigned char)ifr.ifr_hwaddr.sa_data[0],
            (unsigned char)ifr.ifr_hwaddr.sa_data[1],
            (unsigned char)ifr.ifr_hwaddr.sa_data[2],
            (unsigned char)ifr.ifr_hwaddr.sa_data[3],
            (unsigned char)ifr.ifr_hwaddr.sa_data[4],
            (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
    return;
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
void MainWindow::onReplied(QNetworkReply* reply)
{
    // 响应的状态码为200, 表示请求成功
    int status_code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();

    qDebug() << "operation:" << reply->operation();       // 请求方式
    qDebug() << "status code:" << status_code;            // 状态码
    qDebug() << "url:" << reply->url();                   // url
    qDebug() << "raw header:" << reply->rawHeaderList();  // header

    if ( reply->error() != QNetworkReply::NoError || status_code != 200 ) {
        qDebug("%s(%d) error: %s", __FUNCTION__, __LINE__, reply->errorString().toLatin1().data());
        QMessageBox::warning(this, "ip", "请求数据失败！", QMessageBox::Ok);
    } else {
        //获取响应信息
        QByteArray byteArray = reply->readAll();
        qDebug() << "read all:" << byteArray.data();
        qDebug() <<"start parse"<<endl;
        parseJson(byteArray);
    }

    reply->deleteLater();
}
//获取ip的信息
void MainWindow::getWeatherInfo(QString cityCode)
{
    std::string urlstr="https://apis.tianapi.com/ipquery/index?key=a30d7e222fcc92f6d407a20479c10df1&ip="+cityCode.toStdString();
    QUrl url(urlstr.c_str());
    qDebug()<<url<<endl;
    mNetAccessManager->get(QNetworkRequest(url));
}
//解析json数据
void MainWindow::parseJson(QByteArray& byteArray)
{
    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(byteArray, &err);
    if ( err.error != QJsonParseError::NoError ) {
        qDebug("%s(%d): %s", __FUNCTION__, __LINE__, err.errorString().toLatin1().data());
        return;
    }

    QJsonObject rootObj= doc.object();
    qDebug() << rootObj.value("msg").toString();
    QString message = rootObj.value("msg").toString();
    if ( !message.contains("success") ) {
        QMessageBox::warning(this, "天气", "请求数据失败！", QMessageBox::Ok);
        return;
    }

    QJsonObject objData = rootObj.value("result").toObject();
    info.ip=objData.value("ip").toString();
    qDebug()<<info.ip<<endl;
    info.continent=objData.value("continent").toString();
    info.country=objData.value("country").toString();
    info.province=objData.value("province").toString();
    info.city=objData.value("city").toString();
    info.district=objData.value("district").toString();
    info.isp=objData.value("isp").toString();
    info.areacode=objData.value("areacode").toString();
    info.countrycode=objData.value("countrycode").toString();
    info.countryenglish=objData.value("countryenglish").toString();
    info.latitude=objData.value("latitude").toString();
    info.longitude=objData.value("longitude").toString();

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

void MainWindow::on_btn_q_query_clicked(){
     getWeatherInfo(ui->line_q_ip->text());
}
