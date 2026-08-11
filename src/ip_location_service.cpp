#include "ip_location_service.h"
#include <QUrl>
#include <QJsonParseError>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>

IpLocationService::IpLocationService(QObject* parent)
    : QObject(parent)
{
    m_netAccessManager = new QNetworkAccessManager(this);
    connect(m_netAccessManager, &QNetworkAccessManager::finished, this, &IpLocationService::onReplied);
}

IpLocationService::~IpLocationService()
{
}

void IpLocationService::queryIpInfo(const QString& ip)
{
    std::string urlstr = "https://apis.tianapi.com/ipquery/index?key=a30d7e222fcc92f6d407a20479c10df1&ip=" + ip.toStdString();
    QUrl url(urlstr.c_str());
    qDebug() << url << endl;
    m_netAccessManager->get(QNetworkRequest(url));
}

void IpLocationService::onReplied(QNetworkReply* reply)
{
    int status_code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();

    qDebug() << "operation:" << reply->operation();
    qDebug() << "status code:" << status_code;
    qDebug() << "url:" << reply->url();
    qDebug() << "raw header:" << reply->rawHeaderList();

    if (reply->error() != QNetworkReply::NoError || status_code != 200) {
        qDebug("%s(%d) error: %s", __FUNCTION__, __LINE__, reply->errorString().toLatin1().data());
        emit queryFailed("请求数据失败！");
    } else {
        QByteArray byteArray = reply->readAll();
        qDebug() << "read all:" << byteArray.data();
        qDebug() << "start parse" << endl;
        parseJson(byteArray);
    }

    reply->deleteLater();
}

void IpLocationService::parseJson(QByteArray& byteArray)
{
    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(byteArray, &err);
    if (err.error != QJsonParseError::NoError) {
        qDebug("%s(%d): %s", __FUNCTION__, __LINE__, err.errorString().toLatin1().data());
        return;
    }

    QJsonObject rootObj = doc.object();
    qDebug() << rootObj.value("msg").toString();
    QString message = rootObj.value("msg").toString();
    if (!message.contains("success")) {
        emit queryFailed("请求数据失败！");
        return;
    }

    QJsonObject objData = rootObj.value("result").toObject();
    m_info.ip = objData.value("ip").toString();
    qDebug() << m_info.ip << endl;
    m_info.continent = objData.value("continent").toString();
    m_info.country = objData.value("country").toString();
    m_info.province = objData.value("province").toString();
    m_info.city = objData.value("city").toString();
    m_info.district = objData.value("district").toString();
    m_info.isp = objData.value("isp").toString();
    m_info.areacode = objData.value("areacode").toString();
    m_info.countrycode = objData.value("countrycode").toString();
    m_info.countryenglish = objData.value("countryenglish").toString();
    m_info.latitude = objData.value("latitude").toString();
    m_info.longitude = objData.value("longitude").toString();

    emit ipInfoReady(m_info);
}
