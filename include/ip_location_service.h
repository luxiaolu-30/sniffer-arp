#ifndef IP_LOCATION_SERVICE_H
#define IP_LOCATION_SERVICE_H

#include <QObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QByteArray>
#include "ip_info.h"

// Service class for IP geolocation queries via HTTP API
class IpLocationService : public QObject
{
    Q_OBJECT
public:
    explicit IpLocationService(QObject* parent = nullptr);
    ~IpLocationService();

    // Query IP geolocation info via API
    void queryIpInfo(const QString& ip);

    // Get the last parsed IP info
    const ipinfo& getInfo() const { return m_info; }

signals:
    // Emitted when IP info is parsed and ready
    void ipInfoReady(const ipinfo& info);

    // Emitted when request fails
    void queryFailed(const QString& errorMsg);

private slots:
    void onReplied(QNetworkReply* reply);

private:
    void parseJson(QByteArray& byteArray);

    QNetworkAccessManager* m_netAccessManager;
    ipinfo m_info;
};

#endif // IP_LOCATION_SERVICE_H
