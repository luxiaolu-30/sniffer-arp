#ifndef IP_INFO_H
#define IP_INFO_H

#include <QString>

// IP geolocation information data class
class ipinfo {
public:
    QString ip;
    QString continent;
    QString country;
    QString province;
    QString city;
    QString district;
    QString isp;
    QString areacode;
    QString countrycode;
    QString countryenglish;
    QString latitude;
    QString longitude;
};

#endif // IP_INFO_H
