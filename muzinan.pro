#-------------------------------------------------
#
# Project created by QtCreator 2023-03-01T10:35:44
#
#-------------------------------------------------

QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = muzinan
TEMPLATE = app

DEFINES += QT_DEPRECATED_WARNINGS

CONFIG += c++11

SOURCES += \
        src/main.cpp \
        src/mainwindow.cpp \
        src/getthread.cpp \
        src/arpattack.cpp \
        src/sendarp.cpp \
        src/ip_info.cpp \
        src/icmpflood.cpp \
        src/smurf.cpp

HEADERS += \
        include/mainwindow.h \
        include/getthread.h \
        include/arpattack.h \
        include/sendarp.h \
        include/icmpflood.h \
        include/smurf.h

FORMS += \
        src/mainwindow.ui

# --- Library configuration ---
# Update these paths to match your local libpcap / libnet installation.
# Linux example:
#   LIBS += -lpcap -lnet
# Windows (MinGW) example:
#   LIBS += -L"C:/path/to/libpcap" -lpcap
#   LIBS += -L"C:/path/to/libnet" -lnet
LIBS += -lpcap -lnet

RESOURCES += \
    resources.qrc

DISTFILES += \
    list.txt
