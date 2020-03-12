QT       += core network
QT       -= gui

CONFIG   += console c++14 debug

TARGET = testserver
DESTDIR = ../bin
TEMPLATE = app

SOURCES += ../testserver.cpp

HEADERS += ../../../include/core/libivc.h

INCLUDEPATH += "../../../include/core"

LIBS += -lxenbe -livc -lpvbackendhelper

target.path = /usr/bin
INSTALLS += target
