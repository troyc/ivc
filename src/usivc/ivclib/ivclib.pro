QT       += core network
QT       -= gui

CONFIG   += console c++14 debug

TARGET = ivc
DESTDIR = ../lib
TEMPLATE = lib

SOURCES += ../libivc.cpp
HEADERS += ../libivc.h
HEADERS += ../libivc_core.h

INCLUDEPATH += "$$(STAGING_DIR_TARGET)/usr/include"

LIBS += -lxenbe

target.path = /usr/lib
INSTALLS += target
