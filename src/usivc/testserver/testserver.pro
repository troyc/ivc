QT       += core network
QT       -= gui

CONFIG   += console c++14 debug

TARGET = testserver
DESTDIR = ../bin
TEMPLATE = app

SOURCES += ../testserver.cpp
SOURCES += ../../data-structures/ringbuffer.c

HEADERS += ../../../include/core/libivc.h
HEADERS += ../../data-structures/ringbuffer.h

INCLUDEPATH += "../../../include/core"
INCLUDEPATH += "../../data-structures"

LIBS += -lxenbe -livc -lpvbackendhelper

target.path = /usr/bin
INSTALLS += target
