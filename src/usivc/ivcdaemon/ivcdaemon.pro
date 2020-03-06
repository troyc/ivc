QT       += core network
QT       -= gui

CONFIG   += console c++14 debug

TARGET = ivcdaemon
DESTDIR = ../bin
TEMPLATE = app

SOURCES += ../ivcd.cpp
SOURCES += ../ivcbackend.cpp
SOURCES += ../guestmanager.cpp
SOURCES += ../guestcontroller.cpp
SOURCES += ../ringbuffer.c

HEADERS += ../ivcbackend.h
HEADERS += ../guestmanager.h
HEADERS += ../guestcontroller.h
HEADERS += ../ringbuffer.h
HEADERS += ../ringbuf.h

INCLUDEPATH += "$$(STAGING_DIR_TARGET)/usr/include"

LIBS += -lxenbe

target.path = /usr/bin
INSTALLS += target
