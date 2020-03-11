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
SOURCES += ../../data-structures/ringbuffer.c

HEADERS += ../ivcbackend.h
HEADERS += ../guestmanager.h
HEADERS += ../guestcontroller.h
HEADERS += ../../data-structures/ringbuffer.h
HEADERS += ../ringbuf.h

INCLUDEPATH += "../../../include/core ../../data-structures"

LIBS += -lxenbe

target.path = /usr/bin
INSTALLS += target
