QT       += core network
QT       -= gui

CONFIG   += console c++14 debug

TARGET = ivc
DESTDIR = ../lib
TEMPLATE = lib

VERSION = 2.0

SOURCES += ../libivc.cpp
SOURCES += ../libivc_core.cpp
SOURCES += ../ivc_client.cpp
SOURCES += ../event_controller.cpp
SOURCES += ../ringbuf.cpp
SOURCES += ../../data-structures/ringbuffer.c

HEADERS += ../../../include/core/libivc.h
HEADERS += ../libivc_core.h
HEADERS += ../ivc_client.h
HEADERS += ../ringbuf.h
HEADERS += ../event_controller.h
HEADERS += ../../data-structures/ringbuffer.h

INCLUDEPATH += "../../../include/core"
INCLUDEPATH += "../../data-structures"

LIBS += -lxenbe

target.path = /usr/lib
INSTALLS += target

headers.path = /usr/include
headers.files = \
	../../../include/core/libivc.h \
	../../../include/core/libivc_types.h \
	../../../include/core/libivc_debug.h
INSTALLS += headers
