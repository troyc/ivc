#include <iostream>
#include "ivcbackend.h"

#include <QCoreApplication>

extern "C" {
#include <unistd.h>
}

int main(int argc, const char *argv[])
{
  QCoreApplication app(argc, (char **) argv);
  IvcBackend ivcbe;

  app.exec();
  return 0;
}
