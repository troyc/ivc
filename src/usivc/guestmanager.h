#ifndef GUESTMANAGER__H
#define GUESTMANAGER__H

// stdlib
#include <iostream>

// 3rd party libs
#include <xen/be/XenStore.hpp>
#include <QObject>

class GuestManager : public QObject {
  Q_OBJECT
 public:
  GuestManager(XenBackend::XenStore &xs);
  ~GuestManager();

signals:
  void addGuest(domid_t domid);
  void removeGuest(domid_t domid);
  
private:
  bool containsDomain(const std::vector<domid_t> &domList, domid_t domid);
  void printDomains(const std::vector<domid_t> &domList);
  
  void syncRunningDomains(std::vector<domid_t> &runningDomains,
			  const std::vector<domid_t> &currentDomains);
  void addDomain(std::vector<domid_t> &domList, domid_t domid);
  void removeDomain(std::vector<domid_t> &domList, domid_t domid);
  
  void localDomainCallback(const std::string &path);
  XenBackend::XenStore::WatchCallback mLocalDomainCallback;  
  std::vector<domid_t> mRunningDomains;
  std::mutex mDomainListLock;

  XenBackend::XenStore &mXs;
};
#endif //GUESTMANAGER__H
