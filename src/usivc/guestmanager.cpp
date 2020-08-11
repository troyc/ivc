#include "guestmanager.h"

GuestManager::GuestManager(XenBackend::XenStore &xs) : mXs(xs)
{
  // Watch the /local/domain path to monitor new guests
  mLocalDomainCallback = std::function<void(const std::string &)>([&](const std::string path){ localDomainCallback(path); });
  mXs.setWatch("/local/domain", mLocalDomainCallback);
  mXs.start();
}

GuestManager::~GuestManager()
{ }

bool GuestManager::containsDomain(const std::vector<domid_t> &domList, domid_t domid)
{
  for (const auto &d : domList) {
    if (domid == d) {
      return true;
    }
  }

  return false;
}

void GuestManager::printDomains(const std::vector<domid_t> &domList)
{
  std::cout << "Domain list: ";
  for(const auto &d : domList) {
    std::cout << d << ' ';
  }
  std::cout << '\n';
}

void GuestManager::syncRunningDomains(std::vector<domid_t> &runningDomains,
				      const std::vector<domid_t> &currentDomains)
{
  for(const auto &domid : currentDomains) {
    if(!containsDomain(runningDomains, domid)) {
      addDomain(runningDomains, domid);
    }
  }

  for(const auto &domid : runningDomains) {
    if(!containsDomain(currentDomains, domid)) {
      removeDomain(runningDomains, domid);
    }
  }
}

void GuestManager::addDomain(std::vector<domid_t> &domList, domid_t domid)
{
  if (!containsDomain(domList, domid)) {
    domList.push_back(domid);
    emit addGuest(domid);
  }
}

void GuestManager::removeDomain(std::vector<domid_t> &domList, domid_t domid)
{
  int i = 0;
  for (const auto &d : domList) {
    if (domid == d) {
      domList.erase(domList.begin()+i);
      emit removeGuest(domid);
      return;
    }
    i++;
  }
}

void GuestManager::localDomainCallback(const std::string &path)
{
    std::vector<std::string> directoryDomains = mXs.readDirectory(path);
    std::vector<domid_t> currentDomains;
    std::lock_guard<std::mutex> lock(mDomainListLock);

    for (const auto &d : directoryDomains) {
      domid_t domid = stoul(d);
      if (!containsDomain(currentDomains, domid)) {
	currentDomains.push_back(domid);
      }
    }

    if (currentDomains != mRunningDomains) {
      syncRunningDomains(mRunningDomains, currentDomains);
      printDomains(currentDomains);
    }

    return;
}
