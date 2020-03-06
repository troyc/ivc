#include "libivc.h"
#include <iostream>
#include <iomanip>
extern "C" {
#include <string.h>
#include <unistd.h>
#include <pv_display_backend_helper.h>
}

void dump_buf(uint32_t *buf, uint32_t len)
{
    for(int i = 0; i < len/(sizeof(uint32_t)); i++) {
        std::cout << std::hex << std::setfill('0') << std::setw(8) << buf[i] << " ";
        if(i % 16 == 0) {
            std::cout << '\n';
        }
    }

    std::cout << std::dec;
}

void control_connection_cb(void *opaque, struct libivc_client *client)
{
  struct pv_display_consumer *c = (struct pv_display_consumer *)opaque;
  struct pv_display_backend *b = nullptr;

  std::cout << __PRETTY_FUNCTION__ << ":" << __LINE__ << '\n';
  c->finish_control_connection(c, client);
  std::cout << __PRETTY_FUNCTION__ << ":" << __LINE__ << '\n';
}

void capabilities_request_cb(struct pv_display_consumer *consumer,
			  struct dh_driver_capabilities *request)
{
  dh_display_info info;
  memset(&info, 0x00, sizeof(dh_display_info));

  info.x = 0;
  info.y = 0;
  info.width = 1024;
  info.height = 768;
  info.key = 1;
  
  int rc = consumer->display_list(consumer, &info, 1);
  std::cout << rc << "\n";
}

int main(int argc, const char *argv[])
{
  struct pv_display_consumer *display_consumer;
  struct pv_display_backend *display;
  
  create_pv_display_consumer(&display_consumer, LIBIVC_DOMID_ANY, 1500, nullptr);
  display_consumer->set_driver_data(display_consumer, display_consumer);
  display_consumer->register_control_connection_handler(display_consumer, control_connection_cb);
  display_consumer->register_driver_capabilities_request_handler(display_consumer, capabilities_request_cb);
  display_consumer->start_server(display_consumer);

  while(1) { 
	sleep(1);
  }
  
  return 0;
}
