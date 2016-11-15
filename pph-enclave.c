#include <sgx.h>
#include <sgx-user.h>
#include <sgx-kern.h>
#include <sgx-lib.h>
#include <stdio.h>
#include <string.h>

//Test enclave code called from PPH
void enclave_main()
{
  char buff [100];
  puts("hello from other world");
  //Write code to generate secret and write back to client
  sgx_enclave_read(buff,100);
  puts(buff);
  sgx_enclave_write("OK",2);
  sgx_exit(NULL);
}
