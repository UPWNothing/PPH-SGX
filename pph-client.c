/*
 *  Copyright (C) 2015, OpenSGX team, Georgia Tech & KAIST, All Rights Reserved
 *
 *  This file is part of OpenSGX (https://github.com/sslab-gatech/opensgx).
 *
 *  OpenSGX is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  OpenSGX is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with OpenSGX.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <getopt.h>
#include <time.h>

#include <sgx.h>
#include <sgx-user.h>
#include <sgx-crypto.h>
#include <sgx-utils.h>
#include <sgx-loader.h>
#include <libpolypasswordhasher.h>

// a context is the data structure that holds the information about the
// whole pph store
pph_context *context;

void poly_pass_test()
{
	

  // Setting a theshold of two means that we are going to need two accounts
  // to attempt bootstrapping.
  uint8 threshold = 2;

  // isolated-check-bits will be set to two, so users can login after any reboot
  // event.
  uint8 isolated_check_bits = 2;



  // setup the context, this will generate us the shares, setup information
  // needed to operate and initialize all of the data structures.
  context = pph_init_context(threshold, isolated_check_bits);


  // add some users, we send the context, a username, a password and a number
  // of shares to assign to the user. The a user can have many shares, and count
  // more towards the threshold.
  pph_create_account(context, "Alice", strlen("Alice"),
                                       "I.love.bob", strlen("I.love.bob"), 1);
  pph_create_account(context, "Bob", strlen("Bob"),
                       "i.secretly.love.eve",strlen("i.secretly.love.eve"),1);

  // when creating a user with no shares, we get a *shielded* account.
  // Shielded accounts have their hash encrypted and are unable to
  // bootstrap a context
  pph_create_account(context,"Eve", strlen("Eve"),
                                   "i'm.all.ears", strlen("i'm.all.ears"), 0);

  // to check a login we must have an bootstrapped context, we send the credentials and
  // receive an error in return
  if(pph_check_login(context, "Alice", strlen("Alice"), "I.love.bob",
         strlen("I.love.bob")) == PPH_ERROR_OK){
    printf("welcome alice\n");
  }else{
    printf("generic error message\n");
  }

  // We can, then store a context to work with it later, have in mind the
  // context will be stored in a locked state and alice and bob will have
  // to bootstrap it.
  pph_store_context(context,"securepasswords");

  // We should destroy a context when we finish to free sensible data, such as
  // the share information. The pph_destroy_context function ensures that all
  // of the data structures associated with the context are properly freed.
  pph_destroy_context(context);

  // time goes by and we want to start working again, with the same information
  // about alice, bob and eve...

  // We reload our context, we reload a context from disk using
  // pph_reload_context, providing a filename, remember that the obtained
  // context is locked after loading from disk.
  context = pph_reload_context("securepasswords");

  // at this point we can still provide a login service, thanks to the isolated
  // bytes extension. But in order to create accounts and to provide full login
  // functionality, we should bootstrap the store.
  if(pph_check_login(context, "Alice",strlen("alice"), "i'm.trudy",
                                          strlen("i'm.trudy")) == PPH_ERROR_OK){
    printf("welcome alice!\n"); // this won't happen
  }else{
    printf("go away trudy!\n");
  }

  // during the locked phase, we are unable to create **protector** account
  if(pph_create_account(context, "trudy", strlen("trudy"), "I'm.trudy",
                           strlen("I'm.trudy"), 1) == PPH_CONTEXT_IS_LOCKED){
    printf("Sorry, we cannot create accounts at this time\n");
  }else{
    printf("This shouldn't happen\n");
  }

  // But Nevertheless we can create *shielded* account
  if(pph_create_account(context, "trudy", strlen("trudy"), "I'm.trudy",
                           strlen("I'm.trudy"), 0) == PPH_ERROR_OK){
    printf("Trudy shielded account created\n");
  }else{
    printf("This shouldn't happen\n");
  }

  // In order to be able to create accounts, we must unlock the vault.
  // for this, we setup an array of username strings and an array of password
  // strings.
  char **usernames = malloc(sizeof(*usernames)*2);
  usernames[0] = strdup("Alice");
  usernames[1] = strdup("Bob");

  char **passwords = malloc(sizeof(*passwords)*2);
  passwords[0] = strdup("I.love.bob");
  passwords[1] = strdup("i.secretly.love.eve");

  unsigned int *username_lengths = malloc(sizeof(*username_lengths)*2);
  username_lengths[0] = strlen("Alice");
  username_lengths[1] = strlen("bob");

  unsigned int *password_lengths = malloc(sizeof(*password_lengths)*2);
  password_lengths[0] = strlen("I.love.bob");
  password_lengths[1] = strlen("i.secretly.love.eve");

  // if the information provided was correct, the pph_unlock_password_data
  // returns PPH_ERROR_OK, transitions to normal operation and recovers the shares.
  pph_unlock_password_data(context, 2, usernames, username_lengths, passwords, password_lengths);

  // now the data is unlocked. We can create accounts now.
  pph_create_account(context, "carl", strlen("carl"), "verysafe",
                                                        strlen("verysafe"),0);

  // we can now check accounts using the full feature also (non-isolated-check-bits)
  if(pph_check_login(context, "carl", strlen("carl"), "verysafe",
                                          strlen("verysafe")) == PPH_ERROR_OK){
    printf("welcome back carl\n");
  }else{
    printf("you are not carl\n");
  }

  // we should now store the context and free the data before leaving
  pph_store_context(context,"securepasswords");
 
  free(password_lengths);
  free(usernames);
  free(passwords);
  free(username_lengths);	
}


void pph_destroy()
{
   pph_destroy_context(context);
}

int main(int argc, char *argv[])
{
	  char *binary;
    char *conf=NULL;
    void *entry;
    void *base_addr;
    size_t npages;
    unsigned long entry_offset;
    int toff;

    printf("Enter PPH client code \n");
    poly_pass_test();

  	printf("Before sgx init:\n");
  	if(!sgx_init())
          err(1, "failed to init sgx");
  	printf("after sgx init\n");
  	base_addr = load_elf_enclave("hello.sgx", &npages, &entry, &toff);
    if (base_addr == NULL) {
        err(1, "Please provide valid binary/configuration files.");
    }

	 entry_offset = (uint64_t)entry - (uint64_t)base_addr;

  	tcs_t *tcs = init_enclave(base_addr, entry_offset, npages, conf);
      if (!tcs)
          err(1, "failed to run enclave");
	
	
  	void (*aep)() = exception_handler;
  	char result[20];

    //Instead we request the secret from enclave
    sgx_host_write("good", 4);

	  sgx_enter(tcs, aep);

    //Here ideally we should be able to read back the secret.
    sgx_host_read(result, 20);

    printf("Host read: %s\n", result);

    //destroy the session
    pph_destroy();
	
    return 0;
}
