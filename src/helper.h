#ifndef HELPER_H
# define HELPER_H

#include "sockslink.h"

/*
void helper_init(struct helper *helper);
void helper_clear(struct helper *helper);

bool helper_running(struct helper *helper);
int helper_start(struct helper *helper);
int helper_stop(struct helper *helper);

int helper_auth_none(struct helper *helper, struct client *client);
int helper_auth_username(struct client *client,
			 const char *username,
			 const char *password);

*/
static int helper_init(Helper *helper) { return 0; }
static int helper_start(Helper *helper) { return 0; }
static int helper_stop(Helper *helper) { return 0; }
static int helper_clear(Helper *helper) { return 0; }
static int helper_restart(Helper *helper) { return 0; }

#endif /* !HELPER_H */
