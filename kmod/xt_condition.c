/*
 * xt_condition
 * iptables kernel module for userspace condition match.
 *
 * Copyright (c) Theo Julienne <theo@github.com>
 *
 * Based on original ipt_condition:
 * Copyright (c) Stephane Ouellette <ouellettes@videotron.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <asm/atomic.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include "xt_condition.h"


#ifndef CONFIG_PROC_FS
#error  "Proc file system support is required for this module"
#endif


MODULE_AUTHOR("Theo Julienne <theo@github.com>");
MODULE_DESCRIPTION("Allows rules to match against condition variables");
MODULE_LICENSE("GPL");


struct condition_variable {
	struct condition_variable *next;
	struct proc_dir_entry *status_proc;
	char name[CONDITION_NAME_LEN];
	atomic_t refcount;
	int enabled;
};


static rwlock_t list_lock;
static struct condition_variable *head = NULL;
static struct proc_dir_entry *proc_net_condition = NULL;


static int
xt_condition_procfs_open(struct inode *inode, struct file *file)
{
	if (!try_module_get(THIS_MODULE))
		return -EPERM; /* Not an ideal error, but better than failing later */
	file->private_data = PDE_DATA(inode);
	return 0;
}

static int
xt_condition_procfs_close(struct inode *inode, struct file *file)
{
	module_put(THIS_MODULE);
	return 0;
}

static ssize_t
xt_condition_read_info(struct file *file, char *buffer,
	                    size_t length, loff_t *offset)
{
	struct condition_variable *var =
	    (struct condition_variable *)file->private_data;

	if (*offset == 0 && length >= 2) {
		char tmp[2] = {
			(var->enabled) ? '1' : '0',
			'\n'
		};
		if (copy_to_user(buffer, tmp, 2))
			return -EFAULT;
		*offset += 2;
		return 2;
	}

	return 0;
}

static ssize_t
xt_condition_write_info(struct file *file, const char *buffer,
                         size_t length, loff_t *off)
{
	struct condition_variable *var =
	    (struct condition_variable *)file->private_data;

	if (length >= 1) {
		char tmp[2];

		if (copy_from_user(tmp, buffer, 1)) {
			return -EFAULT;
		}

		/* Match only on the first character */
		switch (tmp[0]) {
		case '0':
			var->enabled = 0;
			break;
		case '1':
			var->enabled = 1;
		}

		return length; /* say we consumed all the data */
	}

	return 0;
}

static bool
xt_condition_match(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct condition_info *info = 
		(const struct condition_info *)par->matchinfo;
	struct condition_variable *var = info->var;

	WARN_ON(var == NULL);

	if (var == NULL)
		return info->invert;

	return var->enabled ^ info->invert;
}

static const struct file_operations proc_fops = {
	.owner   = THIS_MODULE,
	.open    = xt_condition_procfs_open,
	.read    = xt_condition_read_info,
	.write   = xt_condition_write_info,
	.release = xt_condition_procfs_close,
};

static int
_xt_condition_safe_get_or_create(struct condition_info *info)
{
	struct condition_variable *var, *newvar;
	char proc_name[CONDITION_NAME_LEN] = "";

	/* Ensure input string null terminated */
	strncpy(proc_name, info->name, CONDITION_NAME_LEN);
	proc_name[CONDITION_NAME_LEN-1] = '\0';

	info->var = NULL;

	/* The first step is to check if the condition variable already exists. */
	/* Here, a read lock is sufficient because we won't change the list */
	read_lock(&list_lock);

	for (var = head; var; var = var->next) {
		if (strcmp(proc_name, var->name) == 0) {
			atomic_inc(&var->refcount);
			info->var = var;
			read_unlock(&list_lock);
			return 0;
		}
	}

	read_unlock(&list_lock);

	/* At this point, we need to allocate a new condition variable */
	newvar = kmalloc(sizeof(struct condition_variable), GFP_KERNEL);

	if (!newvar)
		return -ENOMEM;

	/* Create the condition variable's proc file entry */
	newvar->status_proc = proc_create_data(proc_name, 0644, proc_net_condition, &proc_fops, newvar);

	if (!newvar->status_proc) {
	  /*
	   * There are two possibilities:
	   *  1- Another condition variable with the same name has been created, which is valid.
	   *  2- There was a memory allocation error.
	   */
		kfree(newvar);
		read_lock(&list_lock);

		for (var = head; var; var = var->next) {
			if (strcmp(proc_name, var->name) == 0) {
				atomic_inc(&var->refcount);
				info->var = var;
				read_unlock(&list_lock);
				return 0;
			}
		}

		read_unlock(&list_lock);
		return -ENOMEM;
	}

	atomic_set(&newvar->refcount, 1);
	info->var = newvar;
	newvar->enabled = 0;
	strcpy(newvar->name, proc_name);

	write_lock(&list_lock);

	newvar->next = head;
	head = newvar;

	write_unlock(&list_lock);

	return 0;
}

static void
_xt_condition_safe_destroy(struct condition_info *info)
{
	struct condition_variable *var, *prev = NULL;
	char proc_name[CONDITION_NAME_LEN] = "";

	/* Ensure input string null terminated */
	strncpy(proc_name, info->name, CONDITION_NAME_LEN);
	proc_name[CONDITION_NAME_LEN-1] = '\0';

	write_lock(&list_lock);

	for (var = head; var && strcmp(proc_name, var->name);
	     prev = var, var = var->next);

	BUG_ON(var != info->var);

	if (var && atomic_dec_and_test(&var->refcount)) {
		if (prev)
			prev->next = var->next;
		else
			head = var->next;

		write_unlock(&list_lock);
		remove_proc_entry(var->name, proc_net_condition);
		kfree(var);
	} else
		write_unlock(&list_lock);
}

static int
xt_condition_checkentry(const struct xt_mtchk_param *par)
{
	struct condition_info *info = (struct condition_info *)par->matchinfo;
	
	return _xt_condition_safe_get_or_create(info);
}

static void
xt_condition_destroy(const struct xt_mtdtor_param *par)
{
	struct condition_info *info = (struct condition_info *)par->matchinfo;
	
	_xt_condition_safe_destroy(info);
}

static int
condition_tg4_check(const struct xt_tgchk_param *par)
{
	struct condition_info *info = (struct condition_info *)par->targinfo;
	
	return _xt_condition_safe_get_or_create(info);
}

static unsigned int
condition_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct condition_info *info = (struct condition_info *)par->targinfo;
	struct condition_variable *var = info->var;

	WARN_ON(var == NULL);

	if (var != NULL)
		var->enabled = info->invert ? 0 : 1;

	return XT_CONTINUE;
}


static void
condition_tg4_destroy(const struct xt_tgdtor_param *par)
{
	struct condition_info *info = (struct condition_info *)par->targinfo;
	
	_xt_condition_safe_destroy(info);
}

static struct xt_match condition_match __read_mostly = {
	.name       = "condition",
	.family     = NFPROTO_UNSPEC,
	.checkentry = xt_condition_checkentry,
	.match      = xt_condition_match,
	.destroy    = xt_condition_destroy,
	.matchsize  = sizeof(struct condition_info),
	.me         = THIS_MODULE,
};

static struct xt_target condition_tg4_reg __read_mostly = {
	.name		= "CONDITION",
	.family		= NFPROTO_UNSPEC,
	.target		= condition_tg4,
	.targetsize	= sizeof(struct condition_info),
	.checkentry	= condition_tg4_check,
	.destroy	= condition_tg4_destroy,
	.me		    = THIS_MODULE,
};

static int __init
init(void)
{
	int errorcode;

	rwlock_init(&list_lock);
	proc_net_condition = proc_mkdir("ipt_condition", init_net.proc_net);

	if (proc_net_condition) {
		errorcode = xt_register_match(&condition_match);

		if (!errorcode) {
			errorcode = xt_register_target(&condition_tg4_reg);

			if (errorcode)
				xt_unregister_match(&condition_match);
		}

		if (errorcode)
			remove_proc_entry("ipt_condition", init_net.proc_net);
	} else
		errorcode = -EACCES;

	return errorcode;
}


static void __exit
fini(void)
{
	xt_unregister_match(&condition_match);
	xt_unregister_target(&condition_tg4_reg);
	remove_proc_entry("ipt_condition", init_net.proc_net);
}

module_init(init);
module_exit(fini);
