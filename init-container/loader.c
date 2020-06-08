#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>

static char **load_list(const char *file_name) {
	struct stat filestatus;
	int s_ret = stat(file_name, &filestatus);
	if (s_ret != 0) {
		return NULL;
	}
	int len = filestatus.st_size;
	char *buf = malloc(len+1);
	int fd = open(file_name, 0);
	if (fd == -1) {
		return NULL;
	}
	int rlen = read(fd, buf, len);
	if (rlen != len) {
		return NULL;
	}
	close(fd);
	int cnt = 0;
	for (int i=0; i<len; ++i) {
		if (buf[i]=='\n') {
			++cnt;
		}
	}
	char **ret = calloc(cnt+1, sizeof(char *));
	cnt = 0;
	char *start = buf;
	for (int i=0; i<len; ++i) {
		if (buf[i] == '\n') {
			buf[i++]=0;			
			ret[cnt++] = start;
			start = &buf[i];
		}
	}
	buf[len]=0;
	if (start != &buf[len]) {
		ret[cnt++] = start;
	}
	ret[cnt++] = 0;
	return ret;
}

static void print_list(char **argv) {
	if (argv == NULL) {
		printf("NULL\n");
		return;
	}

	for (char **p = argv; *p; p++) {
		printf("line=[%s]\n", *p);
	}
}

struct parser {
	char *pos, *end;
	char *key[2], *value[2];
	int state;
};

/*
 * 0 - init
 * 1 - in key
 * 2 - 
 */
enum {
	S_INIT,
	S_IN_KEY,
	S_IN_VAL,
	S_IN_QVAL,
	S_IN_SEP,
};

static void parser_init(struct parser *p, char *buf, int len) {
	p->pos = buf;
	p->end = buf+len;
	p->key[0] = buf;
	p->key[1] = buf;
	p->value[0] = 0;
	p->value[1] = 0;
	p->state = 0;
}

static bool parser_next(struct parser *p) {
	char *pos = p->pos;
	while (pos < p->end) {
		switch (p->state) {
			case S_INIT:
				if (*pos == '=') {
					p->key[1] = pos;
					++pos;
					p->state = S_IN_VAL;
					p->value[0] = pos;
					p->value[1] = pos;
					continue;
				}
				if (*pos == ' ') {
					p->key[1] = pos;
					++pos;
					p->state = S_IN_SEP;
					p->pos = pos;
					return true;
				}
				p->key[1] = pos;
				++pos;
				break;
			case S_IN_VAL:
				if (*pos == '"') {
					++pos;
					p->state = S_IN_QVAL;
					p->value[1] = pos;
					continue;
				}
				if (*pos == ' ') {
					p->value[1] = pos;
					++pos;
					p->state = S_IN_SEP;
					p->pos = pos;
					return true;
				}
				p->value[1]=pos;
				++pos;
				break;
			case S_IN_QVAL:
				if (*pos == '"') {
					++pos;
					p->state = S_IN_VAL;
					p->value[1] = pos;
					continue;
				}
				p->value[1] = pos;
				++pos;
				break;
			case S_IN_SEP:
				if (*pos == ' ') {
					++pos;
					continue;
				}
				p->key[0] = pos;
				p->key[1] = pos;
				p->value[0] = 0;
				p->value[1] = 0;
				p->state = S_INIT;
				continue;
		}
	}

	p->pos = pos;
	bool have_val =  p->state == S_IN_QVAL || p->state == S_IN_VAL;
	p->state = S_IN_SEP;

	return have_val;
}

static bool eq_strings(const char *left[2], const char *right[2]) {
	const char *pleft = left[0];
	const char *pright = right[0];

	while (pleft < left[1] && pright < right[1]) {
		if (*pleft++ != *pright++) {
			return false;
		}
	}
	return pleft == left[1] && pright == right[1];
}

static char *copy_string(char *s[2]) {
	char *p = malloc(s[1] - s[0]+1);

	if (s[0] == s[1]) {
		*p = 0;
		return p;
	}
	
	char *it = s[0];
	char *dst_it = p;
	if (*it == '"') {
		it++;
		while (it < s[1]) {
			*dst_it++ = *it++;
		}
		if (dst_it[-1] == '"') {
			dst_it[-1] = 0;
		}
		else {
			*dst_it++ = 0;
		}
	}
	else {
		while (it < s[1]) {
			*dst_it++ = *it++;
		}
		*dst_it++ = 0;
	}
	return p;
}


static char **args_list(const char *prefix) {
	char buf[16000];
	int fd = open("/proc/cmdline", 0);
	if (fd == -1) {
		exit(1);
		return NULL;
	}
	int len = read(fd, buf, sizeof(buf));
	if (len == -1) {
		return NULL;
	}

	struct parser p;
	const char *pv[2];
       	pv[0] = prefix;
	pv[1] = prefix + strlen(prefix);
	int cnt = 0;
	parser_init(&p, buf, len);
	while (parser_next(&p)) {
		if (eq_strings(pv, (const char **)p.key)) {
			++cnt;
		}
	}
	cnt +=1;
	char **ret = calloc(cnt, sizeof(char *));
	parser_init(&p, buf, len);
	cnt=0;
	while (parser_next(&p)) {
		if (eq_strings(pv, (const char **)p.key)) {
			ret[cnt++] = copy_string(p.value);
		}
	}
	ret[cnt++] = NULL;
	return ret;
}

static bool is_empty_list(char **l) {
	return l == NULL || l[0] == NULL;
}

static char **concat_list(char **l1, char **l2) {
	int cnt = 0;

	if (l1) {
		for (char **l = l1; *l; ++l) {
			++cnt;
		}
	}

	if (l2) {
		for (char **l = l2; *l; ++l) {
			++cnt;
		}
	}

	char **ret = calloc(cnt+1, sizeof(char *));
	cnt = 0;
	for (char **l = l1; l && *l; ++l) {
		ret[cnt++] = *l;
	}
	for (char **l = l2; l && *l; ++l) {
		ret[cnt++] = *l;
	}
	ret[cnt++] =0;
	return ret;
}
	
int main(int argc, const char *argv[]) {

#ifdef TESTS
	char buf[] = "BOOT_IMAGE=/vmlinuz-4.15.0-46-generic "
		"root=UUID=7ad987ec-ecf0-49c7-a8d2-bcc3c69e79a2 ro "
		"apparg=arg1 apparg=\"ala ma kota\" "
		"quiet splash vt.handoff=1 apparg=test1\0";
	struct parser p;
	printf("%s\n\n", buf);
	parser_init(&p, buf, sizeof(buf)-1);
	while (parser_next(&p)) {
		printf("key=[%s], val=[%s]\n", copy_string(p.key), copy_string(p.value));
	}

#else
	int err = chroot("/mnt/app-rw");
	if (err == -1) {
		return -1;
	}
	char **env = load_list("/.env");
	char **entrypoint = load_list("/.entrypoint");
	char **cmd = load_list("/.cmd");
	char **args = args_list("apparg");

	char **exec_args = is_empty_list(args) ? concat_list(entrypoint, cmd) : concat_list(entrypoint, args);

	print_list(env);
	print_list(exec_args);
	chdir("/");
	putenv("TERM=linux");
	putenv("GOLEM_VMKIT=1");
	for (char **e = env; *e; ++e) {
		putenv(*e);
	}

	execvpe(exec_args[0], exec_args, env);
	perror("execve");
#endif
	return 0;
}

