/*
 Simplest ls program
 Has following restrictions:
	no sort, 
	no total files number printing,
	no extended access right printing,
	no multiple command options (several target directories)
	...


 Author: Irina Leontovich
*/

#include <inttypes.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>

#include <dirent.h>

#include <sys/stat.h>
#include <unistd.h>

#include <string.h>
#include <stdint.h>

#include <limits.h>

#include <pwd.h>
#include <grp.h>

#include <time.h>

#include <signal.h>


/*
 * Char buffer size boundaries detection 
 * The implementation based on intprops.h code:
 * hint:  log10(2) <~ 146/485
 */
#define STR_BUFSIZE_BOUND(bits) ((bits * 146 / 485) + 1)
#define BUFSIZE_BOUND(BOUND) ( STR_BUFSIZE_BOUND((sizeof(BOUND) * CHAR_BIT)) + (BOUND < 0 ? 1 : 0) )

/*
 * Bound on length of the string representing an integer
 */
#define INT_BUFSIZE_BOUND BUFSIZE_BOUND(INT_MAX)

/*
 * Bound on length of the string representing an unsigned integer
 */
#define UINT_BUFSIZE_BOUND BUFSIZE_BOUND(UINT_MAX)

/*
 * Bound on length of the string representing a long 
 */
#define LONG_BUFSIZE_BOUND BUFSIZE_BOUND(LONG_MAX)

#define MAX_OWNER_NAME	80
#define MAX_GROUP_NAME	80
#define MAX_FILE_TIME	25
#define MAX_FILENAME	PATH_MAX

/*
 * True represents output as table
 */
uint8_t long_mode = 0;

/*
 * Output files' list of directory specified this value instead of current directory   
 */
const char *operated_dir = "";

/*
 * File description corresponding to long representation
 */

char file_nlink[UINT_BUFSIZE_BOUND];	// hard link count
char file_owner[MAX_CANON];		// file owner name
char file_group[MAX_CANON];		// file group name
char file_size[LONG_BUFSIZE_BOUND + 2];	// file size in bytes + 2 (just in case if major, minor output)
char file_time[25];			// last access time
char file_realpath[PATH_MAX];		// realpath in link case

enum {
	FILE_TYPE = 0,
	RUSR = 1,
	WUSR = 2,
	XUSR = 3,
	RGRP = 4,
	WGRP = 5,
	XGRP = 6,
	ROTH = 7,
	WOTH = 8,
	XOTH = 9, 
	FILE_DESC_MAX = 10
} file_desc_pos;

char file_taccess[FILE_DESC_MAX + 1];	// file type and access rights as char sequence

/*
 * Detect if file should be ignored or not
 */
#define FILE_IGNORED(name) (name[0] == '.' ? 1 : 0) 

/*
 * Command line options processing
 */
void get_parameters(int argc, char *argv[])
{
	int opt;

        while ((opt = getopt(argc, argv, "l")) != -1) {	
        	switch (opt) {
               	case 'l':
                	long_mode = 1;
                   	break;
                default: /* '?' */
                	fprintf(stderr, "Usage: %s [-l] [name]\n", argv[0]);
                   	exit(EXIT_FAILURE);
               }
	}

	if (optind < argc) {
		operated_dir = argv[optind];
	}
}

/*
 * Full file name composition
 * Return pointer to allocated buffer, which contains filename or NULL if error
 * After using filename buffer must be cleaned with destroy_filename
 */
char *create_filename(const char *path, const char *name) 
{
	size_t size = strlen(path) + strlen(name);
	if (strlen(path) >= 1 && path[strlen(path)-1] != '/') {
		size++;
	}
	
	char *str = malloc(size + 1);
	if (str == NULL) {
		fprintf(stderr, "malloc : Error is occurred: %s\n", strerror(errno));
		return str;
	}

	str[0] = 0;

	memcpy(str, path, strlen(path));
	if (strlen(path) >= 1 && path[strlen(path)-1] != '/') {
		memset(str + strlen(path), '/', 1);
		strcpy(str + strlen(path) + 1, name);
	} else {
		strcpy(str + strlen(path), name);
	}
	
	return str;
}

/*
 * Cleaning buffer which was allocated using create_filename
 */
void destroy_filename(char *filename) 
{
	if (filename != NULL) {
		free(filename);
	}
}

/*
 * Retrieving owner of file represented by uid
 */
uint8_t put_owner(uid_t uid)
{
	errno = 0;
	struct passwd *pw = getpwuid(uid);
	if (errno != 0) {
		fprintf(stderr, "getpwuid: Error is occurred: %s\n", strerror(errno));
		return 0;
	}

        if (pw != NULL) {
		snprintf(file_owner, sizeof(file_owner), "%s", pw->pw_name);
		return 1;
	}
	
	return 0;
}

/*
 * Retrieving group of file represented by gid
 */
uint8_t put_group(gid_t gid)
{
	errno = 0;
	struct group *gr = getgrgid(gid);
	if (errno != 0) {
		fprintf(stderr, "getpwuid: Error is occurred: %s\n", strerror(errno));
		return 0;
	}

        if (gr != NULL) {
		snprintf(file_group, sizeof(file_group), "%s", gr->gr_name);
		return 1;
	}

	return 0;
}

/*
 * Retrieving file access right
 */
void put_rights(mode_t mode) 
{
	file_taccess[RUSR] = ((mode & S_IRUSR) ? 'r' : '-'); 
	file_taccess[WUSR] = ((mode & S_IWUSR) ? 'w' : '-'); 
	file_taccess[XUSR] = ((mode & S_IXUSR) ? 'x' : '-'); 

	file_taccess[RGRP] = ((mode & S_IRGRP) ? 'r' : '-'); 
	file_taccess[WGRP] = ((mode & S_IWGRP) ? 'w' : '-'); 
	file_taccess[XGRP] = ((mode & S_IXGRP) ? 'x' : '-'); 

	file_taccess[ROTH] = ((mode & S_IROTH) ? 'r' : '-'); 
	file_taccess[WOTH] = ((mode & S_IWOTH) ? 'w' : '-'); 
	file_taccess[XOTH] = ((mode & S_IXOTH) ? 'x' : '-'); 
}

inline void put_size(long size) 
{
	snprintf(file_size, sizeof(file_size), "%ld", size);
}

inline void put_dev(dev_t rdev)
{
	snprintf(file_size, sizeof(file_size), "%d, %d", major(rdev), minor(rdev));
}

inline void put_nlink(unsigned int nlink)
{
	snprintf(file_nlink, sizeof(file_nlink), "%d", nlink);
}

/*
 * Format time string
 */
uint8_t put_time(long atime)
{
	time_t atm = (time_t)atime;
	struct tm *tsm = localtime(&atm);
	if (tsm == NULL) {
		fprintf(stderr, "localtime: Error is occurred\n");
		return 0;
	} 
	strftime(file_time, sizeof(file_time), "%c", tsm);
	return 1;
}

/*
 * Print directory content
 */
void print_dir(const char *name) 
{
	DIR *dir;
	dir = opendir(name);
	if (dir == NULL) {
		switch (errno) {
			case EACCES:
				fprintf(stderr, "'%s' : Permission denied\n", name);
				return; 
			case ENOENT:
				fprintf(stderr, "'%s': Doesn't exist\n", name);
				return; 
			case ENOTDIR:
				fprintf(stderr, "'%s': Not a directory\n", name);
				return;
			default:
				fprintf(stderr, "'%s': Error is occurred: %d\n", name, errno); 	
				return;
		}
	}

	struct dirent *entry;
	errno = 0;
	do {
		entry = readdir(dir);
		if (entry == NULL) {
			if (errno != 0) {
				fprintf(stderr, "readdir: error is occurred: %d\n", errno);
			}
			break;
		}

		if (FILE_IGNORED(entry->d_name)) {
			continue;
		}

		#ifdef _DIRENT_HAVE_D_TYPE
		switch (entry->d_type) {
			case DT_BLK:
				file_taccess[FILE_TYPE] = 'b';
				break;
			case DT_CHR:
				file_taccess[FILE_TYPE] = 'c';
				break;
			case DT_DIR:  
				file_taccess[FILE_TYPE] = 'd';
				break;
			case DT_FIFO:
				file_taccess[FILE_TYPE] = 'f';
				break;
			case DT_LNK:
				file_taccess[FILE_TYPE] = 'l';
				break;
			case DT_REG:
				file_taccess[FILE_TYPE] = '-';
				break;
			case DT_SOCK:
				file_taccess[FILE_TYPE] = 's';
				break;
			case DT_UNKNOWN:
				file_taccess[FILE_TYPE] = 'u';
				break;
		}
		#else
		file_taccess[FILE_TYPE] = 0;
		#endif

		if (!long_mode) {
			printf("%s ", entry->d_name);
			continue;
		}

			char *filename = create_filename(operated_dir, entry->d_name);
		if (filename == NULL) {
			break;
		}

		struct stat fstat;
		if (stat(filename, &fstat) == -1) {
			fprintf(stderr, "\n%s: stat: Error is occurred: %s\n", entry->d_name, strerror(errno));
			destroy_filename(filename);
			break; 	
		}
		
		put_rights(fstat.st_mode);
		put_nlink(fstat.st_nlink);
		if (S_ISCHR(fstat.st_mode) || S_ISBLK(fstat.st_mode)) {
			put_dev(fstat.st_rdev);
		} else {
			put_size(fstat.st_size);
		}
		
		if (!put_owner(fstat.st_uid) || !put_group(fstat.st_gid) || !put_time(fstat.st_atime)) {
			destroy_filename(filename);
			break;
		}

		file_realpath[0] = 0;
		char *path = NULL;
		if  (S_ISLNK(fstat.st_mode) || (entry->d_type == DT_LNK)) {
			path = realpath(filename, file_realpath);
			if (path == NULL) {
				fprintf(stderr,"realpath: error is occurred: %s\n", strerror(errno));
				errno = 0;
			}
		}
		
		// This is the simplest realization of format output
		// It may cause an invalid alignment
		// The better way is collecting of whole directory content
		// in dynamic allocated area, but in case of huge amount of files
		// it looks like more efficient implementation
		
		if (path) {
			printf("%s %s\t%s\t%s\t%s\t%s %s -> %s\n", file_taccess, file_nlink, file_owner, file_group, file_size, file_time, entry->d_name, file_realpath);
		} else {
			printf("%s %s\t%s\t%s\t%s\t%s %s\n", file_taccess, file_nlink, file_owner, file_group, file_size, file_time, entry->d_name);
		}

		destroy_filename(filename);
		
		// In realistic ls implementation the author process signals 
		// by his own signal handler, but I don't find any profit in my case
		// process_signals();
		//

	} while (1);
	
	if (!long_mode) {
		printf("\n");
	}

	closedir(dir);
}

int main(int argc, char *argv[])
{
	// Initialization based on command options
	get_parameters(argc, argv);
	
	// Set current directory as goal if not specified
	if (strlen(operated_dir) == 0) {
		operated_dir = ".";
	}
	
	file_taccess[sizeof(file_taccess)-1] = 0;
	file_group[0] = file_owner[0] = file_nlink[0] = file_size[0] = file_time[0] = 0;
	
	// Block suspending program
	// Suspending doesn't make sense, 
	// furthermore if huge amount of files per directory exist 
	// there are troubles with interruption after background SIGCONT
	// This trouble lies around huge stdout
	// So I decided to block STOP
	// May be the better solution is to interrupt the program or get user more freedom
	sigset_t blocked_sigs; 

	sigemptyset(&blocked_sigs);
	sigaddset(&blocked_sigs, SIGTSTP);

	sigprocmask(SIG_BLOCK, &blocked_sigs, NULL);

	// Show files
	print_dir(operated_dir);

        exit(EXIT_SUCCESS);
}
