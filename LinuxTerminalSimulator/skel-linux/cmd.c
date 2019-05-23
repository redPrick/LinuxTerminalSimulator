/**
 *Operating Systems 2013-2017 - Assignment 2
 *
 *TODO Name, Group
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 *Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	//in case of no param
	int result = 0;
	char *path = get_word(dir);

	//this will change the value of result
	if (path != NULL && strcmp(path, "") != 0)
		result = chdir(path);

	return result;
}

/**
 *Internal exit/quit command.
 */
static int shell_exit(void)
{
	return SHELL_EXIT;
}

static void shell_redirect(char *filename, int filedesc, int redir_flag)
{
	int src_fd, rc;


	switch (redir_flag) {
	case 0: //stdout
		src_fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		break;
	case 1: //append
		src_fd = open(filename, O_CREAT | O_WRONLY | O_APPEND, 0644);
		break;
	case 2: //append
		src_fd = open(filename, O_CREAT | O_WRONLY | O_APPEND, 0644);
		break;
	case 3: //stdin
		src_fd = open(filename, O_RDONLY, 0644);
		break;
	default:
		return;
	}

	DIE(src_fd < 0, "open");

	rc = dup2(src_fd, filedesc);
	DIE(rc < 0, "dup");

	rc = close(src_fd);
	DIE(rc < 0, "close");

}

//elibereaza memoria comenzii
static void freeCommand(char **command, int size)
{
	int i = 0;

	for (; i < size; i++)
		free(command[i]);

	free(command);
}


/**
 *Parse a simple command (internal, environment variable assignment,
 *external command).
 */


static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/*TODO sanity checks */
	DIE(s == NULL, "NULL command");
	DIE(s->up != father, "different parent");

	int exitStatus = 0, argsCount = 0, wait_ret = 0, res;
	char **command = get_argv(s, &argsCount);

	//comanda de exit/quit
	if (strcmp(command[0], "exit") == 0 ||
		strcmp(command[0], "quit") == 0) {
		exitStatus = shell_exit();

		//eliberare memorie
		freeCommand(command, argsCount);
		return exitStatus;
	}

	//verifica variabile de mediu
	if (s->verb->next_part != NULL)
		if (get_word(s->verb->next_part)[0] == '=') {
			char *delimiter = strtok(command[0], "=");

			char *key = (char *)malloc(strlen(delimiter) + 1);

			strcpy(key, delimiter);

			delimiter = strtok(NULL, "=");
			char *value = (char *)malloc(strlen(delimiter) + 1);

			strcpy(value, delimiter);

			res = setenv(key, value, 1);
			DIE(res < 0, "setenv");

			free(key);
			free(value);
			freeCommand(command, argsCount);
			return EXIT_SUCCESS;
		}

	//comanda de cd
	if (strcmp(command[0], "cd") == 0) {
		if (get_word(s->out) != NULL) {
			int src_fd, rc;

			src_fd = open(get_word(s->out),
			 O_CREAT | O_WRONLY | O_TRUNC, 0644);
			DIE(src_fd < 0, "open");

			rc = close(src_fd);
			DIE(rc < 0, "close");
		}
		exitStatus = shell_cd(s->params);
		freeCommand(command, argsCount);

		return exitStatus;
	}

	int redir_flag;
	int pid = fork();

	switch (pid) {
	case -1:
		DIE(pid < 0, "fork");
		break;
	case 0:
		// 0 for input
		// 0 for output to stdout
		// 0 for output to stderr
		// 1 to append to stdout
		// 2 to append to stderr

		redir_flag = s->io_flags;
		//fisierul de stdin
		if (s->in != NULL)
			shell_redirect(get_word(s->in), STDIN_FILENO, 3);

		//fisierul de stdout
		if (s->out != NULL) {
			shell_redirect(get_word(s->out),
			 STDOUT_FILENO, redir_flag);

			//fisierul de stderr
			if (s->err != NULL) {
				if (strcmp(get_word(s->out),
					get_word(s->err)) == 0)
					//if the file name
					//in both lists, copy desc
					dup2(STDOUT_FILENO, STDERR_FILENO);
				else
					shell_redirect(get_word(s->err),
					STDERR_FILENO, redir_flag);
			}
		} else
			if (s->err != NULL)
				shell_redirect(get_word(s->err),
				STDERR_FILENO, 1);

		if (strcmp(command[0], "cd") != 0) {
			//executa comanda propriu zisa
			execvp(command[0], command);
			fprintf(stderr, "Execution failed for '%s'\n", command[0]);
			freeCommand(command, argsCount);

			exit(EXIT_FAILURE);
		}
		break;


	default:
		freeCommand(command, argsCount);
		wait_ret = waitpid(pid, &exitStatus, 0);
		DIE(wait_ret < 0, "waitpid");
		if (WIFEXITED(exitStatus))
			return WEXITSTATUS(exitStatus);
		else
			return EXIT_FAILURE;
		break;

	}
	return exitStatus;
}

static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/*TODO execute cmd1 and cmd2 simultaneously */
	int exitStatus, wait_ret;
	int pid = fork();

	switch (pid) {
	case -1:
		DIE(pid < 0, "fork");
		break;
	case 0:
		exitStatus = parse_command(cmd1, level, father);
		DIE(exitStatus < 0, "parallel");
		return EXIT_SUCCESS;
	default:
		exitStatus = parse_command(cmd2, level, father);
		DIE(exitStatus < 0, "parallel");
		break;
	}

	wait_ret = waitpid(pid, &exitStatus, 0);
	DIE(wait_ret < 0, "waitpid");
	if (WIFEXITED(exitStatus))
		return WEXITSTATUS(exitStatus);
	else
		return EXIT_FAILURE;

	return exitStatus;/*TODO replace with actual exit status */
}

/**
 *Run commands by creating an anonymous pipe (cmd1 | cmd2)
 */
static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/*TODO redirect the output of cmd1 to the input of cmd2 */
	int fildes[2], pid1, pid2, wait_ret1, ret, wait_ret2, exitStatus;

	pid1 = fork();

	switch (pid1) {
	case -1:
		DIE(pid1 < 0, "fork");
	case 0:
		ret = pipe(fildes);
		DIE(ret < 0, "pipe");
		pid2 = fork();
		switch (pid2) {
		case -1:
			DIE(pid2 < 0, "fork");
			break;
		case 0:
			ret = close(fildes[1]);//close the write
			DIE(ret < 0, "close");

			ret = dup2(fildes[0], STDIN_FILENO);
			DIE(ret < 0, "dup2");

			ret = close(fildes[0]);//close the read
			DIE(ret < 0, "close");

			ret = parse_command(cmd2, level, father);
			DIE(ret < 0, "pipe");

			exit(ret);
		default:
			ret = close(fildes[0]);//close the read
			DIE(ret < 0, "close");

			ret = dup2(fildes[1], STDOUT_FILENO);
			DIE(ret < 0, "dup2");

			ret = close(fildes[1]);//close the write
			DIE(ret < 0, "close");

			ret = parse_command(cmd1, level, father);
			DIE(ret < 0, "pipe");

			ret = close(STDOUT_FILENO);//close stdout
			DIE(ret < 0, "close");

			//asteapta copilul din al 2-lea fork()
			wait_ret2 = waitpid(pid2, &exitStatus, 0);
			DIE(wait_ret2 < 0, "waitpid");
			if (WIFEXITED(exitStatus))
				exit(WEXITSTATUS(exitStatus));
			else
				return EXIT_FAILURE;
		}


	default:
		//asteapta copilul din al primul fork()
		wait_ret1 = waitpid(pid1, &exitStatus, 0);
		DIE(wait_ret1 < 0, "waitpid");
		if (WIFEXITED(exitStatus))
			return WEXITSTATUS(exitStatus);
		else
			return EXIT_FAILURE;

	}


	return true;
}

/**
 *Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/*TODO sanity checks */
	DIE(c == NULL, "NULL command");
	DIE(c->up != father, "different parent");
	int exitStatus = 1;

	if (c->op == OP_NONE) {
		exitStatus = parse_simple(c->scmd, level + 1, c);
		return exitStatus;
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		exitStatus = parse_command(c->cmd1, level + 1, c);
		exitStatus = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PARALLEL:
		exitStatus = do_in_parallel(c->cmd1, c->cmd2, level + 1, c);
		break;

	case OP_CONDITIONAL_NZERO:
		exitStatus = parse_command(c->cmd1, level + 1, c);
		if (exitStatus != 0)
			exitStatus = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_CONDITIONAL_ZERO:
		exitStatus = parse_command(c->cmd1, level + 1, c);
		if (exitStatus == 0)
			exitStatus = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PIPE:
			exitStatus = do_on_pipe(c->cmd1, c->cmd2, level + 1, c);
		break;

	default:
		return SHELL_EXIT;
	}

	return exitStatus;/*TODO replace with actual exit code of command */
}
