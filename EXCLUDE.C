
/* **********************************************************************
   * Exclude.c                                                          *
   *                                                                    *
   * Copyright (c) 1991, Fredric L. Rice. All rights reserved.          *
   * FidoNet: 1:102/901.0.                                              *
   *									*
   * Compile in LARGE memory model only.				*
   *                                                                    *
   * o Compiles a list of nodes that are to be excluded based upon the  *
   *   flags field of the nodelist and by key-words in the              *
   *   configuration file.                                              *
   *                                                                    *
   * o Scans mail directories for messages originating from any of the  *
   *   listed nodes and erases the messages, appending information to a *
   *   log file.                                                        *
   *                                                                    *
   * o Alternatly returns a message to the originating node.            *
   *                                                                    *
   ********************************************************************** */

#include <alloc.h>
#include <conio.h>
#include <ctype.h>
#include <dir.h>
#include <dos.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef __LARGE__
    #error You must compile in Large memory model
#endif

/* **********************************************************************
   * Define various macros that will be needed.                         *
   *                                                                    *
   ********************************************************************** */

#define skipspace(s)    while (isspace(*s))  ++(s)

/* **********************************************************************
   * Define the global constants that will be used.                     *
   *                                                                    *
   ********************************************************************** */

#define TRUE            1
#define FALSE           0

/* **********************************************************************
   * The message file format offered here is Fido format which has      *
   * been tested with OPUS and Dutchie. It represents the latest        *
   * format that I know about.                                          *
   *                                                                    *
   ********************************************************************** */

   static struct fido_msg {
      char from[36];                  /* Who the message is from             */
      char to[36];                    /* Who the message to to               */
      char subject[72];               /* The subject of the message.         */
      char date[20];                  /* Message createion date/time         */
      unsigned int times;             /* Number of time the message was read */
      unsigned int destination_node;  /* Intended destination node           */
      unsigned int originate_node;    /* The originator node of the message  */
      unsigned int cost;              /* Cost to send this message           */
      unsigned int originate_net;     /* The originator net of the message   */
      unsigned int destination_net;   /* Intended destination net number     */
      unsigned int destination_zone;  /* Intended zone for the message       */
      unsigned int originate_zone;    /* The zone of the originating system  */
      unsigned int destination_point; /* Is there a point to destination?    */
      unsigned int originate_point;   /* The point originated the message    */
      unsigned int reply;             /* Thread to previous reply            */
      unsigned int attribute;         /* Message type                        */
      unsigned int upwards_reply;     /* Thread to next message reply        */
   } message;                         /* Something to store this structure   */

/* **********************************************************************
   * 'Attribute' bit definitions we will use                            *
   *                                                                    *
   ********************************************************************** */

#define Fido_Crash              0x0002
#define Fido_Kill               0x0080
#define Fido_Local              0x0100
#define Fido_File_Attach        0x0010
#define Fido_Hold               0x0200

/* **********************************************************************
   * Define some data storage that needs to be defaulted. The nodelist  *
   * starts out with Zone 1, Psudo-Host 1.                              *
   *                                                                    *
   ********************************************************************** */

    static int zone = 1;
    static int host = 1;
    static int node = 1;

/* **********************************************************************
   * Default to not offer notice.                                       *
   *                                                                    *
   ********************************************************************** */

    static char notice = FALSE;

/* **********************************************************************
   * Define data storage for the file control block pointers we need.   *
   *                                                                    *
   ********************************************************************** */

    static FILE *exclude_file;
    static FILE *log_file;
    static short next_message = 0;
    static char any_text;

/* **********************************************************************
   * Define a data type for the excluded systems.                       *
   *                                                                    *
   * We will maintain a linked-list of systems in memory.               *
   *                                                                    *
   ********************************************************************** */

    static struct Excluded_Systems {
        int zone;                       /* Systems zone                 */
        int network;                    /* Systems network              */
        int node;                       /* Systems node                 */
        char why;                       /* 0-flag, 1-key, 2-predefined  */
        char keyword[21];               /* Offending keyword            */
        char by_pass;                   /* TRUE or FALSE                */
        struct Excluded_Systems *next;  /* The next in the linked list  */
    } *es_first, *es_last, *es_test;    /* Define 3 pointers to it.     */

/* **********************************************************************
   * Define a linked list of keywords to scan for.                      *
   *                                                                    *
   * We maintain a linked list of the keywords to scan for.             *
   *                                                                    *
   ********************************************************************** */

    static struct Key_Words {
        char *key;                      /* Pointer to the key word      */
        struct Key_Words *next;         /* Pointer to the next one      */
    } *kw_first, *kw_last, *kw_test;    /* Define three pointers to it. */

/* **********************************************************************
   * Define a linked list of nodelist flags to scan for.                *
   *                                                                    *
   * We maintain a linked list of the nodelist flags to scan for.       *
   *                                                                    *
   ********************************************************************** */

    static struct Nodelist_Flags {
        char *flag;                     /* Pointer to the flag word     */
        struct Nodelist_Flags *next;    /* Pointer to the next one      */
    } *nf_first, *nf_last, *nf_test;    /* Define three pointers to it  */

/* **********************************************************************
   * Define a linked list of text to append to notice messages.         *
   *                                                                    *
   * We maintain a linked list of the text lines.                       *
   *                                                                    *
   ********************************************************************** */

    static struct Text_Line {
        char *text;                     /* Pointer to the text line     */
        struct Text_Line *next;         /* Pointer to the next one      */
    } *tl_first, *tl_last, *tl_test;    /* Define three pointers to it  */

/* **********************************************************************
   * Define a linked list of directories to scan.                       *
   *                                                                    *
   * We maintain a linked list of directory names to look in.           *
   *                                                                    *
   ********************************************************************** */

    static struct Directories {
        char *dir_name;                 /* Pointer to directory name    */
        struct Directories *next;       /* Pointer to the next one      */
    } *dir_first, *dir_last, *dir_test; /* Define three pointers to it  */

/* **********************************************************************
   * Set the offered string to uppercase.                               *
   *                                                                    *
   ********************************************************************** */

void ucase(char *this_record)
{
   while (*this_record) {
      if (*this_record > 0x60 && *this_record < 0x7b) {
         *this_record = *this_record - 32;
      }

      this_record++;
   }
}

/* **********************************************************************
   * Find the highest message number and return it.                     *
   *                                                                    *
   ********************************************************************** */

static short find_highest_message_number(char *directory)
{
    char result;
    short highest_message_number = 0;
    char directory_search[100];
    struct ffblk file_block;

    strcpy(directory_search, directory);

    if (directory[strlen(directory) - 1] != '\\')
        strcat(directory, "\\");

    strcat(directory_search, "*.msg");

    result = findfirst(directory_search, &file_block, 0x16);

    if (! result) {
        if (atoi(file_block.ff_name) > highest_message_number) {
            highest_message_number = atoi(file_block.ff_name);
        }
    }

    while (! result) {
        result = findnext(&file_block);
        if (! result) {
            if (atoi(file_block.ff_name) > highest_message_number) {
                highest_message_number = atoi(file_block.ff_name);
            }
        }
    }

    return(highest_message_number);
}

/* **********************************************************************
   * If we are to send a notice of erase, create a new message to the   *
   * originating station.                                               *
   *                                                                    *
   * When done, or if no notice is to be sent, erase the message.       *
   *                                                                    *
   ********************************************************************** */

static void exclude_this(char *path,
    char *name,
    char *o_to,
    char *o_from,
    char *o_subject,
    char why)
{
    char full_name[201];
    FILE *msg_file;
    char original_from[40];
    int o_zone, o_network, o_node, o_point;
    int i_zone, i_network, i_node, i_point;
    time_t the_time;

    i_zone = message.destination_zone;
    i_network = message.destination_net;
    i_node = message.destination_node;
    i_point = message.destination_point;
    o_zone = message.originate_zone;
    o_network = message.originate_net;
    o_node = message.originate_node;
    o_point = message.originate_point;

    (void)sprintf(full_name, "%s%s%s",
        path,
        path[strlen(path) - 1] == '\\' ? "" : "\\",
        name);

    (void)unlink(full_name);

    (void)sprintf(full_name, "\n   From %d:%d/%d (%s) to %s",
        message.originate_zone,
        message.originate_net,
        message.originate_node,
        o_from, o_to);

    fputs(full_name, log_file);
    (void)printf(full_name);

    (void)sprintf(full_name, "\n   Re: %s (", o_subject);

    if (why == 0) {
        (void)strcat(full_name, "Nodelist Flag)\n");
    }
    else if (why == 1) {
        (void)strcat(full_name, "Unaccepted Keyword)\n");
    }
    else {
        (void)strcat(full_name, "Predefined Address)\n");
    }

    fputs(full_name, log_file);
    (void)printf(full_name);

    if (notice) {
        if (strncmp(original_from, "Exclude", 6)) {
            if (next_message == 0) {
                next_message = find_highest_message_number(path);
            }

            next_message++;
            (void)printf("   Reply in message number %d\n", next_message);

/*
    Stuff the message header fields
*/

            (void)strcpy(original_from, o_from);
            (void)strcpy(message.from, "Exclude V1.1");
            (void)strcpy(message.to, original_from);
            (void)strcpy(message.subject, o_subject);
            message.times = 0;
            message.destination_node = o_node;
            message.originate_node = i_node;
            message.cost = 0;
            message.originate_net = i_network;
            message.destination_net = o_network;
            message.destination_zone = o_zone;
            message.originate_zone = i_zone;
            message.destination_point = o_point;
            message.originate_point = i_point;
            message.reply = 0;
            message.attribute = Fido_Crash + Fido_Local + Fido_Kill;
            message.upwards_reply = 0;

/*
    Create the message file
*/

            (void)sprintf(full_name, "%s%s%d.msg",
                path,
                path[strlen(path) - 1] == '\\' ? "" : "\\",
                next_message);

            if ((msg_file = fopen(full_name, "wb")) == (FILE *)NULL) {
                (void)printf("Could not create message file: %s!\n", full_name);
                return;
            }

/*
    Store the message header into the new message file
*/

            if (fwrite(&message, sizeof(struct fido_msg), 1, msg_file) != 1) {
                (void)printf("Could not write message file: %s!\n", full_name);
                (void)fclose(msg_file);
                return;
            }

/*
    Make sure that it's marked a both Immediate and as Direct
    to make sure that it gets sent without routing
*/

            the_time = time(NULL);

            (void)sprintf(full_name, "%cFLAGS IMM, DIR%c%c", 0x01, 0x0d, 0x0a);
            (void)fputs(full_name, msg_file);

            (void)sprintf(full_name, "%cMSGID: %d:%d/%d %08lx%c%c",
                0x01,
                i_zone, i_network, i_node,
                (unsigned long)the_time * next_message,
                0x0d, 0x0a);

            (void)fputs(full_name, msg_file);

/*
      Append the text of the message based upon why the
      message was excluded.
*/

            (void)fputs
                ("Exclude V1.1 intercepted above message and then erased it.\r",
                msg_file);

            if (! any_text) {
                (void)fputs("Destination node reason:\r", msg_file);

                if (why == 0) {
                    (void)fputs("   Nodelist flag exclusion\r", msg_file);
                }
                else if (why == 1) {
                    (void)fputs
                        ("   Originating systems name was excluded\r",
                        msg_file);
                }
                else {
                    (void)fputs("   Predefined network address exclusion\r",
                        msg_file);
                }
            }
            else {
                tl_test = tl_first;
		(void)fputc(0x0d, msg_file);

                while (tl_test) {
                    (void)fputs(tl_test->text, msg_file);
                    (void)fputc(0x0d, msg_file);
                    tl_test = tl_test->next;
                }
            }

/*
    Write an end of message marker then close the newly
    created message file
*/

            (void)fputc(0, msg_file);
            (void)fputc(26, msg_file);
            (void)fclose(msg_file);
        }
    }
}

/* **********************************************************************
   * Open up the file and see if it should be erased.                   *
   *                                                                    *
   ********************************************************************** */

static void process_this(char *path, char *name)
{
    char full_name[101];
    FILE *msg_file;

    (void)sprintf(full_name, "%s%s%s",
        path,
        path[strlen(path) - 1] == '\\' ? "" : "\\",
        name);

/*
    If we fail to either open the message file or can't
    read it for some reason, simply return
*/

    if ((msg_file = fopen(full_name, "rb")) == (FILE *)NULL) {
        return;
    }

    if (fread(&message, sizeof(struct fido_msg), 1, msg_file) != 1) {
        (void)fclose(msg_file);
        return;
    }

    (void)fclose(msg_file);

/*
    Correct the zone number if needed, defaulting to zone 1
*/

    if (message.originate_zone > 100 || message.originate_zone < 0)
        message.originate_zone = 1;

    if (message.destination_zone > 100 || message.destination_zone < 0)
        message.destination_zone = 1;

/*
    Go through the linked list of systems that have been
    excluded and if found, call the routine that will erase
    the message.
*/

    es_test = es_first;

    while (es_test) {

        if (es_test->zone == message.originate_zone &&
            es_test->network == message.originate_net &&
            es_test->node == message.originate_node) {

		if (! es_test->by_pass) {
                    exclude_this(path, name,
                        message.to, message.from, message.subject,
                        es_test->why);
		}

                return;
        }

        es_test = es_test->next;
    }
}

/* **********************************************************************
   * Scan the message areas offered in the configuration file for mail  *
   * that's from excluded nodes.                                        *
   *                                                                    *
   * Before anything can be done, however, the excluded systems         *
   * information must be read into the linked list.                     *
   *                                                                    *
   ********************************************************************** */

static void scan_message_areas(void)
{
    char result;
    struct ffblk file_block;
    short message_count;
    char full_path[101];

    if ((exclude_file = fopen("EXCLUDE.BAD", "rb")) == (FILE *)NULL) {
        (void)printf("I could not find file: EXCLUDE.BAD!\n");
        (void)fcloseall();
        exit(19);
    }

/*
    Go through the exclude list on disk and read it into the
    memory linked list array
*/

    while (! feof(exclude_file)) {
        if (fread(es_test, sizeof(struct Excluded_Systems),
                1, exclude_file) == 1) {

            es_test = (struct Excluded_Systems *)
                farmalloc(sizeof(struct Excluded_Systems));

            if (es_test == (struct Excluded_Systems *)NULL) {
                (void)printf("Out of memory allocating excluded systems\n");
                (void)fcloseall();
                exit(12);
            }

/*
    Append the entry to the excluded systems linked list
*/

            es_test->next = (struct Excluded_Systems *)NULL;

            if (es_first == (struct Excluded_Systems *)NULL) {
                es_first = es_test;
            }
            else {
                es_last->next = es_test;
            }

            es_last = es_test;
        }
    }

    (void)fclose(exclude_file);

    dir_test = dir_first;

    while (dir_test) {
        message_count = next_message = 0;

        (void)sprintf(full_path, "%s%s*.MSG",
            dir_test->dir_name,
            dir_test->dir_name[strlen(dir_test->dir_name) - 1] == '\\' ?
            "" : "\\");

        (void)printf("\nScanning %s", full_path);

        result = findfirst(full_path, &file_block, 0x16);

        if (! result) {
            process_this(dir_test->dir_name, file_block.ff_name);
            message_count++;
        }

        while (! result) {
            result = findnext(&file_block);
            if (! result) {
                process_this(dir_test->dir_name, file_block.ff_name);
                message_count++;
            }
        }

        dir_test = dir_test->next;
    }
}

/* **********************************************************************
   * Offer statistical information compiled by this program on the mail *
   * that's been erased automatically.                                  *
   *                                                                    *
   ********************************************************************** */

static void offer_stats(void)
{
    char record[201];

    if (log_file == (FILE *)NULL) {

        (void)printf
            ("No statistics have been automatically collected yet.\n");

        return;
    }

    (void)rewind(log_file);

    while (! feof(log_file)) {
	(void)fgets(record, 200, log_file);

	if (! feof(log_file)) {
            printf(record);
        }
    }
}

/* **********************************************************************
   * If the entry is already defined, then return TRUE, else FALSE.     *
   *                                                                    *
   ********************************************************************** */

static char already_defined(void)
{
    struct Excluded_Systems *temp_test;

    temp_test = es_first;

    while (temp_test) {
        if (temp_test->zone == zone &&
	    temp_test->network == host &&
            temp_test->node == node) {
                return(TRUE);
        }

        temp_test = temp_test->next;
    }

    return(FALSE);
}

/* **********************************************************************
   * If we have a match, append the network address to the exclusion    *
   * linked array and return TRUE, else return FALSE.                   *
   *                                                                    *
   ********************************************************************** */

static char check_these(char *keyword, char *title, char flag)
{

/*
    Check to see if the keyword to look for is in the
    offer string. If not, return
*/

    if (strstr(title, keyword) == (char *)NULL)
        return(FALSE);

/*
    See if it's already defined
*/

    if (already_defined())
        return(TRUE);

/*
    Allocate some memory and then validate it
*/

    es_test =
        (struct Excluded_Systems *)farmalloc(sizeof(struct Excluded_Systems));

    if (es_test == (struct Excluded_Systems *)NULL) {
        (void)printf("Out of memory allocating excluded systems\n");
        (void)fcloseall();
        exit(12);
    }

/*
    Store the information about the newly excluded system
    into the linked list
*/

    es_test->zone = zone;
    es_test->network = host;
    es_test->node = node;
    es_test->by_pass = FALSE;
    (void)strncpy(es_test->keyword, keyword, 20);

    if (! flag)
        es_test->why = 1;
    else
        es_test->why = 0;

    es_test->next = (struct Excluded_Systems *)NULL;

    if (es_first == (struct Excluded_Systems *)NULL) {
        es_first = es_test;
    }
    else {
        es_last->next = es_test;
    }

    es_last = es_test;

    (void)printf("%s Excluded: %d:%d/%d (%s)\n",
        ! flag ? "Keyword" : "Flag   ",
        es_test->zone,
        es_test->network,
        es_test->node,
        keyword);

    return(TRUE);
}

/* **********************************************************************
   * See if the following entry should be excluded                      *
   *                                                                    *
   * We check the keywords in the linked list against the string by     *
   * calling another function and if that fails to return a match, we   *
   * check to see if a flags we need to exclude exists.                 *
   *                                                                    *
   ********************************************************************** */

static void test_this_entry(char *title, char *remainder)
{
    char i;

    ucase(title);

/*
    Go through the keyword linked list
*/

    kw_test = kw_first;

    while (kw_test) {
        if (check_these(kw_test->key, title, FALSE)) {
            return;
        }

        kw_test = kw_test->next;
    }

/*
    It's not a keyword so skip forward in the nodelist entry
    being examined until the pointer points to the nodelist
    flags.
*/

    for (i = 0; i < 4; i++) {
        while (*remainder && *remainder != ',') {
            remainder++;
        }

        if (! *remainder) {
            return;
        }

        remainder++;
    }

/*
    Go through the Flags linked list
*/

    nf_test = nf_first;

    while (nf_test) {
        if (check_these(nf_test->flag, remainder, TRUE)) {
            return;
        }

        nf_test = nf_test->next;
    }
}

/* **********************************************************************
   * Examine the nodelist for systems that should be excluded and post  *
   * that information to the exclusion file.                            *
   *                                                                    *
   ********************************************************************** */

static void compile_listing(char *nodelist)
{
    FILE *nodelist_file;
    char record[201], *point;
    char title[81];
    char i;
    short output_count;

    if (nodelist == (char *)NULL) {
        (void)printf("You must offer a nodelist file name!\n");
        (void)fcloseall();
        exit(17);
    }

    if ((nodelist_file = fopen(nodelist, "rt")) == (FILE *)NULL) {
        (void)printf("I could not find file: %s\n", nodelist);
        (void)fcloseall();
        exit(18);
    }

    clrscr();

    (void)printf("Scanning for the following keywords:\n");

/*
    Go through the keywords linked list and display the
    entries in the list
*/

    kw_test = kw_first;

    while (kw_test) {
        (void)printf("    %s\n", kw_test->key);
        kw_test = kw_test->next;
    }

/*
    Go through the nodelist until the end is found
*/

    while (! feof(nodelist_file)) {
        (void)fgets(record, 200, nodelist_file);

        if (! feof(nodelist_file)) {
            point = record;
            skipspace(point);

/*
    Ignore comment lines and scan for Zones, Regions, and Hosts,
    updating the proper numeric variables.
*/

          if (*point != ';') {
                if (! strncmp(point, "Zone,", 5)) {
                    point += 5;
                    zone = atoi(point);
                }
                else if (! strncmp(point, "Region,", 7)) {
                    point += 7;
                    host = atoi(point);
                }
                else if (! strncmp(point, "Host,", 5)) {
                    point += 5;
                    host = atoi(point);
                    (void)printf("Zone %2d Host %5d   \r", zone, host);
                }
                else {

/*
    Step towards the systems title
*/

                    while (*point && *point != ',') {
                        point++;
                    }
                    if (*point) {
                        point++;
                        node = atoi(point);

                        while (*point && *point != ',') {
                            point++;
                        }

                        if (*point) {
                            point++;
                            i = 0;

/*
    Copy the systems title into the title array, changing
    the _ characters into space characters
*/

                            while (*point && *point != ',') {
                                if (*point != '_') {
                                    title[i++] = *point++;
                                }
                                else {
                                    title[i++] = ' ';
                                    point++;
                                }
                            }

/*
    Terminate the title and incriment to the next field. Then
    call the function which will test the title and then the
    nodelist flags for possible exclusion
*/

                            title[i] = (char)NULL;
                            point++;
                            test_this_entry(title, point);
                        }
                    }
                }
            }
        }
    }

    (void)fclose(nodelist_file);

/*
    Now that the linked list of excluded systems is compleate,
    write the information to the excluded data file
*/

    if (exclude_file == (FILE *)NULL) {
        if ((exclude_file = fopen("EXCLUDE.BAD", "wb")) == (FILE *)NULL) {
            (void)printf("I could not create file: EXCLUDE.BAD!\n");
            (void)fcloseall();
            exit(14);
        }
    }

    es_test = es_first;
    output_count = 0;

    while (es_test) {
        if (fwrite(es_test,
                sizeof(struct Excluded_Systems), 1, exclude_file) != 1) {

            (void)printf("Failed to write record to file: EXCLUDE.BAD!\n");
            (void)fcloseall();
            exit(18);
        }

        output_count++;
        es_test = es_test->next;
    }

    (void)printf
        ("\nThere were %d exclusions in the nodelist and from known systems\n",
        output_count);

    (void)fclose(exclude_file);
}

/* **********************************************************************
   * A key to look for was defined. Append it to the linked list.       *
   *                                                                    *
   ********************************************************************** */

static void plug_key(char *atpoint)
{
    kw_test = (struct Key_Words *)farmalloc(sizeof(struct Key_Words));

    if (kw_test == (struct Key_Words *)NULL) {
        (void)printf("Out of memory allocating key words\n");
        (void)fcloseall();
        exit(12);
    }

    kw_test->key = (char *)farmalloc(strlen(atpoint) + 1);
    kw_test->next = (struct Key_Words *)NULL;
    (void)strcpy(kw_test->key, atpoint);
    kw_test->key[strlen(kw_test->key) - 1] = (char)NULL;

    if (kw_first == (struct Key_Words *)NULL) {
        kw_first = kw_test;
    }
    else {
        kw_last->next = kw_test;
    }

    kw_last = kw_test;
}

/* **********************************************************************
   * A flag to look for was defined. Append it to the linked list.      *
   *                                                                    *
   ********************************************************************** */

static void plug_flag(char *atpoint)
{
    nf_test =
        (struct Nodelist_Flags *)farmalloc(sizeof(struct Nodelist_Flags));

    if (nf_test == (struct Nodelist_Flags *)NULL) {
        (void)printf("Out of memory allocating nodelist flags\n");
        (void)fcloseall();
        exit(12);
    }

    nf_test->flag = (char *)farmalloc(strlen(atpoint) + 1);
    nf_test->next = (struct Nodelist_Flags *)NULL;
    (void)strcpy(nf_test->flag, atpoint);
    nf_test->flag[strlen(nf_test->flag) - 1] = (char)NULL;

    if (nf_first == (struct Nodelist_Flags *)NULL) {
        nf_first = nf_test;
    }
    else {
        nf_last->next = nf_test;
    }

    nf_last = nf_test;
}

/* **********************************************************************
   * A test to look for was defined. Append it to the linked list.      *
   *                                                                    *
   ********************************************************************** */

static void plug_text(char *atpoint)
{
    tl_test =
        (struct Text_Line *)farmalloc(sizeof(struct Text_Line));

    if (tl_test == (struct Text_Line*)NULL) {
        (void)printf("Out of memory allocating text line\n");
        (void)fcloseall();
        exit(12);
    }

    tl_test->text = (char *)farmalloc(strlen(atpoint) + 1);
    tl_test->next = (struct Text_Line *)NULL;
    (void)strcpy(tl_test->text, atpoint);
    tl_test->text[strlen(tl_test->text) - 1] = (char)NULL;

    if (tl_first == (struct Text_Line *)NULL) {
        tl_first = tl_test;
    }
    else {
        tl_last->next = tl_test;
    }

    tl_last = tl_test;
}

/* **********************************************************************
   * A known system address was offered. Extract the information and    *
   * then append it to the exclusion data file.                         *
   *                                                                    *
   * The format that's looked for is:                                   *
   *                                                                    *
   *    <zone>:<network>/<node>                                         *
   *                                                                    *
   * If a point is encountered, it will considered part of the node     *
   * number yet the fraction will be discarded so points doesn't matter *
   * to this routine.                                                   *
   *                                                                    *
   ********************************************************************** */

static void plug_known(char *atpoint)
{
    char by_pass;

    es_test =
        (struct Excluded_Systems *)farmalloc(sizeof(struct Excluded_Systems));

    if (es_test == (struct Excluded_Systems *)NULL) {
        (void)printf("Out of memory allocating excluded systems\n");
        (void)fcloseall();
        exit(12);
    }

    by_pass = FALSE;

/*
    Mark the 'why' as a predefined exclusion
*/

    es_test->why = 2;

/*
    See if it's a - that follows the known field. If it is, then
    it means that the node should NOT be excluded for any reason
*/

    skipspace(atpoint);

    if (*atpoint == '-') {
        by_pass = TRUE;
        atpoint++;
        skipspace(atpoint);
    }

    es_test->by_pass = by_pass;

/*
    Extract and validate the zone
*/

    es_test->zone = atoi(atpoint);

    if (es_test->zone < 1) {
        (void)printf("Known Zone in configuration file is bad!\n");
        (void)fcloseall();
        exit(15);
    }

    while (*atpoint && *atpoint != ':')
        atpoint++;

    if (! *atpoint) {
        (void)printf
            ("Known network address format in configuration file is bad!\n");

        (void)fcloseall();
        exit(15);
    }

    atpoint++;

/*
    Extract and validate the network
*/

    es_test->network = atoi(atpoint);

    if (es_test->network < 1) {
        (void)printf("Known network in configuration file is bad!\n");
        (void)fcloseall();
        exit(15);
    }

    while (*atpoint && *atpoint != '/')
        atpoint++;

    if (! *atpoint) {
        (void)printf
            ("Known network address format in configuration file is bad!\n");

        (void)fcloseall();
        exit(15);
    }

    atpoint++;

/*
    Extract the node
*/

    es_test->node = atoi(atpoint);
    es_test->keyword[0] = (char)NULL;

/*
    Append the entry to the excluded systems linked list
*/

    es_test->next = (struct Excluded_Systems *)NULL;

    if (es_first == (struct Excluded_Systems *)NULL) {
        es_first = es_test;
    }
    else {
        es_last->next = es_test;
    }

    es_last = es_test;
}

/* **********************************************************************
   * Extract either yes or no from the notice configuration parameter   *
   * and stuff the result into the notice flag.                         *
   *                                                                    *
   ********************************************************************** */

static void plug_notice(char *atpoint)
{
    if (! strncmp(atpoint, "YES", 3)) {
        notice = TRUE;
    }
    else if (! strncmp(atpoint, "NO", 2)) {
        notice = FALSE;
    }
    else {
        (void)printf("Notice keyword has an unknown parameter!\n");
        (void)printf("It should be either YES or NO!\n");
        (void)fcloseall();
        exit(13);
    }
}

/* **********************************************************************
   * The name of a directory was offered. Extract the name and append   *
   * it to the end of the linked list of directory names to look in.    *
   *                                                                    *
   ********************************************************************** */

static void plug_look(char *atpoint)
{
    dir_test = (struct Directories *)farmalloc(sizeof(struct Directories));

    if (dir_test == (struct Directories *)NULL) {
        (void)printf("Out of memory allocating directries to look in\n");
        (void)fcloseall();
        exit(12);
    }

    dir_test->dir_name = (char *)farmalloc(strlen(atpoint) + 1);
    dir_test->next = (struct Directories *)NULL;
    (void)strcpy(dir_test->dir_name, atpoint);
    dir_test->dir_name[strlen(dir_test->dir_name) - 1] = (char)NULL;

    if (dir_first == (struct Directories *)NULL) {
        dir_first = dir_test;
    }
    else {
        dir_last->next = dir_test;
    }

    dir_last = dir_test;
}

/* **********************************************************************
   * Display the current exclusions in the bad file.                    *
   *                                                                    *
   ********************************************************************** */

static void display_exclusions(void)
{
    char report[100];

    if ((exclude_file = fopen("EXCLUDE.BAD", "rb")) == (FILE *)NULL) {
        (void)printf("I could not find file: EXCLUDE.BAD!\n");
        (void)fcloseall();
        exit(19);
    }

    while (! feof(exclude_file)) {
        if (fread(es_test, sizeof(struct Excluded_Systems),
                1, exclude_file) != 1) {

            return;
        }

	if (! es_test->by_pass) {
	    (void)sprintf(report, "%d:%d/%d excluded",
		es_test->zone,
                es_test->network,
                es_test->node);

            if (es_test->why == 0) {
                (void)strcat(report, " because of flag '");
                (void)strcat(report, es_test->keyword);
                (void)strcat(report, "'");
            }
            else if (es_test->why == 1) {
                (void)strcat(report, " because of keyword '");
                (void)strcat(report, es_test->keyword);
                (void)strcat(report, "'");
            }
            else {
                (void)strcat(report, " in predefined configuration");
            }

            (void)printf("%s\n", report);
        }
        else {
	    (void)printf("%d:%d/%d SAFE\n",
		es_test->zone,
                es_test->network,
                es_test->node);
        }
    }

    (void)fclose(exclude_file);
}

/* **********************************************************************
   * Here is the main entry point.                                      *
   *                                                                    *
   * /c <filename>      - Compiles a new exclusion list from the        *
   *                      offered nodelist file.                        *
   *                                                                    *
   * /s                 - Offers statistics on erased messages.         *
   *                                                                    *
   * /d                 - Display current exclusions                    *
   *                                                                    *
   * Default            - Scan configured message directories for mail  *
   *                      from excluded systems, erasing them when      *
   *                      found, and optionally creating a return       *
   *                      message.                                      *
   *                                                                    *
   ********************************************************************** */

void main(int argc, char *argv[])
{
    int look;
    char *point;
    FILE *config;
    char record[201], original[201];
    char look_count;

    (void)printf("Exclude exclusion program. Offer /h for help\n");

    if ((config = fopen("EXCLUDE.CFG", "rt")) == (FILE *)NULL) {
        (void)printf("Unable to open file: EXCLUDE.CFG!\n");
        exit(10);
    }

    if ((log_file = fopen("EXCLUDE.LOG", "a+t")) == (FILE *)NULL) {
        (void)printf("Unable to open file: EXCLUDE.LOG!\n");
        exit(10);
    }

    kw_first = kw_last = kw_test = (struct Key_Words *)NULL;
    dir_first = dir_last = dir_test = (struct Directories *)NULL;
    look_count = 0;
    exclude_file = (FILE *)NULL;
    any_text = FALSE;

/*
    Go through the configuration file, extracting the information
    we are interested in by looking at the fields we expect. Discard
    anything that we are not interested in
*/

    while (! feof(config)) {
        (void)fgets(record, 200, config);

        if (! feof(config)) {
            point = record;
            skipspace(point);
            (void)strcpy(original, point);
            ucase(point);

            if (*point != ';' && strlen(point) > 2) {
                if (! strncmp(point, "KEY ", 4)) {
                    point += 4;
                    skipspace(point);
                    if (*point) {
                        plug_key(point);
                    }
                }
                else if (! strncmp(point, "FLAG ", 5)) {
                    point += 5;
                    skipspace(point);
                    if (*point) {
                        plug_flag(point);
                    }
                }
                else if (! strncmp(point, "TEXT ", 5)) {
                    point = original;
                    point += 5;
                    skipspace(point);
                    if (*point) {
                        plug_text(point);
                        any_text = TRUE;
                    }
                }
                else if (! strncmp(point, "KNOWN ", 6)) {
                    point += 6;
                    skipspace(point);
                    if (*point) {
                        plug_known(point);
                    }
                }
                else if (! strncmp(point, "NOTICE ", 7)) {
                    point += 7;
                    skipspace(point);
                    if (*point) {
                        plug_notice(point);
                    }
                }
                else if (! strncmp(point, "LOOK ", 5)) {
                    point += 5;
                    skipspace(point);
                    if (*point) {
                        plug_look(point);
                        look_count++;
                    }
                }
            }
        }
    }

    (void)fclose(config);

    if (look_count == 0) {
        (void)printf("There were no directories defined in EXCLUDE.CFG!\n");
        exit(11);
    }

/*
    If there were no arguments, scan the message directories,
    otherwise check to see what the command line options are
    and execute the proper routines
*/

    if (argc == 1) {
        scan_message_areas();
    }
    else {
        for (look = 1; look < argc; look++) {
            if (argv[look][0] == '/') {
                point = argv[look];
                point++;
                skipspace(point);

                if (toupper(*point) == 'H') {
                    (void)printf
                        ("Exclude /c <file_name>  - Compile list\n");

                    (void)printf
                        ("Exclude /s              - Display Statistics\n");

                    (void)printf
                        ("Exclude /d              - Display Exclusions\n");

                    (void)printf
                        ("Exclude [Enter]         - Scan mail directories\n");

                    look = argc;
                }
                else if (toupper(*point) == 'D') {
                    display_exclusions();
                    look = argc;
                }
                else if (toupper(*point) == 'S') {
                    offer_stats();
                    look = argc;
                }
                else if (toupper(*point) == 'C') {
                    if (*argv[look + 1]) {
                        compile_listing(argv[look + 1]);
                        look = argc;
                    }
                    else {
                        (void)printf("Nodelist file name is missing.\n");
                        look = argc;
                    }
                }
            }
        }
    }

    fcloseall();
    exit(0);
}

