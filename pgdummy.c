/*------------------------------------------------------------------------------
 * pgaudit.c
 *
 * An audit logging extension for PostgreSQL. Provides detailed logging classes,
 * object level logging, and fully-qualified object names for all DML and DDL
 * statements where possible (See README.md for details).
 *
 * Copyright (c) 2014-2017, PostgreSQL Global Development Group
 *------------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/htup_details.h"
#include "access/sysattr.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/objectaccess.h"
#include "catalog/pg_class.h"
#include "catalog/namespace.h"
#include "commands/dbcommands.h"
#include "catalog/pg_proc.h"
#include "commands/event_trigger.h"
#include "executor/executor.h"
#include "executor/spi.h"
#include "miscadmin.h"
#include "libpq/auth.h"
#include "nodes/nodes.h"
#include "nodes/params.h"
#include "tcop/utility.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "utils/timestamp.h"
//#include "utils/varlena.h"

PG_MODULE_MAGIC;

void _PG_init(void);


/*
 *  * String constants for log classes - used when processing tokens in the
 *   * pgaudit.log GUC.
 *    */
#define CLASS_DDL       "DDL"
#define CLASS_FUNCTION  "FUNCTION"
#define CLASS_MISC      "MISC"
#define CLASS_MISC_SET  "MISC_SET"
#define CLASS_READ      "READ"
#define CLASS_ROLE      "ROLE"
#define CLASS_WRITE     "WRITE"

#define CLASS_NONE      "NONE"
#define CLASS_ALL       "ALL"

#define LOG_DDL         (1 << 0)    /* CREATE/DROP/ALTER objects */
#define LOG_FUNCTION    (1 << 1)    /* Functions and DO blocks */
#define LOG_MISC        (1 << 2)    /* Statements not covered */
#define LOG_READ        (1 << 3)    /* SELECTs */
#define LOG_ROLE        (1 << 4)    /* GRANT/REVOKE, CREATE/ALTER/DROP ROLE */
#define LOG_WRITE       (1 << 5)    /* INSERT, UPDATE, DELETE, TRUNCATE */
#define LOG_MISC_SET    (1 << 6)    /* SET ... */

#define LOG_NONE        0               /* nothing */
#define LOG_ALL         (0xFFFFFFFF)    /* All */

/* GUC variable for pgaudit.log, which defines the classes to log. */
/* Bitmap of classes selected */
static int auditLogBitmap = LOG_NONE;
/*
 * Define GUC variables and install hooks upon module load.
 */
static char *auditLog = NULL;
bool auditLogCatalog = true;

static bool
check_pgaudit_log(char **newVal, void **extra, GucSource source)
{
    List *flagRawList;
    char *rawVal;
    ListCell *lt;
    int *flags;

    /* Make sure newval is a comma-separated list of tokens. */
    rawVal = pstrdup(*newVal);
    if (!SplitIdentifierString(rawVal, ',', &flagRawList))
    {
        GUC_check_errdetail("List syntax is invalid");
        list_free(flagRawList);
        pfree(rawVal);
        return false;
    }

    /*
 *      * Check that we recognise each token, and add it to the bitmap we're
 *           * building up in a newly-allocated int *f.
 *                */
    if (!(flags = (int *) malloc(sizeof(int))))
        return false;

    *flags = 0;

    foreach(lt, flagRawList)
    {
        char *token = (char *) lfirst(lt);
        bool subtract = false;
        int class;

        /* If token is preceded by -, then the token is subtractive */
        if (token[0] == '-')
        {
            token++;
            subtract = true;
        }

        /* Test each token */
        if (pg_strcasecmp(token, CLASS_NONE) == 0)
            class = LOG_NONE;
        else if (pg_strcasecmp(token, CLASS_ALL) == 0)
            class = LOG_ALL;
        else if (pg_strcasecmp(token, CLASS_DDL) == 0)
            class = LOG_DDL;
        else if (pg_strcasecmp(token, CLASS_FUNCTION) == 0)
            class = LOG_FUNCTION;
        else if (pg_strcasecmp(token, CLASS_MISC) == 0)
            class = LOG_MISC | LOG_MISC_SET;
        else if (pg_strcasecmp(token, CLASS_MISC_SET) == 0)
            class = LOG_MISC_SET;
        else if (pg_strcasecmp(token, CLASS_READ) == 0)
            class = LOG_READ;
        else if (pg_strcasecmp(token, CLASS_ROLE) == 0)
            class = LOG_ROLE;
        else if (pg_strcasecmp(token, CLASS_WRITE) == 0)
            class = LOG_WRITE;
        else
        {
            free(flags);
            pfree(rawVal);
            list_free(flagRawList);
            return false;
        }

        /* Add or subtract class bits from the log bitmap */
        if (subtract)
            *flags &= ~class;
        else
            *flags |= class;
    }

    pfree(rawVal);
    list_free(flagRawList);

    /* Store the bitmap for assign_pgaudit_log */
    *extra = flags;

    return true;
}

/*
 *  * Set pgaudit_log from extra (ignoring newVal, which has already been
 *   * converted to a bitmap above). Note that extra may not be set if the
 *    * assignment is to be suppressed.
 *     */
static void
assign_pgaudit_log(const char *newVal, void *extra)
{
    if (extra)
        auditLogBitmap = *(int *) extra;
}


void
_PG_init(void)
{
    /* Be sure we do initialization only once */
    static bool inited = false;

    if (inited)
        return;

    /* Must be loaded with shared_preload_libraries */
    if (!process_shared_preload_libraries_in_progress)
        ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                errmsg("pgaudit must be loaded via shared_preload_libraries")));

    /* Define pgaudit.log */
    DefineCustomStringVariable(
        "pgaudit.log",

        "Specifies which classes of statements will be logged by session audit "
        "logging. Multiple classes can be provided using a comma-separated "
        "list and classes can be subtracted by prefacing the class with a "
        "- sign.",

        NULL,
        &auditLog,
        "none",
        PGC_SUSET,
        GUC_LIST_INPUT | GUC_NOT_IN_SAMPLE,
        check_pgaudit_log,
        assign_pgaudit_log,
        NULL);

    /* Define pgaudit.log_catalog */
    DefineCustomBoolVariable(
        "pgaudit.log_catalog",

        "Specifies that session logging should be enabled in the case where "
        "all relations in a statement are in pg_catalog.  Disabling this "
        "setting will reduce noise in the log from tools like psql and PgAdmin "
        "that query the catalog heavily.",

        NULL,
        &auditLogCatalog,
        true,
        PGC_SUSET,
        GUC_NOT_IN_SAMPLE,
        NULL, NULL, NULL);

    inited = true;
}
