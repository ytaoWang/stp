#include "stp_fs.h"
#include "stp.h"
#include "stp_error.h"

stp_error stp_errno = STP_NO_ERROR;

const char * const stp_errlist[STP_MAX_ERRNO + 1] = {
    N_("No error"), 				/*STP_NO_ERROR */
    N_("Index file open error"), 	/*STP_INDEX_OPEN_ERROR */
    N_("Metadata file open error"), /*STP_META_OPEN_ERROR */
    N_("Index file read error"),    /*STP_INDEX_READ_ERROR */
    N_("Metadata file read error"), /*STP_META_READ_ERROR */
    N_("Index file write error"),   /*STP_INDEX_WRITE_ERROR */
    N_("Metadata file write error"), /*STP_META_WRITE_ERROR */
    N_("Bad magic number"),			 /*STP_BAD_MAGIC_NUMBER */
    N_("Medadata file can't be write"),   /*STP_META_CANT_BE_WRITER */
    N_("Index file can't be write"),	  /*STP_INDEX_CANT_BE_WRITER */
    N_("Index file can't be reader"),     /*STP_INDEX_CANT_BE_READER */
    N_("Metadata file can't be reader"),  /*STP_META_CANT_BE_READER */
    N_("Index/Metadata reader can't store"),/*STP_INDEX_READER_CANT_STORE*/
    N_("Index/Metadata reader can't store"), /*STP_META_READER_CANT_STORE*/
    N_("Index/Metadata reader can't delete"),/*STP_INDEX_READER_CANT_DELETE*/
    N_("Index/Metadata reader can't delete"),/*STP_META_READER_CANT_DELETE*/
    N_("Index reader can't compact"),/*STP_INDEX_READER_CANT_COMPACTION*/
    N_("Meta reader can't compact"),/*STP_META_READER_CANT_COMPACTION*/
    N_("Index reader can't update"),/*STP_INDEX_READER_CANT_UPDATE*/
    N_("Meta reader can't update"),/*STP_META_READER_CANT_UPDATE*/
    N_("Index item not found"),/*STP_INDEX_ITEM_NOT_FOUND*/
    N_("Metadata item not found"),/*STP_META_ITEM_NOT_FOUND*/
    N_("Index file illeagal data"),/*STP_INDEX_ILLEAGAL_DATA*/
    N_("Meta file illeagal data"),/*STP_META_ILLEAGAL_DATA*/
    N_("Index file has no enough space"),/*STP_INDEX_NO_SPACE */
    N_("Malloc memory error"),/*STP_MALLOC_SERROR*/
    N_("Create index file error"),/*STP_INDEX_CREAT_ERROR*/
    N_("Create metadata file error"),/*STP_META_CREAT_ERROR*/
    N_("Fail to check index file"),/*STP_INDEX_FILE_CHECK_ERROR*/
    N_("Fail to check metadata file"),/*STP_META_FILE_CHECK_ERROR*/
    N_("Fail to allocate inode"),/*STP_INODE_MALLOC_ERROR*/
    N_("Fail to allocate bnode"),/*STP_BNODE_MALLOC_ERROR*/
    };

    
const char * stp_strerror(stp_error error)
{
    if((((int) error) < STP_MIN_ERRNO) || ((int)error > STP_MAX_ERRNO))
        return _("Unknown error");
    else
        return _(stp_errlist[(int)error]);
}
