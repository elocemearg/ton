#ifndef _TTTFILETRANSFER_H
#define _TTTFILETRANSFER_H

#include "tttsession.h"

int
ttt_file_transfer_session(struct ttt_session *sess, int is_sender,
        const char *output_dir, const char **paths_to_push,
        int num_paths_to_push);

#endif
