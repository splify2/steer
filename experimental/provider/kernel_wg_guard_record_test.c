#define _GNU_SOURCE
#include "kernel_wg_guard_record.h"
#include "../spec/execution_journal.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const struct steer_draft_wg_guard_record fixture={
    .link={.generation=17,.instance_token=5,.namespace_device=11,.namespace_inode=42,
           .boot_id={1},.intent_id={2},.physical_name="swabcdefghijklm",
           .kind="wireguard",.group=123},
    .ifindex=27,.table="steer_wg_0123456789abcdef",
    .marker="steer-wg:0123456789abcdef0123456789abcdef"
};

static struct steer_spec_journal_record record(uint64_t tx,
    const struct steer_draft_wg_guard_record *guard,int outcome){
    struct steer_spec_journal_record r={
        .key={tx,fixture.link.instance_token,outcome?2:1,
              outcome?STEER_SPEC_JOURNAL_OUTCOME:STEER_SPEC_JOURNAL_INTENT},
        .generation=18,.intent_sequence=outcome!=0,.operation=1,
        .effect=outcome!=0,.phase=outcome?2:1,.length=STEER_DRAFT_WG_GUARD_RECORD_BYTES,
        .provider="wireguard-fixture",.provider_version="1"
    };
    assert(!steer_draft_wg_guard_record_encode(guard,r.data));
    return r;
}

static void append_synced(struct steer_spec_journal *j,const struct steer_spec_journal_record *r){
    struct steer_spec_journal_result result=steer_spec_journal_append(j,r);
    assert(!result.error.code&&result.durability==STEER_SPEC_JOURNAL_SYNCED);
}

static void clear_fixture(const char *path){
    int fd=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(fd>=0);
    assert(!unlinkat(fd,"r-0000000000000001-0000000000000005-00000001-1",0));
    assert(!unlinkat(fd,"r-0000000000000001-0000000000000005-00000002-2",0));
    assert(!unlinkat(fd,"r-0000000000000002-0000000000000005-00000001-1",0));
    assert(!unlinkat(fd,"r-0000000000000002-0000000000000005-00000002-2",0));
    assert(!unlinkat(fd,".writer.lock",0));
    assert(!close(fd));
}

int main(int argc,char **argv){
    assert(argc==2);
    alarm(20);
    struct steer_draft_wg_guard_record captured=fixture,restored;
    const uint64_t first_handle=UINT64_C(0x1020304050607080),next_handle=first_handle+1;
    captured.handle=first_handle;
    struct steer_spec_journal *j;
    assert(!steer_spec_journal_open(argv[1],8,4,&j).code);
    struct steer_spec_journal_record create=record(1,&fixture,0),created=record(1,&captured,1);
    append_synced(j,&create);
    append_synced(j,&created);
    /* Simulate stopping after replacement intent fsync, before the outcome. */
    struct steer_spec_journal_record replace=record(2,&captured,0);
    append_synced(j,&replace);
    assert(!steer_spec_journal_close(j).code);

    assert(!steer_spec_journal_open(argv[1],8,4,&j).code);
    assert(!steer_spec_journal_sync_existing(j).code);
    struct steer_spec_journal_record in,out;
    assert(!steer_spec_journal_read(j,&create.key,&in).code);
    assert(!steer_spec_journal_read(j,&created.key,&out).code);
    assert(!steer_draft_wg_guard_record_restore(in.data,in.length,out.data,out.length,&restored));
    assert(restored.handle==first_handle&&restored.ifindex==fixture.ifindex);
    assert(!strcmp(restored.link.physical_name,fixture.link.physical_name)&&
           restored.link.group==fixture.link.group&&restored.link.generation==fixture.link.generation&&
           restored.link.instance_token==fixture.link.instance_token&&
           restored.link.namespace_device==fixture.link.namespace_device&&
           restored.link.namespace_inode==fixture.link.namespace_inode&&
           !memcmp(restored.link.boot_id,fixture.link.boot_id,sizeof(fixture.link.boot_id))&&
           !memcmp(restored.link.intent_id,fixture.link.intent_id,sizeof(fixture.link.intent_id))&&
           !strcmp(restored.table,fixture.table));
    assert(steer_draft_wg_guard_record_observe(&restored,first_handle,fixture.marker)==STEER_DRAFT_WG_OWNED);
    assert(steer_draft_wg_guard_record_observe(&restored,next_handle,fixture.marker)==STEER_DRAFT_WG_UNKNOWN);
    assert(steer_draft_wg_guard_record_observe(&restored,first_handle,"foreign")==STEER_DRAFT_WG_FOREIGN);
    assert(steer_draft_wg_guard_record_observe(&restored,0,"")==STEER_DRAFT_WG_ABSENT);
    assert(steer_draft_wg_guard_record_observe(&restored,0,NULL)==STEER_DRAFT_WG_UNKNOWN);

    assert(!steer_spec_journal_read(j,&replace.key,&in).code);
    captured.handle=next_handle;
    struct steer_spec_journal_record replaced=record(2,&captured,1);
    assert(steer_spec_journal_read(j,&replaced.key,&out).code==STEER_PV1_UNSUPPORTED);
    assert(!steer_draft_wg_guard_record_restore(in.data,in.length,NULL,0,&restored));
    assert(!restored.handle);
    assert(steer_draft_wg_guard_record_observe(&restored,first_handle,fixture.marker)==STEER_DRAFT_WG_UNKNOWN);
    assert(steer_draft_wg_guard_record_observe(&restored,next_handle,fixture.marker)==STEER_DRAFT_WG_UNKNOWN);
    append_synced(j,&replaced);
    assert(!steer_spec_journal_read(j,&replaced.key,&out).code);
    assert(!steer_draft_wg_guard_record_restore(in.data,in.length,out.data,out.length,&restored));
    assert(restored.handle==next_handle);
    assert(!steer_spec_journal_close(j).code);

    assert(steer_draft_wg_guard_record_decode(out.data,out.length-1,&restored)==EINVAL&&!restored.handle);
    out.data[0]='?';
    assert(steer_draft_wg_guard_record_decode(out.data,out.length,&restored)==EINVAL);
    out=replaced;
    out.data[8+40]^=1; /* Nested link record checksum no longer matches. */
    assert(steer_draft_wg_guard_record_decode(out.data,out.length,&restored)==EINVAL);
    out=replaced;
    out.data[out.length-1]='x'; /* Canonical marker must be NUL terminated. */
    assert(steer_draft_wg_guard_record_decode(out.data,out.length,&restored)==EINVAL);
    captured.ifindex=0;
    assert(steer_draft_wg_guard_record_encode(&captured,out.data)==EINVAL);
    captured.ifindex=fixture.ifindex+1;
    out=record(2,&captured,1);
    assert(steer_draft_wg_guard_record_restore(in.data,in.length,out.data,out.length,&restored)==EINVAL);
    captured.ifindex=fixture.ifindex;
    captured.marker[9]='f';
    out=record(2,&captured,1);
    assert(steer_draft_wg_guard_record_restore(in.data,in.length,out.data,out.length,&restored)==EINVAL);

    clear_fixture(argv[1]);
    puts("WG guard record: synced intent/outcome, restart, lost outcome, exact identity and malformed payloads PASS");
    return 0;
}
