#define _POSIX_C_SOURCE 200809L
#include "execution_prepare_async.h"
#include <stdlib.h>
#include <time.h>
struct request {
 struct steer_spec_execution_prepare_input input;
 steer_spec_execution_prepare_done done;void *user;struct steer_draft_host_job *job;uint64_t deadline;
};
static struct steer_pv1_error error(uint32_t code){return (struct steer_pv1_error){code,0};}
static struct steer_draft_host_work_result prepare(void *arg,const void *document,size_t length,
 uint64_t deadline,const struct steer_draft_cancel *cancel){
 struct request *request=arg;const struct steer_spec_execution_prepare_input *input=&request->input;
 struct steer_spec_execution *execution=NULL;
 struct steer_spec_plan *plan=steer_spec_compile(document,length,input->inventory,input->inventory_count);
 struct steer_pv1_error result=error(plan?STEER_PV1_OK:STEER_PV1_RESOURCE_EXHAUSTED);
 if(plan){
  struct steer_spec_summary summary=steer_spec_summary(plan);
  if(!summary.syntax_valid||!summary.topology_valid)result=error(STEER_PV1_INVALID);
  else result=steer_spec_execution_prepare(&plan,input->generation,input->first_instance_token,
   input->factories,input->factory_count,&input->limits,deadline,cancel,&execution);
  steer_spec_destroy(plan);
 }
 return (struct steer_draft_host_work_result){result,execution,0};
}
static void completed(void *arg,struct steer_draft_host_work_result result){
 struct request *request=arg;struct steer_spec_execution *execution=result.value;
 struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);uint64_t now=(uint64_t)t.tv_sec*1000000000ull+(uint64_t)t.tv_nsec;
 if(execution&&(result.worker_flags||steer_draft_host_job_cancelled(request->job)||now>=request->deadline)){
  steer_spec_execution_retire(execution);
  result.error=error(result.worker_flags?STEER_PV1_IO:steer_draft_host_job_cancelled(request->job)?STEER_PV1_CANCELLED:STEER_PV1_TIMEOUT);
 }
 request->done(request->user,result.error,execution);free(request);
}
struct steer_pv1_error steer_spec_execution_submit(struct steer_draft_host_worker *worker,
 const void *document,size_t length,const struct steer_spec_execution_prepare_input *input,
 uint64_t deadline,const struct steer_draft_host_work_guard *guard,
 steer_spec_execution_prepare_done done,void *user,struct steer_draft_host_job **out){
 if(out)*out=NULL;
 if(!worker||!document||!length||!input||!input->generation||!input->first_instance_token||
  (!input->factories&&input->factory_count)||input->factory_count>STEER_SPEC_EXECUTION_FACTORIES_MAX||
  (!input->inventory&&input->inventory_count)||input->inventory_count>4096||!done||!out)return error(STEER_PV1_INVALID);
 struct request *request=malloc(sizeof(*request));if(!request)return error(STEER_PV1_RESOURCE_EXHAUSTED);
 request->input=*input;request->done=done;request->user=user;request->deadline=deadline;request->job=NULL;
 struct steer_pv1_error result=steer_draft_host_worker_submit(worker,document,length,deadline,
  prepare,request,guard,completed,request,out);
 if(result.code)free(request);else request->job=*out;
 return result;
}
