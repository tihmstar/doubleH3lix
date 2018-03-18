#include <errno.h>
#include <string.h>             // strcmp, strerror
#include <sys/utsname.h>        // uname

#include "common.h"             // LOG, kptr_t
#include "offsets.h"
#include <liboffsetfinder64/liboffsetfinder64.hpp>

static offsets_t offs;
static bool didInit = false;

extern "C" offsets_t* get_offsets(void *fi_)
{
    tihmstar::offsetfinder64 *fi = static_cast<tihmstar::offsetfinder64 *>(fi_);
    if (!didInit){
        offs.base =                             0xfffffff007004000;
        
        offs.sizeof_task =                      (kptr_t)fi->find_sizeof_task();
        offs.task_itk_self =                    (kptr_t)fi->find_task_itk_self();
        offs.task_itk_registered =              (kptr_t)fi->find_task_itk_registered();
        offs.task_bsd_info =                    (kptr_t)fi->find_task_bsd_info();
        offs.proc_ucred =                       (kptr_t)fi->find_proc_ucred();
        offs.vm_map_hdr =                       (kptr_t)fi->find_vm_map_hdr();
        offs.ipc_space_is_task =                (kptr_t)fi->find_ipc_space_is_task();
        offs.realhost_special =                 0x10;
        offs.iouserclient_ipc =                 (kptr_t)fi->find_iouserclient_ipc();
        offs.vtab_get_retain_count =            (kptr_t)fi->find_vtab_get_retain_count();
        offs.vtab_get_external_trap_for_index = (kptr_t)fi->find_vtab_get_external_trap_for_index();
        
        offs.zone_map =                         (kptr_t)fi->find_zone_map();
        offs.kernel_map =                       (kptr_t)fi->find_kernel_map();
        offs.kernel_task =                      (kptr_t)fi->find_kernel_task();
        offs.realhost =                         (kptr_t)fi->find_realhost();
        
        offs.copyin =                           (kptr_t)fi->find_copyin();
        offs.copyout =                          (kptr_t)fi->find_copyout();
        offs.chgproccnt =                       (kptr_t)fi->find_chgproccnt();
        offs.kauth_cred_ref =                   (kptr_t)fi->find_kauth_cred_ref();
        offs.ipc_port_alloc_special =           (kptr_t)fi->find_ipc_port_alloc_special();
        offs.ipc_kobject_set =                  (kptr_t)fi->find_ipc_kobject_set();
        offs.ipc_port_make_send =               (kptr_t)fi->find_ipc_port_make_send();
        offs.osserializer_serialize =           (kptr_t)fi->find_osserializer_serialize();
        offs.rop_ldr_x0_x0_0x10 =               (kptr_t)fi->find_rop_ldr_x0_x0_0x10();
        didInit = true;
    }
    return &offs;
}
