/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DEVICESTATUS_ERRORS_H
#define DEVICESTATUS_ERRORS_H

#include <errors.h>

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
enum {
    DEVICESTATUS_MODULE_TYPE_SERVICE = 0,
    DEVICESTATUS_MODULE_TYPE_KIT = 1,
    DEVICESTATUS_MODULE_TYPE_CLIENT = 2
};

constexpr ErrCode DEVICESTATUS_SERVICE_ERR_OFFSET = ErrCodeOffset(SUBSYS_MSDP, DEVICESTATUS_MODULE_TYPE_SERVICE);

enum {
    E_DEVICESTATUS_WRITE_PARCEL_ERROR = DEVICESTATUS_SERVICE_ERR_OFFSET,
    E_DEVICESTATUS_READ_PARCEL_ERROR,
    E_DEVICESTATUS_GET_SYSTEM_ABILITY_MANAGER_FAILED,
    E_DEVICESTATUS_GET_SERVICE_FAILED,
    E_DEVICESTATUS_ADD_DEATH_RECIPIENT_FAILED,
    E_DEVICESTATUS_INNER_ERR,
    ETASKS_INIT_FAIL,
    ETASKS_WAIT_TIMEOUT,
    ETASKS_WAIT_DEFERRED,
    ETASKS_POST_SYNCTASK_FAIL,
    ETASKS_POST_ASYNCTASK_FAIL,
    EPOLL_CREATE_FAIL,
    MSG_SEND_FAIL
};

enum {
    FILE_OPEN_FAIL = ErrCodeOffset(SUBSYS_MSDP, DEVICESTATUS_MODULE_TYPE_KIT),
    STREAM_BUF_READ_FAIL,
    EVENT_REG_FAIL,
    PARAM_INPUT_FAIL
};

enum {
    NON_STD_EVENT = ErrCodeOffset(SUBSYS_MSDP, DEVICESTATUS_MODULE_TYPE_CLIENT),
    VAL_NOT_EXP,
    ERROR_UNSUPPORT,
    ERROR_NULL_POINTER
};

enum {
    DEVICESTATUS_OK = 0,
    DEVICESTATUS_FAILED = -1,
    DEVICESTATUS_INVALID_FD = -2,
    DEVICESTATUS_NOT_FIND_JSON_ITEM = -3
};

enum {
    INIT_FAIL = -1,
    INIT_SUCCESS = 0,
    INIT_CANCEL = 1
};

enum ErrorCode : int32_t {
    OTHER_ERROR = -1,
    COMMON_PERMISSION_CHECK_ERROR = 201,
    COMMON_NOT_SYSTEM_APP = 202,
    COMMON_PARAMETER_ERROR = 401,
    COMMON_CAPABILITY_NOT_SUPPORT = 801,
    COMMON_NOT_ALLOWED_DISTRIBUTED = 40101,
    COOPERATOR_FAIL = 20900001
};

enum CustomErrCode : int32_t {
    UNKNOWN_ERROR = -1,
    OPEN_SESSION_FAILED = 20900002,
    SEND_PACKET_FAILED = 20900003,
    UNEXPECTED_START_CALL = 20900004,
    WORKER_THREAD_TIMEOUT = 20900005,
    NOT_AOLLOW_COOPERATE_WHEN_MOTION_DRAGGING = 20900006,
};

enum BoomerangErrCode : int32_t {
    HANDLER_FAILD = 32100001,
    ENCODE_FAILED = 32100002,
    DECODE_FAILED = 32100003,
    SUBSCRIBE_FAILED = 32100004,
    UNSUBSCRIBE_FAILED = 32100005,
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS

#endif // DEVICESTATUS_ERRORS_H
