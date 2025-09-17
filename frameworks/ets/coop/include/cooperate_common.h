/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef INPUT_DEVICE_COOPERATE_ANI_H
#define INPUT_DEVICE_COOPERATE_ANI_H

#include <map>
#include <string>

#include "ohos.multimodalInput.inputDeviceCooperate.proj.hpp"
#include "ohos.multimodalInput.inputDeviceCooperate.impl.hpp"
#include "ohos.multimodalInput.inputDeviceCooperate.CooperationCallbackData.ani.1.hpp"
#include "ohos.multimodalInput.inputDeviceCooperate.TraversalSwitchStatus.ani.1.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include "coordination_message.h"
#include "devicestatus_errors.h"
#include "fi_log.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
#ifndef RET_OK
    #define RET_OK (0)
#endif

const std::map<int32_t, std::string> NAPI_ERRORS = {
    { COMMON_PERMISSION_CHECK_ERROR, "Permission denied. An attempt was made to %s forbidden by permission:%s." },
    { COMMON_PARAMETER_ERROR, "Parameter error. The type of %s must be %s." },
    { COMMON_NOT_ALLOWED_DISTRIBUTED, "Cross-device dragging is not allowed" },
    { COOPERATOR_FAIL, " Service exception. Possible causes: 1. A system error, such as null pointer,"
        "container-related exception, or IPC exception. 2. N-API invocation exception or invalid N-API status." },
    { COMMON_NOT_SYSTEM_APP, "Non system applications." }
};

const std::unordered_map<CoordinationMessage, std::string> COOPERATE_MSG_MAP {
    { CoordinationMessage::PREPARE, "PREPARE" },
    { CoordinationMessage::UNPREPARE, "UNPREPARE" },
    { CoordinationMessage::ACTIVATE, "ACTIVATE" },
    { CoordinationMessage::ACTIVATE_SUCCESS, "ACTIVATE_SUCCESS" },
    { CoordinationMessage::ACTIVATE_FAIL, "ACTIVATE_FAIL" },
    { CoordinationMessage::DEACTIVATE_SUCCESS, "DEACTIVATE_SUCCESS" },
    { CoordinationMessage::DEACTIVATE_FAIL, "DEACTIVATE_FAIL" },
    { CoordinationMessage::SESSION_CLOSED, "SESSION_CLOSED" }
};


enum class CallbackType : uint8_t {
    ENABLE,
    START,
    STOP,
    GETSTATE,
    ON,
    OFF,
};


class AniCallbackInfo {
public:
    AniCallbackInfo(CallbackType t):type_(t) {}
    ~AniCallbackInfo();

    bool init(uintptr_t opq);
    void AttachThread();
    void DetachThread();

    int32_t errCode_ { 0 };
    bool result_ = false;
    std::string deviceDescriptor_;
    CoordinationMsgInfo msgInfo_;
    CallbackType type_;
    ani_object funObject_ = nullptr;
    ani_ref ref_ = nullptr;
    ani_vm* vm_ = nullptr;
    ani_env* envT_ = nullptr;
    ani_env* env_ = nullptr;
    ani_object promise_ = nullptr;
    ani_resolver deferred_ = nullptr;
    bool attach_ = false;
};

class CooperateCommon final {
public:
    static ani_object WrapBusinessError(ani_env* env, const std::string& msg);
    static ani_ref CreateBusinessError(ani_env* env, ani_int code, const std::string& msg);
    static ani_status GetAniEnv(ani_vm* vm, ani_env** env);
    static void ExecAsyncCallbackPromise(ani_env *env, ani_resolver deferred, ani_ref data, ani_ref businessError);
    static ani_status ExecAsyncCallBack(ani_env *env, ani_object businessError,
        ani_object param, ani_object callbackFunc);
    static ani_object CreateBooleanObject(ani_env *env, bool value);
    static ani_object CreateIntObject(ani_env *env, int32_t value);
    static bool GetErrorMsg(int32_t code, std::string &codeMsg);
    static void HandleExecuteResult(int32_t errCode, const std::string param1, const std::string param2);
    static bool GetErrMsg(const CoordinationMsgInfo &msgInfo, std::string &msg);
    static int32_t GetErrCode(const CoordinationMsgInfo &msgInfo);
    static bool IsSameHandle(ani_env *env, ani_ref localRef, ani_ref inRef);
};

class GlobalRefGuard {
    ani_env *env_ = nullptr;
    ani_ref ref_ = nullptr;

public:
    GlobalRefGuard(ani_env *env, ani_object obj);
    explicit operator bool() const
    {
        return ref_ != nullptr;
    }
    ani_ref get() const
    {
        return ref_;
    }
    ~GlobalRefGuard();
    GlobalRefGuard(const GlobalRefGuard &) = delete;
    GlobalRefGuard &operator=(const GlobalRefGuard &) = delete;
};

} // DeviceStatus
} // Msdp
} // OHOS
#endif // INPUT_DEVICE_COOPERATE_ANI_H