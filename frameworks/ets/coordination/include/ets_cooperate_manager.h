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

#ifndef ETS_COOPERATE_MANAGER_H
#define ETS_COOPERATE_MANAGER_H

#include "ohos.cooperate.proj.hpp"
#include "ohos.cooperate.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"
#include "devicestatus_errors.h"
#include "coordination_message.h"
#include "i_coordination_listener.h"
#include "i_event_listener.h"

#include <algorithm>
#include <mutex>
#include <map>
#include <queue>
#include <string>
#include <variant>
#include <vector>

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace taihe;
using CooperateMessage_t = ohos::cooperate::CooperateMessage;
using CooperateState_t = ohos::cooperate::CooperateState;
using MouseLocation_t = ohos::cooperate::MouseLocation;
using CooperateOptions_t = ohos::cooperate::CooperateOptions;
using callbackType = std::variant<taihe::callback<void(CooperateMessage_t const&)>,
    taihe::callback<void(MouseLocation_t const&)>>;

const std::map<int32_t, std::string> ETS_ERRORS = {
    { COMMON_PERMISSION_CHECK_ERROR, "Permission denied. An attempt was made to %s forbidden by permission:%s." },
    { COMMON_PARAMETER_ERROR, "Parameter error. The type of %s must be %s." },
    { COMMON_NOT_ALLOWED_DISTRIBUTED, "Cross-device dragging is not allowed" },
    { COOPERATOR_FAIL, " Service exception. Possible causes: 1. A system error, such as null pointer,"
        "container-related exception, or IPC exception. 2. N-API invocation exception or invalid N-API status." },
    { COMMON_NOT_SYSTEM_APP, "Non system applications." }
};

const std::unordered_map<CoordinationMessage, std::string> MSG_MAP {
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
    PREPARE,
    ACTIVATE,
    DEACTIVATE,
    GETSTATE,
    ACTIVATEOPTIONS,
};

class AniCallbackInfo {
public:
    AniCallbackInfo(CallbackType t): type_(t)
    {
    }
    ~AniCallbackInfo()
    {
        if (env_ && ref_) {
            env_->GlobalReference_Delete(ref_);
            ref_ = nullptr;
        }
        if (attach_ && vm_) {
            vm_->DetachCurrentThread();
            attach_ = false;
        }
    };
 
    bool Init(uintptr_t opq);
    void AttachThread();
    void DetachThread();

    int32_t errCode_ { 0 };
    bool result_ = false;
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
    bool coordinationOpened_ { false };
};

class CooperateCommon final {
public:
    static ani_object WrapBusinessError(ani_env* env, const std::string& msg);
    static ani_ref CreateBusinessError(ani_env* env, ani_int code, const std::string& msg);
    static ani_status GetAniEnv(ani_vm* vm, ani_env** env);
    static void ExecAsyncCallbackPromise(ani_env *env, ani_resolver deferred, ani_ref data, ani_ref businessError);
    static ani_status ExecAsyncCallBack(ani_env *env, ani_object businessError,  ani_object param,
        ani_object callbackFunc);
    static ani_object CreateBooleanObject(ani_env *env, bool value);
    static ani_object CreateIntObject(ani_env *env, int32_t value);
    static bool GetErrorMsg(int32_t code, std::string &codeMsg);
    static void HandleExecuteResult(int32_t errCode, const std::string param1, const std::string param2);
    static bool GetErrMsg(const CoordinationMsgInfo &msgInfo, std::string &msg);
    static int32_t GetErrCode(const CoordinationMsgInfo &msgInfo);
};

struct CallbackObject {
    CallbackObject(callbackType cb, ani_ref ref) : callback(cb), ref(ref)
    {
    }

    ~CallbackObject()
    {
        auto *env = taihe::get_env();
        if (env == nullptr) {
            return;
        }
        env->GlobalReference_Delete(ref);
    }

    callbackType callback;
    ani_ref ref;
};

class GlobalRefGuard {
    ani_env *env_ = nullptr;
    ani_ref ref_ = nullptr;

public:
    GlobalRefGuard(ani_env *env, ani_object obj) : env_(env)
    {
        if (!env_) {
            return;
        }
        if (ANI_OK != env_->GlobalReference_Create(obj, &ref_)) {
            ref_ = nullptr;
        }
    }

    explicit operator bool() const
    {
        return ref_ != nullptr;
    }

    ani_ref get() const
    {
        return ref_;
    }

    ~GlobalRefGuard()
    {
        if (env_ && ref_) {
            env_->GlobalReference_Delete(ref_);
        }
    }

    GlobalRefGuard(const GlobalRefGuard &) = delete;
    GlobalRefGuard &operator=(const GlobalRefGuard &) = delete;
};

class EtsCooperateManager : public ICoordinationListener,
                            public IEventListener,
                            public std::enable_shared_from_this<EtsCooperateManager> {
public:
    EtsCooperateManager();
    virtual ~EtsCooperateManager() = default;

    static std::shared_ptr<EtsCooperateManager> GetInstance();
    void EmitAniPromise(std::shared_ptr<AniCallbackInfo> cb);
    void EmitAniAsyncCallback(std::shared_ptr<AniCallbackInfo> cb);
    void EmitAni(std::shared_ptr<AniCallbackInfo> cb);
    void RemoveFailCallback(ani_env *env, const std::string &type, uintptr_t opq,
        std::map<std::string, std::vector<std::shared_ptr<CallbackObject>>> &jsCbMap);
    void RegisterCooperateListener(const std::string &type, callbackType &&f, uintptr_t opq);
    void UnRegisterCooperateListener(const std::string &type, optional_view<uintptr_t> opq);
    void RegisterMouseListener(const std::string &networkId, callbackType &&f, uintptr_t opq);
    void UnRegisterMouseListener(const std::string &networkId, optional_view<uintptr_t> opq);
    void ResetEnv();
    void Prepare(bool enable, uintptr_t opq, ani_object& promise);
    void Activate(const std::string &targetNetworkId, int32_t inputDeviceId, uintptr_t opq, ani_object& promise);
    void Deactivate(bool isUnchained, uintptr_t opq, ani_object& promise);
    void GetCrossingSwitchState(const std::string &networkId, uintptr_t opq, ani_object& promise);
    void ActivateCooperateWithOptions(const std::string &remoteNetworkId, int32_t startDeviceId,
        CooperateOptions_t cooperateOptions, uintptr_t opq, ani_object& promise);
    void OnCoordinationMessage(const std::string &networkId, CoordinationMessage msg) override;
    void OnMouseLocationEvent(const std::string &networkId, const Event &event) override;

private:
    std::atomic_bool isListeningProcess_ { false };
    std::recursive_mutex mutex_;
    std::map<std::string, std::vector<std::shared_ptr<CallbackObject>>> jsCbMap_;
};
} // namespace DeviceStatus
} // Msdp
} // OHOS
#endif // ETS_COOPERATE_MANAGER_H