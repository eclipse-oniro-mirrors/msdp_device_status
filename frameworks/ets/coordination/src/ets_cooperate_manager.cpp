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
#include "securec.h"

#include "ets_cooperate_manager.h"
#include "fi_log.h"
#include "devicestatus_errors.h"
#include "devicestatus_define.h"
#include "interaction_manager.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "EtsCooperateManager"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
constexpr int PARAM_NUM = 2;
inline std::string COOPERATE_NAME { "cooperate" };
inline std::string COOPERATE_MESSAGE_NAME { "cooperateMessage" };

AniCallbackInfo::~AniCallbackInfo()
{
    CALL_DEBUG_ENTER;
    if (env_ && ref_) {
        FI_HILOGD("Begin ANI reference delete!");
        env_->GlobalReference_Delete(ref_);
        ref_ = nullptr;
    }
    if (attach_ && vm_) {
        vm_->DetachCurrentThread();
        attach_ = false;
    }
}

bool AniCallbackInfo::Init(uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    env_ = taihe::get_env();
    if (env_ ==  nullptr) {
        FI_HILOGE("ANI Get env is nullptr");
        return false;
    }
    ani_status status = ANI_OK;
    if (ANI_OK != env_->GetVM(&vm_)) {
        FI_HILOGE("env GetVM faild");
        return false;
    }
    if (opq != 0) {
        FI_HILOGD("beign Init callback");
        funObject_ = reinterpret_cast<ani_object>(opq);
        if ((status= env_->GlobalReference_Create(funObject_, &ref_)) != ANI_OK) {
            FI_HILOGE("create callback object failed, status = %{public}d", status);
            ref_ = nullptr;
            return false;
        }
    } else {
        if ((status = env_->Promise_New(&deferred_, &promise_)) != ANI_OK) {
            FI_HILOGE("create promise object failed, status = %{public}d", status);
            return false;
        }
    }
    return true;
}

void AniCallbackInfo::AttachThread()
{
    CALL_DEBUG_ENTER;
    if (attach_) {
        return;
    }
    ani_status status = ANI_OK;
    if ((status = CooperateCommon::GetAniEnv(vm_, &envT_)) != ANI_OK) {
        FI_HILOGE("create promise object failed, status = %{public}d", status);
        return;
    }
    attach_ = true;
}

void AniCallbackInfo::DetachThread()
{
    CALL_DEBUG_ENTER;
    if (attach_ && vm_) {
        vm_->DetachCurrentThread();
        attach_ = false;
    }
}

ani_object CooperateCommon::WrapBusinessError(ani_env* env, const std::string& msg)
{
    ani_class cls {};
    ani_method method {};
    ani_object obj = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        return nullptr;
    }

    ani_string aniMsg = nullptr;
    if ((status = env->String_NewUTF8(msg.c_str(), msg.size(), &aniMsg)) != ANI_OK) {
        return nullptr;
    }

    ani_ref undefRef;
    if ((status = env->GetUndefined(&undefRef)) != ANI_OK) {
        return nullptr;
    }

    if ((status = env->FindClass("Lescompat/Error;", &cls)) != ANI_OK) {
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", "Lstd/core/String;Lescompat/ErrorOptions;:V", &method)) !=
        ANI_OK) {
        return nullptr;
    }

    if ((status = env->Object_New(cls, method, &obj, aniMsg, undefRef)) != ANI_OK) {
        return nullptr;
    }
    return obj;
}

ani_ref CooperateCommon::CreateBusinessError(ani_env* env, ani_int code, const std::string& msg)
{
    ani_class cls;
    ani_status status = ANI_OK;
    if ((status = env->FindClass("L@ohos/base/BusinessError;", &cls)) != ANI_OK) {
        return nullptr;
    }
    ani_method ctor;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "DLescompat/Error;:V", &ctor)) != ANI_OK) {
        return nullptr;
    }
    ani_object error = CooperateCommon::WrapBusinessError(env, msg);
    if (error == nullptr) {
        return nullptr;
    }
    ani_object obj = nullptr;
    ani_double dCode(code);
    if ((status = env->Object_New(cls, ctor, &obj, dCode, error)) != ANI_OK) {
        return nullptr;
    }
    return reinterpret_cast<ani_ref>(obj);
}

ani_status CooperateCommon::GetAniEnv(ani_vm* vm, ani_env** env)
{
    CALL_DEBUG_ENTER;
    if (nullptr == vm) {
        return ANI_ERROR;
    }
    ani_options aniOpt {0, nullptr};
    auto status = vm->AttachCurrentThread(&aniOpt, ANI_VERSION_1, env);
    return status;
}

void CooperateCommon::ExecAsyncCallbackPromise(ani_env *env, ani_resolver deferred, ani_ref data,
    ani_ref businessError)
{
    CALL_DEBUG_ENTER;
    if (nullptr == env) {
        FI_HILOGE("env is null");
        return;
    }
    if (nullptr == deferred) {
        FI_HILOGE("deferred is null");
        return;
    }
    ani_status status = ANI_OK;
    if (businessError != nullptr) {
        if ((status = env->PromiseResolver_Reject(deferred, static_cast<ani_error>(businessError))) != ANI_OK) {
            FI_HILOGE("promise reject failed, status = %{public}d", status);
        }
        return;
    }
    if (nullptr == data) {
        if ((status = env->GetUndefined(&data)) != ANI_OK) {
            FI_HILOGE("get undefined value failed, status = %{public}d", status);
            return;
        }
    }
    if ((status = env->PromiseResolver_Resolve(deferred, data)) != ANI_OK) {
        FI_HILOGE("promiseResolver resolve failed, status = %{public}d", status);
        return;
    }
    return;
}

ani_status CooperateCommon::ExecAsyncCallBack(ani_env *env, ani_object businessError,  ani_object param,
    ani_object callbackFunc)
{
    CALL_DEBUG_ENTER;
    ani_status status = ANI_ERROR;
    ani_ref ani_argv[] = {businessError, param};
    ani_ref ani_result;
    ani_class cls;
    if ((status = env->FindClass("Lstd/core/Function2;", &cls)) != ANI_OK) {
        FI_HILOGE("find calss is failed, status = %{public}d", status);
        return status;
    }
    ani_boolean ret;
    env->Object_InstanceOf(callbackFunc, cls, &ret);
    if (!ret) {
        FI_HILOGE("callbackFunc is not instance Of Function2.");
        return status;
    }
    if ((status = env->FunctionalObject_Call(static_cast<ani_fn_object>(callbackFunc), PARAM_NUM,
        ani_argv, &ani_result)) != ANI_OK) {
        FI_HILOGE("call ani func failed, status = %{public}d.", status);
        return status;
    }
    return status;
}

ani_object CooperateCommon::CreateBooleanObject(ani_env *env, bool value)
{
    CALL_DEBUG_ENTER;
    if (env == nullptr) {
        FI_HILOGE("Env is null.");
        return nullptr;
    }

    ani_class persionCls;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass("std.core.Boolean", &persionCls)) != ANI_OK) {
        FI_HILOGE("Failed to FindClass, status : %{public}d.", static_cast<int32_t>(status));
        return nullptr;
    }
    ani_method personInfoCtor;
    if ((status = env->Class_FindMethod(persionCls, "<ctor>", "z:", &personInfoCtor)) != ANI_OK) {
        FI_HILOGE("Failed to FindMethod, status : %{public}d.", static_cast<int32_t>(status));
        return nullptr;
    }
    ani_object personInfoObj;
    if ((status = env->Object_New(persionCls, personInfoCtor, &personInfoObj, value)) != ANI_OK) {
        FI_HILOGE("Failed to Object_New, status : %{public}d.", static_cast<int32_t>(status));
        return nullptr;
    }
    return personInfoObj;
}

ani_object CooperateCommon::CreateIntObject(ani_env *env, int32_t value)
{
    CALL_DEBUG_ENTER;
    if (env == nullptr) {
        FI_HILOGE("Env is null.");
        return nullptr;
    }

    ani_class persionCls;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass("std.core.Int", &persionCls)) != ANI_OK) {
        FI_HILOGE("Failed to FindClass, status : %{public}d.", static_cast<int32_t>(status));
        return nullptr;
    }
    ani_method aniMethod;
    if ((status = env->Class_FindMethod(persionCls, "<ctor>", "i:", &aniMethod)) != ANI_OK) {
        FI_HILOGE("Failed to FindMethod, status : %{public}d.", static_cast<int32_t>(status));
        return nullptr;
    }
    ani_object aniObject;
    if ((status = env->Object_New(persionCls, aniMethod, &aniObject, value)) != ANI_OK) {
        FI_HILOGE("Failed to Object_New, status : %{public}d.", static_cast<int32_t>(status));
        return nullptr;
    }
    return aniObject;
}

bool CooperateCommon::GetErrorMsg(int32_t code, std::string &codeMsg)
{
    auto iter = ETS_ERRORS.find(code);
    if (iter == ETS_ERRORS.end()) {
        FI_HILOGE("Error code %{public}d not found", code);
        return false;
    }
    codeMsg = iter->second;
    return true;
}

void CooperateCommon::HandleExecuteResult(int32_t errCode, const std::string param1,
    const std::string param2)
{
    switch (errCode) {
        case COMMON_PERMISSION_CHECK_ERROR: {
            std::string codeMsg;
            if (!CooperateCommon::GetErrorMsg(errCode, codeMsg)) {
                FI_HILOGE("GetErrorMsg failed");
                return;
            }
            char buf[300] = { 0 };
            int32_t ret = sprintf_s(buf, sizeof(buf), codeMsg.c_str(), param1.c_str(), param2.c_str());
            if (ret > 0) {
                taihe::set_business_error(ret, buf);
            } else {
                FI_HILOGE("Failed to convert string type to char type, error code:%{public}d", errCode);
            }
            break;
        }
        case COMMON_PARAMETER_ERROR: {
            taihe::set_business_error(errCode, "param is invalid");
            break;
        }
        case COMMON_NOT_SYSTEM_APP: {
            std::string errMsg;
            if (!CooperateCommon::GetErrorMsg(errCode, errMsg)) {
                FI_HILOGE("GetErrorMsg failed");
                return;
            }
            taihe::set_business_error(errCode, errMsg.c_str());
            break;
        }
        case COMMON_NOT_ALLOWED_DISTRIBUTED: {
            std::string errMsg;
            if (!CooperateCommon::GetErrorMsg(errCode, errMsg)) {
                FI_HILOGE("GetErrorMsg failed");
                return;
            }
            taihe::set_business_error(COMMON_PARAMETER_ERROR, errMsg.c_str());
            break;
        }
        default: {
            FI_HILOGW("Unknown error throwcode:%{public}d", errCode);
            taihe::set_business_error(COMMON_PARAMETER_ERROR, "unknown error");
            break;
        }
    }
}

bool CooperateCommon::GetErrMsg(const CoordinationMsgInfo &msgInfo, std::string &msg)
{
    auto iter = MSG_MAP.find(msgInfo.msg);
    if (iter == MSG_MAP.end()) {
        FI_HILOGE("Error code:%{public}d is not founded in COOPERATE_MSG_MAP", static_cast<int32_t> (msgInfo.msg));
        return false;
    }
    msg = iter->second;
    switch (static_cast<CoordinationErrCode>(msgInfo.errCode)) {
        case CoordinationErrCode::COORDINATION_OK: {
            msg += "Everything is fine";
            break;
        }
        case CoordinationErrCode::OPEN_SESSION_FAILED: {
            msg += "Open session failed";
            break;
        }
        case CoordinationErrCode::SEND_PACKET_FAILED: {
            msg += "Send packet failed";
            break;
        }
        case CoordinationErrCode::UNEXPECTED_START_CALL: {
            msg += "Unexpected start call";
            break;
        }
        case CoordinationErrCode::WORKER_THREAD_TIMEOUT: {
            msg += "Worker thread timeout";
            break;
        }
        case CoordinationErrCode::NOT_AOLLOW_COOPERATE_WHEN_MOTION_DRAGGING: {
            msg += "Not allow cooperate when motion dragging";
            break;
        }
        default:
            msg +="Softbus bind failed";
    }
    return true;
}

int32_t CooperateCommon::GetErrCode(const CoordinationMsgInfo &msgInfo)
{
    switch (static_cast<CoordinationErrCode>(msgInfo.errCode)) {
        case CoordinationErrCode::OPEN_SESSION_FAILED: {
            return CustomErrCode::OPEN_SESSION_FAILED;
        }
        case CoordinationErrCode::SEND_PACKET_FAILED: {
            return CustomErrCode::SEND_PACKET_FAILED;
        }
        case CoordinationErrCode::UNEXPECTED_START_CALL: {
            return CustomErrCode::UNEXPECTED_START_CALL;
        }
        case CoordinationErrCode::WORKER_THREAD_TIMEOUT: {
            return CustomErrCode::WORKER_THREAD_TIMEOUT;
        }
        case CoordinationErrCode::NOT_AOLLOW_COOPERATE_WHEN_MOTION_DRAGGING: {
            return CustomErrCode::NOT_AOLLOW_COOPERATE_WHEN_MOTION_DRAGGING;
        }
        default:
            return msgInfo.errCode;
    }
}

EtsCooperateManager::EtsCooperateManager()
{
    CALL_DEBUG_ENTER;
    auto ret = jsCbMap_.insert({ COOPERATE_NAME, std::vector<std::shared_ptr<CallbackObject>>() });
    if (!ret.second) {
        FI_HILOGW("Failed to insert, errCode:%{public}d", static_cast<int32_t>(VAL_NOT_EXP));
    }
}

std::shared_ptr<EtsCooperateManager> EtsCooperateManager::GetInstance()
{
    static std::once_flag flag;
    static std::shared_ptr<EtsCooperateManager> instance_;

    std::call_once(flag, []() {
        instance_ = std::make_shared<EtsCooperateManager>();
    });
    return instance_;
}

void EtsCooperateManager::EmitAniPromise(std::shared_ptr<AniCallbackInfo> cb)
{
    CALL_DEBUG_ENTER;
    if (cb == nullptr) {
        FI_HILOGE("cb is nullptr");
        return;
    }
    if (cb->promise_ != nullptr) {
        FI_HILOGE("promise is nullptr");
        return;
    }
    auto env = cb->envT_;
    if (cb->result_) {
        CooperateCommon::ExecAsyncCallbackPromise(env, cb->deferred_, nullptr, nullptr);
        return;
    }
    std::string errMsg;
    if (!CooperateCommon::GetErrMsg(cb->msgInfo_, errMsg)) {
        FI_HILOGE("GetErrMsg failed");
        return;
    }
    int32_t errorCode = CooperateCommon::GetErrCode(cb->msgInfo_);
    FI_HILOGD("errorCode:%{public}d, msg:%{public}s", errorCode, errMsg.c_str());
    auto callResult = CooperateCommon::CreateBusinessError(env, static_cast<ani_int>(errorCode), errMsg);
    if (callResult == nullptr) {
        FI_HILOGE("The callResult is nullptr");
        return;
    }
    CooperateCommon::ExecAsyncCallbackPromise(env, cb->deferred_, callResult, nullptr);
    return;
}

void EtsCooperateManager::EmitAniAsyncCallback(std::shared_ptr<AniCallbackInfo> cb)
{
    CALL_DEBUG_ENTER;
    if (cb == nullptr) {
        FI_HILOGE("cb is nullptr");
        return;
    }
    if (cb->funObject_ != nullptr) {
        FI_HILOGE("promise is nullptr");
        return;
    }
    auto env = cb->envT_;
    ani_ref  aniUndefined;
    ani_ref  aniNull;
    ani_status status;
    if ((status = env->GetUndefined(&aniUndefined)) != ANI_OK) {
        FI_HILOGE("get undefined value failed, status = %{public}d", status);
        return;
    }
    if ((status = env->GetNull(&aniNull)) != ANI_OK) {
        FI_HILOGE("get undefined value failed, status = %{public}d", status);
        return;
    }
    if (cb->result_) {
        CooperateCommon::ExecAsyncCallBack(env, static_cast<ani_object>(aniNull),
            static_cast<ani_object>(aniUndefined), cb->funObject_);
        return;
    }
    std::string errMsg;
    if (!CooperateCommon::GetErrMsg(cb->msgInfo_, errMsg)) {
        FI_HILOGE("GetErrMsg failed");
        return;
    }
    int32_t errorCode = CooperateCommon::GetErrCode(cb->msgInfo_);
    FI_HILOGD("errorCode:%{public}d, msg:%{public}s", errorCode, errMsg.c_str());
    auto callResult = CooperateCommon::CreateBusinessError(env, static_cast<ani_int>(errorCode), errMsg);
    if (callResult == nullptr) {
        FI_HILOGE("The callResult is nullptr");
        return;
    }
    CooperateCommon::ExecAsyncCallBack(env, static_cast<ani_object>(callResult),
        static_cast<ani_object>(aniUndefined), cb->funObject_);
    return;
}

void EtsCooperateManager::EmitAni(std::shared_ptr<AniCallbackInfo> cb)
{
    CALL_DEBUG_ENTER;
    if (cb == nullptr) {
        FI_HILOGE("cb is nullptr");
        return;
    }
    if (cb->promise_ != nullptr) {
        EmitAniPromise(cb);
        return;
    }
    EmitAniAsyncCallback(cb);
}

void EtsCooperateManager::RemoveFailCallback(ani_env *env, const std::string &type, uintptr_t opq, std::map<std::string,
    std::vector<std::shared_ptr<CallbackObject>>> &jsCbMap_)
{
    if (env == nullptr) {
        FI_HILOGE("ani_env is nullptr!");
        return;
    }
    const auto cbVec = jsCbMap_.find(type);
    if (cbVec == jsCbMap_.end()) {
        FI_HILOGE("type is invaild");
        return;
    }
    GlobalRefGuard guard(env, reinterpret_cast<ani_object>(opq));
    if (!guard) {
        FI_HILOGE("GlobalRefGuard is false!");
        return;
    }
    const auto pred = [env, targetRef = guard.get()](std::shared_ptr<CallbackObject> &obj) {
        ani_boolean is_equal = false;
        return (ANI_OK == env->Reference_StrictEquals(targetRef, obj->ref, &is_equal)) && is_equal;
    };
    auto &callbacks = cbVec->second;
    const auto it = std::find_if(callbacks.begin(), callbacks.end(), pred);
    if (it != callbacks.end()) {
        FI_HILOGI("remove callback success");
        callbacks.erase(it);
    }
}

void EtsCooperateManager::RegisterCooperateListener(const std::string &type, callbackType &&f, uintptr_t opq)
{
    CALL_INFO_TRACE;
    std::string listenerType = type;
    bool isCompatible = false;
    if (type == COOPERATE_MESSAGE_NAME) {
        isCompatible = true;
        listenerType = COOPERATE_NAME;
    }
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_ref callbackRef;
    ani_env *env = taihe::get_env();
    if (env == nullptr || ANI_OK != env->GlobalReference_Create(callbackObj, &callbackRef)) {
        FI_HILOGE("ani_env is nullptr or GlobalReference_Create failed");
        return;
    }
    auto &cbVec = jsCbMap_[listenerType];
    bool isDuplicate = std::any_of(cbVec.begin(), cbVec.end(), [env, callbackRef](
        std::shared_ptr<CallbackObject> &obj) {
        ani_boolean isEqual = false;
        return (ANI_OK == env->Reference_StrictEquals(callbackRef, obj->ref, &isEqual)) && isEqual;
    });
    if (isDuplicate) {
        env->GlobalReference_Delete(callbackRef);
        FI_HILOGD("cooperate callback already registered");
        return;
    }
    cbVec.emplace_back(std::make_shared<CallbackObject>(f, callbackRef));
    FI_HILOGI("register cooperate callback success");
    if (!isListeningProcess_) {
        int32_t errCode = INTERACTION_MGR->RegisterCoordinationListener(shared_from_this(), isCompatible);
        if (errCode != RET_OK) {
            FI_HILOGE("RegisterCooperateListener failed, ret:%{public}d", errCode);
            {
                std::lock_guard<std::recursive_mutex> guard(mutex_);
                RemoveFailCallback(env, listenerType, opq, jsCbMap_);
                CooperateCommon::HandleExecuteResult(errCode, "on", COOPERATE_PERMISSION);
            }
            return;
        }
        FI_HILOGE("RegisterEventListener success!");
        isListeningProcess_ = true;
    }
}

void EtsCooperateManager::UnRegisterCooperateListener(const std::string &type, optional_view<uintptr_t> opq)
{
    CALL_INFO_TRACE;
    std::string listenerType = type;
    bool isCompatible = false;
    bool shouldUnregister = false;
    if (type == COOPERATE_MESSAGE_NAME) {
        isCompatible = true;
        listenerType = COOPERATE_NAME;
    }
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const auto iter = jsCbMap_.find(listenerType);
    if (iter == jsCbMap_.end()) {
        FI_HILOGE("Not exist %{public}s", listenerType.c_str());
        return;
    }
    if (!opq.has_value()) {
        jsCbMap_.erase(iter);
        FI_HILOGD("cooperate callback is nullptr!");
        shouldUnregister = true;
        return;
    }
    ani_env *env = taihe::get_env();
    GlobalRefGuard guard(env, reinterpret_cast<ani_object>(opq.value()));
    if (env == nullptr || !guard) {
        FI_HILOGE("ani_env is nullptr or GlobalRefGuard is false!");
        return;
    }
    const auto pred = [env, targetRef = guard.get()](std::shared_ptr<CallbackObject> &obj) {
        ani_boolean is_equal = false;
        return (ANI_OK == env->Reference_StrictEquals(targetRef, obj->ref, &is_equal)) && is_equal;
    };
    auto &callbacks = iter->second;
    const auto it = std::find_if(callbacks.begin(), callbacks.end(), pred);
    if (it != callbacks.end()) {
        FI_HILOGI("unRegister cooperate callback success");
        callbacks.erase(it);
    }
    if (callbacks.empty()) {
        jsCbMap_.erase(iter);
        shouldUnregister = true;
    }
    if (shouldUnregister && isListeningProcess_) {
        int32_t errCode = INTERACTION_MGR->UnregisterCoordinationListener(shared_from_this(), isCompatible);
        if (errCode == RET_OK) {
            isListeningProcess_ = false;
        } else {
            CooperateCommon::HandleExecuteResult(errCode, "off", COOPERATE_PERMISSION);
        }
    }
}

void EtsCooperateManager::RegisterMouseListener(const std::string &networkId, callbackType &&f, uintptr_t opq)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_ref callbackRef;
    ani_env *env = taihe::get_env();
    if (env == nullptr || ANI_OK != env->GlobalReference_Create(callbackObj, &callbackRef)) {
        FI_HILOGE("ani_env is nullptr or GlobalReference_Create failed");
        return;
    }
    auto &cbVec = jsCbMap_[networkId];
    bool isDuplicate = std::any_of(cbVec.begin(), cbVec.end(), [env, callbackRef](
        std::shared_ptr<CallbackObject> &obj) {
        ani_boolean isEqual = false;
        return (ANI_OK == env->Reference_StrictEquals(callbackRef, obj->ref, &isEqual)) && isEqual;
    });
    if (isDuplicate) {
        env->GlobalReference_Delete(callbackRef);
        FI_HILOGD("callback already registered");
        return;
    }
    cbVec.emplace_back(std::make_shared<CallbackObject>(f, callbackRef));
    int32_t errCode = INTERACTION_MGR->RegisterEventListener(networkId, shared_from_this());
    if (errCode != RET_OK) {
        FI_HILOGE("RegisterEventListener for networkId:%{public}s failed, ret:%{public}d",
            Utility::Anonymize(networkId).c_str(), errCode);
        {
            RemoveFailCallback(env, networkId, opq, jsCbMap_);
            CooperateCommon::HandleExecuteResult(errCode, "on", COOPERATE_PERMISSION);
        }
        return;
    }
}

void EtsCooperateManager::UnRegisterMouseListener(const std::string &networkId, optional_view<uintptr_t> opq)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const auto iter = jsCbMap_.find(networkId);
    if (iter == jsCbMap_.end()) {
        FI_HILOGE("Not exist callback");
        return;
    }
    if (!opq.has_value()) {
        jsCbMap_.erase(iter);
        FI_HILOGD("cooperate mouse callback is nullptr!");
        return;
    }
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        FI_HILOGE("ani_env is nullptr!");
        return;
    }
    GlobalRefGuard guard(env, reinterpret_cast<ani_object>(opq.value()));
    if (!guard) {
        FI_HILOGE("GlobalRefGuard is false!");
        return;
    }
    const auto pred = [env, targetRef = guard.get()](std::shared_ptr<CallbackObject> &obj) {
        ani_boolean is_equal = false;
        return (ANI_OK == env->Reference_StrictEquals(targetRef, obj->ref, &is_equal)) && is_equal;
    };
    auto &callbacks = iter->second;
    const auto it = std::find_if(callbacks.begin(), callbacks.end(), pred);
    if (it != callbacks.end()) {
        FI_HILOGI("unRegister cooperate callback success");
        callbacks.erase(it);
    }
    if (callbacks.empty()) {
        jsCbMap_.erase(iter);
    }
    int32_t errCode = INTERACTION_MGR->UnregisterEventListener(networkId, shared_from_this());
    if (errCode != RET_OK) {
        FI_HILOGE("UnregisterEventListener for networkId:%{public}s failed, ret:%{public}d",
            Utility::Anonymize(networkId).c_str(), errCode);
            CooperateCommon::HandleExecuteResult(errCode, "off", COOPERATE_PERMISSION);
    }
}

void EtsCooperateManager::ResetEnv()
{
    CALL_INFO_TRACE;
    INTERACTION_MGR->UnregisterCoordinationListener(shared_from_this());
}

// isCompatible 省略 均为true，新增enable 区分Prepare 与 Unprepare
void EtsCooperateManager::Prepare(bool enable, uintptr_t opq, ani_object& promise)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<AniCallbackInfo> cb = std::make_shared<AniCallbackInfo>(CallbackType::PREPARE);
    CHKPV(cb);
    if (!cb->Init(opq)) {
        FI_HILOGE("Init err");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "internal Error");
        return;
    }
    promise = cb->promise_;
    auto callback = [this, cb](const std::string &networkId, const CoordinationMsgInfo &msgInfo) {
        CALL_DEBUG_ENTER;
        cb->result_ = (msgInfo.msg == CoordinationMessage::PREPARE ||
            msgInfo.msg == CoordinationMessage::UNPREPARE);
        cb->msgInfo_ = msgInfo;
        cb->AttachThread();
        EmitAni(cb);
        cb->DetachThread();
    };
    int32_t errCode = 0;
    std::string name = enable ? "prepare" : "unprepare";
    if (enable) {
        errCode = INTERACTION_MGR->PrepareCoordination(callback, true);
    } else {
        errCode = INTERACTION_MGR->UnprepareCoordination(callback, true);
    }
    if (errCode != RET_OK) {
        CooperateCommon::HandleExecuteResult(errCode, name, COOPERATE_PERMISSION);
    }
    return;
}

// bool isCompatible 忽略 为true
void EtsCooperateManager::Activate(const std::string &targetNetworkId, int32_t inputDeviceId,
    uintptr_t opq, ani_object& promise)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<AniCallbackInfo> cb = std::make_shared<AniCallbackInfo>(CallbackType::ACTIVATE);
    CHKPV(cb);
    if (!cb->Init(opq)) {
        FI_HILOGE("Init err");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "internal Error");
        return;
    }
    promise = cb->promise_;
    auto callback = [this, cb](const std::string &targetNetworkId, const CoordinationMsgInfo &msgInfo) {
        CALL_DEBUG_ENTER;
        cb->result_ = (msgInfo.msg == CoordinationMessage::ACTIVATE_SUCCESS);
        cb->msgInfo_ = msgInfo;
        cb->AttachThread();
        EmitAni(cb);
        cb->DetachThread();
    };
    int32_t errCode = INTERACTION_MGR->ActivateCoordination(targetNetworkId, inputDeviceId, callback, true);
    if (errCode != RET_OK) {
        CooperateCommon::HandleExecuteResult(errCode, "activate", COOPERATE_PERMISSION);
    }
    return;
}

// bool isCompatible 忽略 为true
void EtsCooperateManager::Deactivate(bool isUnchained, uintptr_t opq, ani_object& promise)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<AniCallbackInfo> cb = std::make_shared<AniCallbackInfo>(CallbackType::DEACTIVATE);
    CHKPV(cb);
    if (!cb->Init(opq)) {
        FI_HILOGE("Init err");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "internal Error");
        return;
    }
    promise = cb->promise_;
    auto callback = [this, cb](const std::string &networkId, const CoordinationMsgInfo &msgInfo) {
        CALL_DEBUG_ENTER;
        cb->result_ = (msgInfo.msg == CoordinationMessage::DEACTIVATE_SUCCESS);
        cb->msgInfo_ = msgInfo;
        cb->AttachThread();
        EmitAni(cb);
        cb->DetachThread();
    };
    int32_t errCode = INTERACTION_MGR->DeactivateCoordination(isUnchained, callback, true);
    if (errCode != RET_OK) {
        CooperateCommon::HandleExecuteResult(errCode, "deactivate", COOPERATE_PERMISSION);
    }
    return;
}

// bool isCompatible 忽略 为true
void EtsCooperateManager::GetCrossingSwitchState(const std::string &networkId, uintptr_t opq, ani_object& promise)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<AniCallbackInfo> cb = std::make_shared<AniCallbackInfo>(CallbackType::GETSTATE);
    CHKPV(cb);
    if (!cb->Init(opq)) {
        FI_HILOGE("Init err");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "internal Error");
        return;
    }
    promise = cb->promise_;
    auto callback = [this, cb](bool state) {
        CALL_DEBUG_ENTER;
        cb->coordinationOpened_ = state;
        cb->AttachThread();
        EmitAni(cb);
        cb->DetachThread();
    };
    int32_t errCode = INTERACTION_MGR->GetCoordinationState(networkId, callback, true);
    if (errCode != RET_OK) {
        CooperateCommon::HandleExecuteResult(errCode, "getCrossingSwitchState", COOPERATE_PERMISSION);
    }
    return;
}

void EtsCooperateManager::ActivateCooperateWithOptions(const std::string &remoteNetworkId, int32_t startDeviceId,
    CooperateOptions_t cooperateOptions, uintptr_t opq, ani_object& promise)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<AniCallbackInfo> cb = std::make_shared<AniCallbackInfo>(CallbackType::ACTIVATEOPTIONS);
    CHKPV(cb);
    if (!cb->Init(opq)) {
        FI_HILOGE("Init err");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "internal Error");
        return;
    }
    promise = cb->promise_;
    auto callback = [this, cb](const std::string &remoteNetworkId, const CoordinationMsgInfo &msgInfo) {
        CALL_DEBUG_ENTER;
        cb->result_ = (msgInfo.msg == CoordinationMessage::ACTIVATE_SUCCESS);
        cb->msgInfo_ = msgInfo;
        cb->AttachThread();
        EmitAni(cb);
        cb->DetachThread();
    };
    // 转换
    CooperateOptions opts {
        .displayX = cooperateOptions.displayX,
        .displayY = cooperateOptions.displayY,
        .displayId = cooperateOptions.displayId
    };
    int32_t errCode =
        INTERACTION_MGR->ActivateCooperateWithOptions(remoteNetworkId, startDeviceId, callback, opts);
    if (errCode != RET_OK) {
        CooperateCommon::HandleExecuteResult(errCode, "activateCooperateWithOptions", COOPERATE_PERMISSION);
    }
    return;
}

void EtsCooperateManager::OnCoordinationMessage(const std::string &networkId, CoordinationMessage msg)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (jsCbMap_.empty()) {
        FI_HILOGE("The listener list is empty");
        return;
    }
    auto changeEvent = jsCbMap_.find(COOPERATE_NAME);
    if (changeEvent == jsCbMap_.end()) {
        FI_HILOGE("Find %{public}s failed", std::string(COOPERATE_NAME).c_str());
        return;
    }
    for (auto &item : changeEvent->second) {
        CHKPC(item);
        auto &func = std::get<taihe::callback<void(CooperateMessage_t const&)>>(item->callback);
        CooperateMessage_t message = {
            .networkId = std::string_view(networkId),
            .state = CooperateState_t::from_value(static_cast<int32_t>(msg))
        };
        func(message);
    }
}
void EtsCooperateManager::OnMouseLocationEvent(const std::string &networkId, const Event &event)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (jsCbMap_.empty()) {
        FI_HILOGE("The listener list is empty");
        return;
    }
    auto changeEvent = jsCbMap_.find(networkId);
    if (changeEvent == jsCbMap_.end()) {
        FI_HILOGE("Find listener for %{public}s failed", Utility::Anonymize(networkId).c_str());
        return;
    }
    for (auto &item : changeEvent->second) {
        CHKPC(item);
        auto &func = std::get<taihe::callback<void(MouseLocation_t const&)>>(item->callback);
        MouseLocation_t mouse = {
            .displayX = event.displayX,
            .displayY = event.displayY,
            .displayWidth = event.displayWidth,
            .displayHeight = event.displayHeight
        };
        func(mouse);
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS