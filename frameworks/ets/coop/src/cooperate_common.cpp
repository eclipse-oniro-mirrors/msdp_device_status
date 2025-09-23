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

#include "cooperate_common.h"
#include "fi_log.h"


#undef LOG_TAG
#define LOG_TAG "AniCoopCommon"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t ONE_PARAMS = 1;
constexpr int32_t TWO_PARAMS = 2;
}

AniCallbackInfo::~AniCallbackInfo()
{
    CALL_DEBUG_ENTER;
     if (attach_ && vm_) {
        FI_HILOGD("Begin DetachCurrentThread!");
        vm_->DetachCurrentThread();
        attach_ = false;
    }
    if (env_ && ref_) {
        FI_HILOGD("Begin ANI reference delete!");
        env_->GlobalReference_Delete(ref_);
        ref_ = nullptr;
    }
}

bool AniCallbackInfo::init(uintptr_t opq)
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
        FI_HILOGD("beign init callback");
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

////////////////CooperateCommon//////////////////////////////////////////////////
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

void CooperateCommon::ExecAsyncCallbackPromise(ani_env *env, ani_resolver deferred, ani_ref data, ani_ref businessError)
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

ani_status CooperateCommon::ExecAsyncCallBack(ani_env *env, ani_object businessError,
    ani_object param, ani_object callbackFunc)
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
    if ((status = env->FunctionalObject_Call(static_cast<ani_fn_object>(callbackFunc), TWO_PARAMS,
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
    auto iter = NAPI_ERRORS.find(code);
    if (iter == NAPI_ERRORS.end()) {
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
    auto iter = COOPERATE_MSG_MAP.find(msgInfo.msg);
    if (iter == COOPERATE_MSG_MAP.end()) {
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

bool CooperateCommon::IsSameHandle(ani_env *env, ani_ref localRef, ani_ref inRef)
{
    ani_boolean isSame = false;
    ani_status status;
    if ((status = env->Reference_StrictEquals(localRef, inRef, &isSame)) != ANI_OK) {
        FI_HILOGE("Failed to Reference_StrictEquals %{public}d", status);
        return isSame;
    }
    return isSame;
}

ani_status CooperateCommon::ExecCallBack(ani_env *env, ani_object param, ani_object callbackFunc)
{
    CALL_DEBUG_ENTER;
    ani_status status = ANI_ERROR;
    ani_ref ani_argv[] = {param};
    ani_ref ani_result;
    ani_class cls;
    if ((status = env->FindClass("Lstd/core/Function1;", &cls)) != ANI_OK) {
        FI_HILOGE("find calss is failed, status = %{public}d", status);
        return status;
    }
    ani_boolean ret;
    env->Object_InstanceOf(callbackFunc, cls, &ret);
    if (!ret) {
        FI_HILOGE("callbackFunc is not instance Of Function2.");
        return status;
    }
    if ((status = env->FunctionalObject_Call(static_cast<ani_fn_object>(callbackFunc), ONE_PARAMS,
        ani_argv, &ani_result)) != ANI_OK) {
        FI_HILOGE("call ani func failed, status = %{public}d.", status);
        return status;
    }
    return status;
}

/////////////GlobalRefGuard////////////////////////////////////////////////
GlobalRefGuard::GlobalRefGuard(ani_env *env, ani_object obj): env_(env)
{
    CALL_DEBUG_ENTER;
    if (!env_)
        return;
    if (ANI_OK != env_->GlobalReference_Create(obj, &ref_)) {
        FI_HILOGE("Create callback reference failed!");
        ref_ = nullptr;
    }
}

GlobalRefGuard::~GlobalRefGuard()
{
    CALL_DEBUG_ENTER;
    if (env_ && ref_) {
        FI_HILOGD("Begin ANI Reference Delete!");
        env_->GlobalReference_Delete(ref_);
    }
}
} // DeviceStatus
} // Msdp
} // OHOS