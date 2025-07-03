/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "underage_model_napi.h"

#include <cstdlib>
#include <dlfcn.h>
#include <string_view>

#include "devicestatus_define.h"
#include "fi_log.h"
#include "napi_constants.h"
#include "underage_model_napi_error.h"
#include "util_napi_error.h"

#undef LOG_TAG
#define LOG_TAG "DeviceUnderageModelNapi"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr uint32_t INVALID_TYPE = 0;
constexpr uint32_t UNDERAGE_MODEL_TYPE_KID = 16;
constexpr size_t MAX_ARG_STRING_LEN = 512;
constexpr int32_t MAX_ERROR_CODE = 1000;
constexpr uint32_t UNSUBSCRIBE_ONE_PARA = 1;
constexpr uint32_t UNSUBSCRIBE_TWO_PARA = 2;
constexpr int32_t OTHERS = 0;
constexpr int32_t CHILD = 1;
std::mutex g_mutex; // mutex:Subscribe/Unsubscribe/OnListener
const std::array<napi_valuetype, 2> EXPECTED_SUB_ARG_TYPES = { napi_string, napi_function };
const std::array<napi_valuetype, 1> EXPECTED_UNSUB_ONE_ARG_TYPES = { napi_string };
const std::array<napi_valuetype, 2> EXPECTED_UNSUB_TWO_ARG_TYPES = { napi_string, napi_function };
const std::string USER_AGE_GROUP_DETECTED = "userAgeGroupDetected";
const std::string USER_STATUS_CLIENT_SO_PATH = "libuser_status_client.z.so";
const std::string_view REGISTER_LISTENER_FUNC_NAME = { "RegisterListener" };
const std::string_view SUBSCRIBE_FUNC_NAME = { "Subscribe" };
const std::string_view UNSUBSCRIBE_FUNC_NAME = { "Unsubscribe" };
UnderageModelNapi *g_underageModelObj = nullptr;
};

bool UnderageModelNapi::LoadLibrary()
{
    if (g_underageModelObj->g_userStatusHandle == nullptr) {
        g_underageModelObj->g_userStatusHandle = dlopen(USER_STATUS_CLIENT_SO_PATH.c_str(), RTLD_LAZY);
        if (g_underageModelObj->g_userStatusHandle == nullptr) {
            FI_HILOGE("Load failed, path is %{private}s, error after: %{public}s",
                USER_STATUS_CLIENT_SO_PATH.c_str(), dlerror());
            return false;
        }
    }
    return true;
}

void UnderageModelListener::OnUnderageModelListener(uint32_t eventType, int32_t result, float confidence) const
{
    FI_HILOGD("Enter");
    auto task = [eventType, result, confidence]() {
        std::lock_guard<std::mutex> guard(g_mutex);
        CHKPV(g_underageModelObj);
        g_underageModelObj->OnEventChanged(eventType, result, confidence);
    };
    if (napi_send_event(env_, task, napi_eprio_immediate) != napi_status::napi_ok) {
        FI_HILOGE("Failed to SendEvent");
    }
    FI_HILOGD("Exit");
}

UnderageModelNapi::UnderageModelNapi(napi_env env, napi_value thisVar) : UnderageModelNapiEvent(env, thisVar)
{
    env_ = env;
}

UnderageModelNapi::~UnderageModelNapi()
{
    if (g_userStatusHandle != nullptr) {
        dlclose(g_userStatusHandle);
        g_userStatusHandle = nullptr;
    }
    g_registerListenerFunc = nullptr;
    g_subscribeFunc = nullptr;
    g_unsubscribeFunc = nullptr;
}

uint32_t UnderageModelNapi::GetUnderageModelType(const std::string &type)
{
    FI_HILOGD("Enter");
    if (type == USER_AGE_GROUP_DETECTED) {
        return UNDERAGE_MODEL_TYPE_KID;
    }
    FI_HILOGD("Don't find this type");
    return INVALID_TYPE;
}

bool UnderageModelNapi::SubscribeCallback(napi_env env, uint32_t type)
{
    if (g_underageModelObj == nullptr) {
        ThrowUnderageModelErr(env, SUBSCRIBE_EXCEPTION, "g_underageModelObj is nullptr");
        return false;
    }
    auto iter = g_underageModelObj->callbacks_.find(type);
    if (iter == g_underageModelObj->callbacks_.end()) {
        FI_HILOGD("Find no callback, to create");
        if (g_underageModelObj->g_registerListenerFunc == nullptr) {
            g_underageModelObj->g_registerListenerFunc = reinterpret_cast<RegisterListenerFunc>(
                dlsym(g_underageModelObj->g_userStatusHandle, REGISTER_LISTENER_FUNC_NAME.data()));
            if (g_underageModelObj->g_registerListenerFunc == nullptr) {
                FI_HILOGE("RegisterListener find symbol failed, error: %{public}s", dlerror());
                return false;
            }
        }
        auto listener = std::make_shared<UnderageModelListener>(env);
        int32_t ret = std::abs(g_underageModelObj->g_registerListenerFunc(type, listener));
        if (ret < MAX_ERROR_CODE) {
            FI_HILOGE("RegisterListener failed, ret:%{public}d", ret);
            return false;
        }
        g_underageModelObj->callbacks_.insert(std::make_pair(type, listener));
    }
    return true;
}

bool UnderageModelNapi::UnsubscribeCallback(napi_env env, uint32_t type)
{
    if (g_underageModelObj == nullptr) {
        ThrowUnderageModelErr(env, UNSUBSCRIBE_EXCEPTION, "g_underageModelObj is nullptr");
        return false;
    }
    if (!g_underageModelObj->CheckEvents(type)) {
        auto iter = g_underageModelObj->callbacks_.find(type);
        if (iter == g_underageModelObj->callbacks_.end()) {
            FI_HILOGE("Failed to find callback, %{public}d", type);
            ThrowUnderageModelErr(env, UNSUBSCRIBE_EXCEPTION, "Find type failed");
            return false;
        }
        if (g_underageModelObj->g_unsubscribeFunc == nullptr) {
            g_underageModelObj->g_unsubscribeFunc = reinterpret_cast<UnsubscribeFunc>(
                dlsym(g_underageModelObj->g_userStatusHandle, UNSUBSCRIBE_FUNC_NAME.data()));
            if (g_underageModelObj->g_unsubscribeFunc == nullptr) {
                FI_HILOGE("%{public}s find symbol failed, error: %{public}s", UNSUBSCRIBE_FUNC_NAME.data(), dlerror());
                ThrowUnderageModelErr(env, UNSUBSCRIBE_EXCEPTION, "Find symbol failed");
                return false;
            }
        }
        auto ret = g_underageModelObj->g_unsubscribeFunc(type);
        if (ret == RET_OK) {
            g_underageModelObj->callbacks_.erase(iter);
            return true;
        }
        FI_HILOGE("Unsubscribe failed, ret: %{public}d", ret);
    }
    ThrowUnderageModelErr(env, UNSUBSCRIBE_EXCEPTION, "Unsubscribe failed");
    return false;
}

bool UnderageModelNapi::Subscribe(uint32_t type)
{
    if (g_underageModelObj->g_subscribeFunc == nullptr) {
        g_underageModelObj->g_subscribeFunc = reinterpret_cast<SubscribeFunc>(
            dlsym(g_underageModelObj->g_userStatusHandle, SUBSCRIBE_FUNC_NAME.data()));
        if (g_underageModelObj->g_subscribeFunc == nullptr) {
            FI_HILOGE("%{public}s find symbol failed, error: %{public}s", SUBSCRIBE_FUNC_NAME.data(), dlerror());
            return false;
        }
    }
    int32_t ret = g_underageModelObj->g_subscribeFunc(type);
    if (ret != RET_OK) {
        FI_HILOGE("Subscribe failed, ret: %{public}d", ret);
        return false;
    }
    return true;
}

napi_value UnderageModelNapi::SubscribeUnderageModel(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
    size_t argc = 2;
    napi_value args[2] = { nullptr };
    napi_value jsThis = nullptr;
    napi_value result = nullptr;
    if (napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr) != napi_ok) {
        ThrowUnderageModelErr(env, SUBSCRIBE_EXCEPTION, "napi_get_cb_info failed");
        return nullptr;
    }
    if (!ValidateArgsType(env, args, argc, EXPECTED_SUB_ARG_TYPES)) {
        ThrowUnderageModelErr(env, PARAM_EXCEPTION, "validateargstype failed");
        return nullptr;
    }
    std::string typeStr;
    if (!TransJsToStr(env, args[0], typeStr)) {
        ThrowUnderageModelErr(env, SUBSCRIBE_EXCEPTION, "Trans to string failed");
        return nullptr;
    }
    uint32_t type = GetUnderageModelType(typeStr);
    if (type == INVALID_TYPE) {
        ThrowUnderageModelErr(env, PARAM_EXCEPTION, "Type is illegal");
        return nullptr;
    }
    {
        std::lock_guard<std::mutex> guard(g_mutex);
        if (!ConstructUnderageModel(env, jsThis)) {
            ThrowUnderageModelErr(env, SUBSCRIBE_EXCEPTION, "Failed to get g_underageModelObj");
            return nullptr;
        }
        if (g_underageModelObj->g_userStatusHandle == nullptr && !LoadLibrary()) {
            ThrowUnderageModelErr(env, DEVICE_EXCEPTION, "Device not support");
            return nullptr;
        }
        if (!SubscribeCallback(env, type)) {
            ThrowUnderageModelErr(env, SUBSCRIBE_EXCEPTION, "RegisterListener failed");
            return nullptr;
        }
        if (!g_underageModelObj->AddCallback(type, args[1])) {
            ThrowUnderageModelErr(env, SERVICE_EXCEPTION, "AddCallback failed");
            return nullptr;
        }
        if (!Subscribe(type)) {
            ThrowUnderageModelErr(env, SUBSCRIBE_EXCEPTION, "Subscribe failed");
            return nullptr;
        }
    }
    napi_get_undefined(env, &result);
    return result;
}

napi_value UnderageModelNapi::UnsubscribeUnderageModel(napi_env env, napi_callback_info info)
{
    if (g_underageModelObj == nullptr) {
        ThrowUnderageModelErr(env, UNSUBSCRIBE_EXCEPTION, "g_underageModelObj is nullptr");
        return nullptr;
    }
    size_t argc = 2;
    napi_value args[2] = { nullptr };
    napi_value jsThis = nullptr;
    napi_value result = nullptr;
    if (napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr) != napi_ok) {
        ThrowUnderageModelErr(env, UNSUBSCRIBE_EXCEPTION, "napi_get_cb_info is failed");
        return nullptr;
    }
    bool validateArgsRes = false;
    if (argc == UNSUBSCRIBE_ONE_PARA) {
        validateArgsRes = ValidateArgsType(env, args, argc, EXPECTED_UNSUB_ONE_ARG_TYPES);
    } else if (argc == UNSUBSCRIBE_TWO_PARA) {
        validateArgsRes = ValidateArgsType(env, args, argc, EXPECTED_UNSUB_TWO_ARG_TYPES);
    }
    if (!validateArgsRes) {
        ThrowUnderageModelErr(env, PARAM_EXCEPTION, "validateargstype failed");
        return nullptr;
    }
    std::string typeStr;
    if (!TransJsToStr(env, args[0], typeStr)) {
        ThrowUnderageModelErr(env, UNSUBSCRIBE_EXCEPTION, "Trans to string failed");
        return nullptr;
    }
    uint32_t type = GetUnderageModelType(typeStr);
    if (type == INVALID_TYPE) {
        ThrowUnderageModelErr(env, PARAM_EXCEPTION, "Type is illegal");
        return nullptr;
    }
    {
        std::lock_guard<std::mutex> guard(g_mutex);
        if (g_underageModelObj->g_userStatusHandle == nullptr && !LoadLibrary()) {
            ThrowUnderageModelErr(env, DEVICE_EXCEPTION, "Device not support");
            return nullptr;
        }
        if (!RemoveCallbackArgs(type, argc, args)) {
            ThrowUnderageModelErr(env, SERVICE_EXCEPTION, "RemoveCallback failed");
            return nullptr;
        }
        if (!UnsubscribeCallback(env, type)) {
            return nullptr;
        }
    }
    napi_get_undefined(env, &result);
    return result;
}

bool UnderageModelNapi::RemoveCallbackArgs(uint32_t type, size_t argc, napi_value args[])
{
    auto removeRet = false;
    if (argc != UNSUBSCRIBE_TWO_PARA) {
        removeRet = g_underageModelObj->RemoveAllCallback(type);
    } else {
        removeRet = g_underageModelObj->RemoveCallback(type, args[1]);
    }
    return removeRet;
}

bool UnderageModelNapi::ConstructUnderageModel(napi_env env, napi_value jsThis) __attribute__((no_sanitize("cfi")))
{
    if (g_underageModelObj == nullptr) {
        g_underageModelObj = new (std::nothrow) UnderageModelNapi(env, jsThis);
        if (g_underageModelObj == nullptr) {
            FI_HILOGE("faild to get g_underageModelObj");
            return false;
        }
        napi_status status = napi_wrap(env, jsThis, reinterpret_cast<void *>(g_underageModelObj),
            [](napi_env env, void *data, void *hint) {
                (void)env;
                (void)hint;
                if (data != nullptr) {
                    UnderageModelNapi *underageMode = reinterpret_cast<UnderageModelNapi *>(data);
                    delete underageMode;
                    underageMode = nullptr;
                }
            }, nullptr, nullptr);
        if (status != napi_ok) {
            delete g_underageModelObj;
            g_underageModelObj = nullptr;
            FI_HILOGE("napi_wrap failed");
            return false;
        }
    }
    return true;
}

bool UnderageModelNapi::CreateUserAgeGroup(napi_env env, napi_value exports)
{
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    CHKPF(scope);
    napi_value userAgeGroup;
    CHKRF_SCOPE(env, napi_create_object(env, &userAgeGroup), CREATE_OBJECT, scope);
    napi_value prop = nullptr;
    CHKRF_SCOPE(env, napi_create_int32(env, OTHERS, &prop), CREATE_INT32, scope);
    CHKRF_SCOPE(env, napi_set_named_property(env, userAgeGroup, "OTHERS", prop), SET_NAMED_PROPERTY, scope);
    CHKRF_SCOPE(env, napi_create_int32(env, CHILD, &prop), CREATE_INT32, scope);
    CHKRF_SCOPE(env, napi_set_named_property(env, userAgeGroup, "CHILD", prop), SET_NAMED_PROPERTY, scope);
    CHKRF_SCOPE(env, napi_set_named_property(env, exports, "UserAgeGroup", userAgeGroup), SET_NAMED_PROPERTY, scope);
    napi_close_handle_scope(env, scope);
    return true;
}

template<size_t N>
bool UnderageModelNapi::ValidateArgsType(napi_env env, napi_value *args, size_t argc,
    const std::array<napi_valuetype, N> &expectedTypes)
{
    FI_HILOGD("Enter");
    napi_status status = napi_ok;
    napi_valuetype valueType = napi_undefined;
    if (argc > expectedTypes.size()) {
        FI_HILOGE("Wrong number of arguments");
        return false;
    }
    for (size_t i = 0; i < argc; ++i) {
        status = napi_typeof(env, args[i], &valueType);
        if (status != napi_ok) {
            FI_HILOGE("Error while checking arguments types");
            return false;
        }
        if (valueType != expectedTypes[i]) {
            FI_HILOGE("Wrong argument type");
            return false;
        }
    }
    return true;
}

bool UnderageModelNapi::TransJsToStr(napi_env env, napi_value value, std::string &str)
{
    FI_HILOGD("Enter");
    size_t strlen = 0;
    napi_status status = napi_get_value_string_utf8(env, value, nullptr, 0, &strlen);
    if (status != napi_ok) {
        FI_HILOGE("Error string length invalid");
        return false;
    }
    if (strlen > MAX_ARG_STRING_LEN) {
        FI_HILOGE("The string length invalid");
        return false;
    }
    std::vector<char> buf(strlen + 1);
    status = napi_get_value_string_utf8(env, value, buf.data(), strlen+1, &strlen);
    if (status != napi_ok) {
        FI_HILOGE("napi_get_value_string_utf8 failed");
        return false;
    }
    str.assign(buf.data());
    return true;
}

napi_value UnderageModelNapi::Init(napi_env env, napi_value exports)
{
    FI_HILOGD("Enter");
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("on", SubscribeUnderageModel),
        DECLARE_NAPI_STATIC_FUNCTION("off", UnsubscribeUnderageModel),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc)/sizeof(desc[0]), desc));
    if (!CreateUserAgeGroup(env, exports)) {
        FI_HILOGE("Failed create UserAgeGroup");
    }
    FI_HILOGD("Exit");
    return exports;
}

EXTERN_C_START
/*
 * function for module exports
 */
static napi_value UnderageModelInit(napi_env env, napi_value exports)
{
    FI_HILOGD("Enter");
    napi_value ret = UnderageModelNapi::Init(env, exports);
    if (ret == nullptr) {
        FI_HILOGE("Failed to init");
        return ret;
    }
    FI_HILOGD("Exit");
    return ret;
}
EXTERN_C_END

/*
 * Module definition
 */
static napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = "multimodalAwareness.userStatus",
    .nm_register_func = UnderageModelInit,
    .nm_modname = "multimodalAwareness.userStatus",
    .nm_priv = (static_cast<void *>(0)),
    .reserved = { nullptr }
};

/*
 * Module registration
 */
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&g_module);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS