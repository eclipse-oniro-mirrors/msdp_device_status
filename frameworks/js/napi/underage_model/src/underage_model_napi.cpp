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
#include <nlohmann/json.hpp>
#include <string_view>

#include "devicestatus_define.h"
#include "fi_log.h"
#include "napi_constants.h"
#include "underage_model_napi_error.h"
#include "util_napi_error.h"
#include "user_status_napi_util.h"

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
constexpr int32_t UNSUPP_FRATURE_ERR = 0x3A1000D;
constexpr int32_t DEVICE_UNSUPPORT_ERR = 0x3A10028;
constexpr int32_t ARG_1 = 1;
constexpr int32_t ARG_2 = 2;
constexpr int32_t ARG_3 = 3;
std::mutex g_mutex; // mutex:Subscribe/Unsubscribe/OnListener
const std::array<napi_valuetype, 2> EXPECTED_SUB_ARG_TYPES = { napi_string, napi_function };
const std::array<napi_valuetype, 1> EXPECTED_UNSUB_ONE_ARG_TYPES = { napi_string };
const std::array<napi_valuetype, 2> EXPECTED_UNSUB_TWO_ARG_TYPES = { napi_string, napi_function };
const std::string USER_AGE_GROUP_DETECTED = "userAgeGroupDetected";
const std::string USER_STATUS_CLIENT_SO_PATH = "libuser_status_client.z.so";
const std::string_view REGISTER_LISTENER_FUNC_NAME = { "RegisterListener" };
const std::string_view SUBSCRIBE_CALLBACK_FUNC_NAME = { "SubscribeCallback" };
const std::string_view SUBSCRIBE_FUNC_NAME = { "Subscribe" };
const std::string_view SUBSCRIBE_WITH_DEVICEINFO_FUNC_NAME = { "SubscribeWithDeviceInfo" };
const std::string_view UNSUBSCRIBE_FUNC_NAME = { "Unsubscribe" };
const std::string_view CONFIGPARAMS_FUNC_NAME = { "ConfigParams" };
const std::string_view QUERYCAPABILITIES_FUNC_NAME = { "QueryCapabilities" };
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
    if (napi_send_event(env_, task, napi_eprio_immediate, "underage.listener") != napi_status::napi_ok) {
        FI_HILOGE("Failed to SendEvent");
    }
    FI_HILOGD("Exit");
}

void UserStatusDataCallback::OnReceiveData(int32_t callbackId, std::shared_ptr<UserStatusData> userStatusData)
{
    FI_HILOGI("Enter");
    auto task = [callbackId, userStatusData]() {
        std::lock_guard<std::mutex> guard(g_mutex);
        CHKPV(g_underageModelObj);
        g_underageModelObj->OnReceiveData(callbackId, userStatusData);
    };
    if (napi_send_event(env_, task, napi_eprio_immediate, "userStatus.listener") != napi_status::napi_ok) {
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
    g_subscribeCallbackFunc = nullptr;
    g_subscribeFunc = nullptr;
    g_subscribeWithdeviceInfoFunc = nullptr;
    g_unsubscribeFunc = nullptr;
    g_configParamsFunc = nullptr;
    g_queryCapabilitiesFunc = nullptr;
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
                ThrowUnderageModelErr(env, SUBSCRIBE_EXCEPTION, "Find symbol failed");
                return false;
            }
        }
        auto listener = std::make_shared<UnderageModelListener>(env);
        int32_t ret = std::abs(g_underageModelObj->g_registerListenerFunc(type, listener));
        if (ret < MAX_ERROR_CODE) {
            FI_HILOGE("RegisterListener failed, ret:%{public}d", ret);
            ThrowUnderageModelErr(env, SUBSCRIBE_EXCEPTION, "RegisterListener failed");
            return false;
        }
        if (!Subscribe(env, type)) {
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
        if (type == UNDERAGE_MODEL_TYPE_KID && iter == g_underageModelObj->callbacks_.end()) {
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
            if (type == UNDERAGE_MODEL_TYPE_KID) {
                g_underageModelObj->callbacks_.erase(iter);
            }
            return true;
        } else if (ret == DEVICE_UNSUPPORT_ERR || ret == UNSUPP_FRATURE_ERR) {
            FI_HILOGE("failed to unsubscribe");
            ThrowUnderageModelErr(env, DEVICE_EXCEPTION, "Device not support");
            return false;
        }
        FI_HILOGE("Unsubscribe failed, ret: %{public}d", ret);
        ThrowUnderageModelErr(env, UNSUBSCRIBE_EXCEPTION, "Unsubscribe failed");
    }
    return false;
}

bool UnderageModelNapi::Subscribe(napi_env env, uint32_t type)
{
    if (g_underageModelObj->g_subscribeFunc == nullptr) {
        g_underageModelObj->g_subscribeFunc = reinterpret_cast<SubscribeFunc>(
            dlsym(g_underageModelObj->g_userStatusHandle, SUBSCRIBE_FUNC_NAME.data()));
        if (g_underageModelObj->g_subscribeFunc == nullptr) {
            FI_HILOGE("%{public}s find symbol failed, error: %{public}s", SUBSCRIBE_FUNC_NAME.data(), dlerror());
            ThrowUnderageModelErr(env, SUBSCRIBE_EXCEPTION, "Find symbol failed");
            return false;
        }
    }
    int32_t ret = g_underageModelObj->g_subscribeFunc(type);
    if (ret == RET_OK) {
        return true;
    } else if (ret == DEVICE_UNSUPPORT_ERR || ret == UNSUPP_FRATURE_ERR) {
        FI_HILOGE("failed to subscribe");
        ThrowUnderageModelErr(env, DEVICE_EXCEPTION, "Device not support");
        return false;
    }
    FI_HILOGE("failed to subscribe, ret: %{public}d", ret);
    ThrowUnderageModelErr(env, SUBSCRIBE_EXCEPTION, "Subscribe failed");
    return false;
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
            return nullptr;
        }
        if (!g_underageModelObj->AddCallback(type, args[1])) {
            ThrowUnderageModelErr(env, SERVICE_EXCEPTION, "AddCallback failed");
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

bool UnderageModelNapi::ValidateAndGetDeviceInfo(napi_env env, napi_value arg, std::vector<DeviceInfo>& deviceInfoList)
{
    bool isArray = false;
    if (napi_is_array(env, arg, &isArray) != napi_ok) {
        FI_HILOGE("napi_is_array failed");
        return false;
    }
    if (!isArray) {
        FI_HILOGE("arg is not Array");
        return false;
    }
    deviceInfoList = GetDeviceList(env, arg);
    return true;
}

bool UnderageModelNapi::InitializeCallback(napi_env env, uint32_t featureId)
{
    if (g_underageModelObj->g_callback != nullptr) {
        return true;
    }

    auto userStatusDataCallback = std::make_shared<UserStatusDataCallback>(env);
    g_underageModelObj->g_callback =
        [userStatusDataCallback](int32_t callbackId, std::shared_ptr<UserStatusData> data) -> void {
            if (userStatusDataCallback == nullptr) {
                FI_HILOGE("userStatusDataCallback is nullptr");
                return;
            }
            userStatusDataCallback->OnReceiveData(callbackId, data);
        };

    if (g_underageModelObj->g_subscribeCallbackFunc == nullptr) {
        g_underageModelObj->g_subscribeCallbackFunc = reinterpret_cast<SubscribeCallbackFunc>(
            dlsym(g_underageModelObj->g_userStatusHandle, SUBSCRIBE_CALLBACK_FUNC_NAME.data()));
        if (g_underageModelObj->g_subscribeCallbackFunc == nullptr) {
            FI_HILOGE("%{public}s find symbol failed, error: %{public}s",
                SUBSCRIBE_CALLBACK_FUNC_NAME.data(), dlerror());
            return false;
        }
    }

    g_underageModelObj->g_subscribeCallbackFunc(featureId, g_underageModelObj->g_callback);
    return true;
}

bool UnderageModelNapi::SubscribeWithDeviceInfo(napi_env env, uint32_t featureId,
    const std::vector<DeviceInfo>& deviceInfoList)
{
    if (g_underageModelObj->g_subscribeWithdeviceInfoFunc == nullptr) {
        g_underageModelObj->g_subscribeWithdeviceInfoFunc = reinterpret_cast<SubscribeWithdeviceInfoFunc>(
            dlsym(g_underageModelObj->g_userStatusHandle, SUBSCRIBE_WITH_DEVICEINFO_FUNC_NAME.data()));
        if (g_underageModelObj->g_subscribeWithdeviceInfoFunc == nullptr) {
            FI_HILOGE("%{public}s find symbol failed, error: %{public}s",
                SUBSCRIBE_WITH_DEVICEINFO_FUNC_NAME.data(), dlerror());
            return false;
        }
    }
    
    g_underageModelObj->g_subscribeWithdeviceInfoFunc(featureId, deviceInfoList);
    return true;
}

napi_value UnderageModelNapi::SubscribeUserStatus(napi_env env, napi_callback_info info)
{
    size_t argc = 3;
    napi_value args[3] = { nullptr, nullptr, nullptr };
    napi_value jsThis = nullptr;
    CHKRP(napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr), "napi_get_cb_info fail");
    if (argc != ARG_2 && argc != ARG_3) {
        ThrowUnderageModelErr(env, PARAM_EXCEPTION, "Wrong number of parameters");
        return nullptr;
    }
    napi_valuetype featureType = napi_undefined;
    CHKRP(napi_typeof(env, args[0], &featureType), "napi_typeof fail");
    if (featureType != napi_number) {
        ThrowUnderageModelErr(env, PARAM_EXCEPTION, "Wrong type of args[0]");
        return nullptr;
    }
    uint32_t featureId = 0;
    CHKRP(napi_get_value_uint32(env, args[0], &featureId), "napi_get_value_uint32 fail");
    std::vector<DeviceInfo> deviceInfoList;
    if (argc == ARG_3) {
        if (!ValidateAndGetDeviceInfo(env, args[ARG_2], deviceInfoList)) {
            ThrowUnderageModelErr(env, PARAM_EXCEPTION, "type mismatch for the args[2]");
            return nullptr;
        }
    }
    if (!ConstructUnderageModel(env, jsThis)) {
        ThrowUnderageModelErr(env, SERVICE_EXCEPTION, "Failed to get g_underageModelObj");
        return nullptr;
    }
    if (g_underageModelObj->g_userStatusHandle == nullptr && !LoadLibrary()) {
        ThrowUnderageModelErr(env, DEVICE_EXCEPTION, "Device not support");
        return nullptr;
    }

    if (!InitializeCallback(env, featureId)) {
        ThrowUnderageModelErr(env, SUBSCRIBE_EXCEPTION, "Find symbol failed");
        return nullptr;
    }

    if (!SubscribeWithDeviceInfo(env, featureId, deviceInfoList)) {
        ThrowUnderageModelErr(env, SUBSCRIBE_EXCEPTION, "Find symbol failed");
        return nullptr;
    }

    if (!g_underageModelObj->AddCallback(featureId, args[1])) {
        ThrowUnderageModelErr(env, SERVICE_EXCEPTION, "AddCallback failed");
        return nullptr;
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value UnderageModelNapi::UnsubscribeUserStatus(napi_env env, napi_callback_info info)
{
    if (g_underageModelObj == nullptr) {
        ThrowUnderageModelErr(env, UNSUBSCRIBE_EXCEPTION, "g_underageModelObj is nullptr");
        return nullptr;
    }
    size_t argc = 2;
    napi_value args[2] = { nullptr };
    napi_value jsThis = nullptr;
    napi_value result = nullptr;
    CHKRP(napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr), "napi_get_cb_info fail");
    bool validateArgsRes = false;
    if (argc == UNSUBSCRIBE_ONE_PARA) {
        std::array<napi_valuetype, ARG_1> argTypes = { napi_number };
        validateArgsRes = ValidateArgsType(env, args, argc, argTypes);
    } else if (argc == UNSUBSCRIBE_TWO_PARA) {
        std::array<napi_valuetype, ARG_2> argTypes = { napi_number, napi_function };
        validateArgsRes = ValidateArgsType(env, args, argc, argTypes);
    }
    if (!validateArgsRes) {
        ThrowUnderageModelErr(env, PARAM_EXCEPTION, "validateargstype failed");
        return nullptr;
    }
    uint32_t featureId = 0;
    CHKRP(napi_get_value_uint32(env, args[0], &featureId), "napi_get_value_uint32 fail");
    {
        std::lock_guard<std::mutex> guard(g_mutex);
        if (g_underageModelObj->g_userStatusHandle == nullptr && !LoadLibrary()) {
            ThrowUnderageModelErr(env, DEVICE_EXCEPTION, "Device not support");
            return nullptr;
        }
        if (!RemoveCallbackArgs(featureId, argc, args)) {
            ThrowUnderageModelErr(env, SERVICE_EXCEPTION, "RemoveCallback failed");
            return nullptr;
        }
        if (!UnsubscribeCallback(env, featureId)) {
            return nullptr;
        }
    }
    napi_get_undefined(env, &result);
    return result;
}

bool UnderageModelNapi::ValidateAndParseParams(napi_env env, napi_value args[], uint32_t& featureId,
    std::map<std::string, std::vector<int32_t>>& details)
{
    napi_valuetype featureType = napi_undefined;
    CHKRF(napi_typeof(env, args[0], &featureType), "napi_typeof fail");
    if (featureType != napi_number) {
        ThrowUnderageModelErr(env, PARAM_EXCEPTION, "Wrong type of args[0]");
        return false;
    }
    CHKRF(napi_get_value_uint32(env, args[0], &featureId), "napi_get_value_uint32 fail");

    napi_valuetype paramsType = napi_undefined;
    CHKRF(napi_typeof(env, args[1], &paramsType), "napi_typeof fail");
    if (paramsType != napi_string) {
        ThrowUnderageModelErr(env, PARAM_EXCEPTION, "Wrong type of args[1]");
        return false;
    }

    std::string typeStr;
    if (!TransJsToStr(env, args[1], typeStr)) {
        ThrowUnderageModelErr(env, UNSUBSCRIBE_EXCEPTION, "Trans to string failed");
        return false;
    }
    if (!ParseConfigParams(typeStr, details)) {
        FI_HILOGE("ParseConfigParams failed ret");
        ThrowUnderageModelErr(env, PARAM_EXCEPTION, "Wrong config of details");
        return false;
    }
    return true;
}

napi_value UnderageModelNapi::ConfigParams(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value args[2] = { nullptr };
    napi_value jsThis = nullptr;
    CHKRP(napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr), "napi_get_cb_info fail");
    if (argc != ARG_2) {
        ThrowUnderageModelErr(env, PARAM_EXCEPTION, "Wrong number of parameters");
        return nullptr;
    }

    uint32_t featureId = 0;
    std::map<std::string, std::vector<int32_t>> details;
    if (!ValidateAndParseParams(env, args, featureId, details)) {
        return nullptr;
    }

    if (!ConstructUnderageModel(env, jsThis)) {
        ThrowUnderageModelErr(env, SERVICE_EXCEPTION, "Failed to get g_underageModelObj");
        return nullptr;
    }
    if (g_underageModelObj->g_userStatusHandle == nullptr && !LoadLibrary()) {
        ThrowUnderageModelErr(env, DEVICE_EXCEPTION, "Device not support");
        return nullptr;
    }
    if (g_underageModelObj->g_configParamsFunc == nullptr) {
        g_underageModelObj->g_configParamsFunc = reinterpret_cast<ConfigParamsFunc>(
            dlsym(g_underageModelObj->g_userStatusHandle, CONFIGPARAMS_FUNC_NAME.data()));
        if (g_underageModelObj->g_configParamsFunc == nullptr) {
            FI_HILOGE("%{public}s find symbol failed, error: %{public}s", CONFIGPARAMS_FUNC_NAME.data(), dlerror());
            ThrowUnderageModelErr(env, SERVICE_EXCEPTION, "Find symbol failed");
            return nullptr;
        }
    }
    int32_t ret = g_underageModelObj->g_configParamsFunc(featureId, details);
    napi_value retValue = nullptr;
    CHKRP(napi_create_int32(env, ret, &retValue), "napi_create_int32 fail");
    return retValue;
}

bool UnderageModelNapi::ValidateAndParseArgs(napi_env env, napi_value args[], std::vector<int32_t>& caps)
{
    if (args == nullptr) {
        ThrowUnderageModelErr(env, PARAM_EXCEPTION, "Invalid arguments");
        return false;
    }

    bool isArray = false;
    CHKRF(napi_is_array(env, args[0], &isArray), "napi_is_array fail");
    if (!isArray) {
        ThrowUnderageModelErr(env, PARAM_EXCEPTION, "type mismatch for the argv");
        return false;
    }

    uint32_t length = 0;
    CHKRF(napi_get_array_length(env, args[0], &length), "napi_get_array_length fail");
    if (length == 0) {
        ThrowUnderageModelErr(env, PARAM_EXCEPTION, "array is empty");
        return false;
    }

    napi_value element = nullptr;
    int32_t cap = -1;
    for (uint32_t i = 0; i < length; i++) {
        CHKRF(napi_get_element(env, args[0], i, &element), "napi_get_element fail");
        CHKRF(napi_get_value_int32(env, element, &cap), "napi_get_value_int32 fail");
        caps.emplace_back(cap);
    }
    return true;
}

int32_t UnderageModelNapi::HandleQueryCapabilities(napi_env env, std::vector<int32_t>& caps)
{
    if (g_underageModelObj->g_queryCapabilitiesFunc == nullptr) {
        g_underageModelObj->g_queryCapabilitiesFunc = reinterpret_cast<QueryCapabilitiesFunc>(
            dlsym(g_underageModelObj->g_userStatusHandle, QUERYCAPABILITIES_FUNC_NAME.data()));
        if (g_underageModelObj->g_queryCapabilitiesFunc == nullptr) {
            FI_HILOGE("%{public}s find symbol failed, error: %{public}s",
                QUERYCAPABILITIES_FUNC_NAME.data(), dlerror());
            ThrowUnderageModelErr(env, SERVICE_EXCEPTION, "Find symbol failed");
            return -1;
        }
    }
    return g_underageModelObj->g_queryCapabilitiesFunc(caps);
}

napi_value UnderageModelNapi::QueryCapabilities(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value args[1] = { nullptr };
    napi_value jsThis = nullptr;
    CHKRP(napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr), "napi_get_cb_info fail");
    if (argc != 1) {
        ThrowUnderageModelErr(env, PARAM_EXCEPTION, "Wrong number of parameters");
        return nullptr;
    }
    std::vector<std::int32_t> caps;
    if (!ValidateAndParseArgs(env, args, caps)) {
        return nullptr;
    }

    if (!ConstructUnderageModel(env, jsThis)) {
        ThrowUnderageModelErr(env, SERVICE_EXCEPTION, "Failed to get g_underageModelObj");
        return nullptr;
    }

    if (g_underageModelObj->g_userStatusHandle == nullptr && !LoadLibrary()) {
        ThrowUnderageModelErr(env, DEVICE_EXCEPTION, "Device not support");
        return nullptr;
    }

    int32_t ret = HandleQueryCapabilities(env, caps);
    if (ret != RET_OK) {
        FI_HILOGE("failed to query capabilities, ret: %{public}d", ret);
        return nullptr;
    }

    napi_value napiStringValue = nullptr;
    CHKRP(napi_create_array_with_length(env, caps.size(), &napiStringValue), "create_array_with_length fail");
    uint32_t idx = 0;
    for (auto& each : caps) {
        napi_value eachObj;
        CHKRP(napi_create_object(env, &eachObj), "napi_create_object failed");
        CHKRP(napi_create_int32(env, each, &eachObj), "napi_create_double failed");
        napi_status status = napi_set_element(env, napiStringValue, idx++, eachObj);
        if (status != napi_ok) {
            FI_HILOGE("error: napi set element error: %{public}d, idx: %{public}d", status, idx - 1);
            return nullptr;
        }
    }
    return napiStringValue;
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

napi_value UnderageModelNapi::CreateAgeGroupObject(napi_env env, napi_handle_scope scope)
{
    napi_value userAgeGroup;
    CHKRP_SCOPE(env, napi_create_object(env, &userAgeGroup), CREATE_OBJECT, scope);

    napi_value prop;
    CHKRP_SCOPE(env, napi_create_int32(env, OTHERS, &prop), CREATE_INT32, scope);
    CHKRP_SCOPE(env, napi_set_named_property(env, userAgeGroup, "OTHERS", prop), SET_NAMED_PROPERTY, scope);

    CHKRP_SCOPE(env, napi_create_int32(env, CHILD, &prop), CREATE_INT32, scope);
    CHKRP_SCOPE(env, napi_set_named_property(env, userAgeGroup, "CHILD", prop), SET_NAMED_PROPERTY, scope);

    return userAgeGroup;
}

napi_value UnderageModelNapi::CreateDeviceTypeObject(napi_env env, napi_handle_scope scope)
{
    napi_value deviceType;
    napi_value prop;
    CHKRP_SCOPE(env, napi_create_object(env, &deviceType), CREATE_OBJECT, scope);
    CHKRP_SCOPE(env, napi_create_int32(env, 0, &prop), CREATE_INT32, scope);
    CHKRP_SCOPE(env, napi_set_named_property(env, deviceType, "UNKNOWN_TYPE", prop), SET_NAMED_PROPERTY, scope);
    CHKRP_SCOPE(env, napi_create_int32(env, 0x0C, &prop), CREATE_INT32, scope);
    CHKRP_SCOPE(env, napi_set_named_property(env, deviceType, "PC", prop), SET_NAMED_PROPERTY, scope);
    CHKRP_SCOPE(env, napi_create_int32(env, 0x0E, &prop), CREATE_INT32, scope);
    CHKRP_SCOPE(env, napi_set_named_property(env, deviceType, "PHONE", prop), SET_NAMED_PROPERTY, scope);
    CHKRP_SCOPE(env, napi_create_int32(env, 0x11, &prop), CREATE_INT32, scope);
    CHKRP_SCOPE(env, napi_set_named_property(env, deviceType, "TABLET", prop), SET_NAMED_PROPERTY, scope);
    return deviceType;
}

napi_value UnderageModelNapi::CreateUserStatusFeatureObject(napi_env env, napi_handle_scope scope)
{
    napi_value userStatusFeature;
    CHKRP_SCOPE(env, napi_create_object(env, &userStatusFeature), CREATE_OBJECT, scope);

    struct FeatureProperty {
        const char* name;
        int32_t value;
    };

    const FeatureProperty properties[] = {
        {"GESTURES_RECOGNITION", 5},
        {"ANTI_MISTOUCH", 6},
        {"QUICK_GESTURES_RECOGNITION", 7},
        {"FACE_RELATIVE_POSITION_RECOGNITION", 8},
        {"QUICK_FACE_RELATIVE_POSITION_RECOGNITION", 9},
        {"HAND_GAZE_COORDINATION", 11},
        {"USER_BLOWING_STATUS", 12},
        {"USER_MOOD", 13},
        {"COMFORT_REMINDER", 15},
        {"ENV_SOUND", 17},
        {"EXT_SCREEN_ANTI_MISTOUCH", 19}
    };

    // 使用循环设置属性
    for (const auto& prop : properties) {
        napi_value value;
        CHKRP_SCOPE(env, napi_create_int32(env, prop.value, &value), CREATE_INT32, scope);
        CHKRP_SCOPE(env, napi_set_named_property(env, userStatusFeature, prop.name, value), SET_NAMED_PROPERTY, scope);
    }
    return userStatusFeature;
}

napi_value UnderageModelNapi::CreateUserStatusAtomicCapObject(napi_env env, napi_handle_scope scope)
{
    napi_value userStatusAtomicCap;
    CHKRP_SCOPE(env, napi_create_object(env, &userStatusAtomicCap), CREATE_OBJECT, scope);

    struct AtomicCapProperty {
        const char* name;
        int32_t value;
    };

    const AtomicCapProperty properties[] = {
        {"ATOMIC_UNKNOWN", 0},
        {"FACE_RELATIVE_POSITION", 1},
        {"FACE_NUM_CHANGE", 2},
        {"GESTURE", 3},
        {"FACE_ANGLE", 4},
        {"SENSOR_GRAVITY", 5},
        {"SENSOR_GYROSCOPE", 6},
        {"SENSOR_ACCELEROMETER", 7},
        {"SENSOR_LINEAR_ACCELERATION", 8},
        {"SENSOR_ROTATION_VECTOR", 9},
        {"SENSOR_ORIENTATION", 10},
        {"BLOWING_STATUS", 11},
        {"MOOD_STATUS", 12},
        {"ENV_SOUND", 13},
        {"NOISE_SOUND", 14},
        {"EYE_GAZE_SCREEN", 15}
    };

    // 使用循环设置属性
    for (const auto& prop : properties) {
        napi_value value;
        CHKRP_SCOPE(env, napi_create_int32(env, prop.value, &value), CREATE_INT32, scope);
        CHKRP_SCOPE(env, napi_set_named_property(env, userStatusAtomicCap, prop.name, value),
            SET_NAMED_PROPERTY, scope);
    }

    return userStatusAtomicCap;
}

napi_value UnderageModelNapi::CreateReminderLevelObject(napi_env env, napi_handle_scope scope)
{
    napi_value reminderLevel;
    CHKRP_SCOPE(env, napi_create_object(env, &reminderLevel), CREATE_OBJECT, scope);

    napi_value prop;
    CHKRP_SCOPE(env, napi_create_int32(env, 0, &prop), CREATE_INT32, scope);
    CHKRP_SCOPE(env, napi_set_named_property(env, reminderLevel, "WEAK_REMINDER", prop), SET_NAMED_PROPERTY, scope);

    CHKRP_SCOPE(env, napi_create_int32(env, 1, &prop), CREATE_INT32, scope);
    CHKRP_SCOPE(env, napi_set_named_property(env, reminderLevel, "NORMAL_REMINDER", prop), SET_NAMED_PROPERTY, scope);

    return reminderLevel;
}

bool UnderageModelNapi::CreateUserAgeGroup(napi_env env, napi_value exports)
{
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    CHKPF(scope);

    napi_value userAgeGroup = CreateAgeGroupObject(env, scope);
    if (userAgeGroup != nullptr) {
        CHKRF_SCOPE(env, napi_set_named_property(env, exports, "UserAgeGroup", userAgeGroup),
            SET_NAMED_PROPERTY, scope);
    }

    napi_value deviceType = CreateDeviceTypeObject(env, scope);
    if (deviceType != nullptr) {
        CHKRF_SCOPE(env, napi_set_named_property(env, exports, "DeviceType", deviceType),
            SET_NAMED_PROPERTY, scope);
    }

    napi_value userStatusFeature = CreateUserStatusFeatureObject(env, scope);
    if (userStatusFeature != nullptr) {
        CHKRF_SCOPE(env, napi_set_named_property(env, exports, "UserStatusFeature", userStatusFeature),
            SET_NAMED_PROPERTY, scope);
    }

    napi_value userStatusAtomicCap = CreateUserStatusAtomicCapObject(env, scope);
    if (userStatusAtomicCap != nullptr) {
        CHKRF_SCOPE(env, napi_set_named_property(env, exports, "UserStatusAtomicCap", userStatusAtomicCap),
            SET_NAMED_PROPERTY, scope);
    }

    napi_value reminderLevel = CreateReminderLevelObject(env, scope);
    if (reminderLevel != nullptr) {
        CHKRF_SCOPE(env, napi_set_named_property(env, exports, "ReminderLevel", reminderLevel),
            SET_NAMED_PROPERTY, scope);
    }

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

bool UnderageModelNapi::ParseConfigParams(
    const std::string &params, std::map<std::string, std::vector<int32_t>> &configMap)
{
    if (params.empty() || !nlohmann::json::accept(params)) {
        return false;
    }
    nlohmann::json root = nlohmann::json::parse(params);
    if (!root.contains("params") || !root["params"].is_array()) {
        return false;
    }
    for (const auto& param : root["params"]) {
        if (!param.contains("description") || !param.contains("value")) {
            FI_HILOGE("Skipping invalid param object");
            return false;
        }
        if (!param["description"].is_string() || !param["value"].is_array()) {
            FI_HILOGE("Skipping invalid param object11111");
            return false;
        }
        std::string key = param["description"].get<std::string>();
        std::vector<int32_t> values;
        for (const auto& num : param["value"]) {
            if (num == nullptr || !num.is_number()) {
                return false;
            }
            values.push_back(static_cast<int32_t>(num.get<int>()));
        }
        configMap.emplace(key, values);
    }
    return true;
}

std::vector<DeviceInfo> UnderageModelNapi::GetDeviceList(napi_env env, napi_value deviceNapiValue)
{
    if (env == nullptr) {
        return {};
    }
    uint32_t arrayLength = 0;
    napi_get_array_length(env, deviceNapiValue, &arrayLength);
    std::vector<DeviceInfo> deviceInfoList;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, deviceNapiValue, i, &hasElement);
        napi_value element = nullptr;
        napi_get_element(env, deviceNapiValue, i, &element);
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, element, &valueType);
        if (valueType != napi_object) {
            break;
        }
        std::string deviceId = GetDeviceInfoItem(env, element, "deviceId");
        std::string networkId = GetDeviceInfoItem(env, element, "networkId");
        std::string deviceName = GetDeviceInfoItem(env, element, "deviceName");
        uint32_t deviceType = 0;
        napi_value deviceTypeNApi = nullptr;
        napi_get_named_property(env, element, "deviceType", &deviceTypeNApi);
        napi_typeof(env, deviceTypeNApi, &valueType);
        if (valueType == napi_number) {
            napi_get_value_uint32(env, deviceTypeNApi, &deviceType);
        }
        DeviceInfo deviceInfo(deviceId, deviceName, networkId, deviceType);
        deviceInfoList.emplace_back(deviceInfo);
    }
    return deviceInfoList;
}

std::string UnderageModelNapi::GetDeviceInfoItem(napi_env env, napi_value value, const char *tag)
{
    napi_valuetype valueType = napi_undefined;
    napi_value napiValue = nullptr;
    napi_get_named_property(env, value, tag, &napiValue);
    napi_typeof(env, napiValue, &valueType);
    char result[64] = { 0 };
    if (valueType == napi_string) {
        size_t bufferLen = 0;
        napi_get_value_string_utf8(env, napiValue, result, sizeof(result), &bufferLen);
    }
    return result;
}

napi_value UnderageModelNapi::Init(napi_env env, napi_value exports)
{
    FI_HILOGD("Enter");
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("on", SubscribeUnderageModel),
        DECLARE_NAPI_STATIC_FUNCTION("off", UnsubscribeUnderageModel),
        DECLARE_NAPI_STATIC_FUNCTION("subscribe", SubscribeUserStatus),
        DECLARE_NAPI_STATIC_FUNCTION("unsubscribe", UnsubscribeUserStatus),
        DECLARE_NAPI_STATIC_FUNCTION("configure", ConfigParams),
        DECLARE_NAPI_STATIC_FUNCTION("queryCapabilities", QueryCapabilities)
    };
    MSDP_CALL(napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
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