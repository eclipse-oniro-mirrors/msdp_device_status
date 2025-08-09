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

#include "devicestatus_napi.h"

#include <js_native_api.h>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "devicestatus_client.h"
#include "devicestatus_define.h"
#include "devicestatus_napi_error.h"
#include "stationary_manager.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusNapi"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr size_t ARG_0 { 0 };
constexpr size_t ARG_1 { 1 };
constexpr size_t ARG_2 { 2 };
constexpr size_t ARG_3 { 3 };
constexpr size_t ARG_4 { 4 };
constexpr int32_t NAPI_BUF_LENGTH { 256 };
constexpr int32_t NANO { 1000000000 };
const std::vector<std::string> vecDeviceStatusValue {
    "VALUE_ENTER", "VALUE_EXIT"
};
thread_local DeviceStatusNapi *g_obj = nullptr;
} // namespace
std::map<int32_t, sptr<IRemoteDevStaCallback>> DeviceStatusNapi::callbacks_;
napi_ref DeviceStatusNapi::devicestatusValueRef_ = nullptr;

void DeviceStatusCallback::OnDeviceStatusChanged(const Data& devicestatusData)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    FI_HILOGD("devicestatusData.type:%{public}d, devicestatusData.value:%{public}d",
        devicestatusData.type, devicestatusData.value);
    data_ = devicestatusData;

    auto task = [this]() {
        FI_HILOGI("Execute lamdba");
        EmitOnEvent(&this->data_);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        FI_HILOGE("Failed to SendEvent");
    }
}

void DeviceStatusCallback::EmitOnEvent(Data* data)
{
    CHKPV(data);
    DeviceStatusNapi* deviceStatusNapi = DeviceStatusNapi::GetDeviceStatusNapi();
    CHKPV(deviceStatusNapi);
    int32_t type = static_cast<int32_t>(data->type);
    int32_t value = static_cast<int32_t>(data->value);
    FI_HILOGD("type:%{public}d, value:%{public}d", type, value);
    deviceStatusNapi->OnDeviceStatusChangedDone(type, value, false);
}

DeviceStatusNapi* DeviceStatusNapi::GetDeviceStatusNapi()
{
    return g_obj;
}

DeviceStatusNapi::DeviceStatusNapi(napi_env env) : DeviceStatusEvent(env)
{
    env_ = env;
    devicestatusValueRef_ = nullptr;
    DeviceStatusClient::GetInstance().RegisterDeathListener([this] {
        FI_HILOGI("Receive death notification");
        callbacks_.clear();
        ClearEventMap();
    });
}

DeviceStatusNapi::~DeviceStatusNapi()
{
    if (devicestatusValueRef_ != nullptr) {
        napi_delete_reference(env_, devicestatusValueRef_);
    }
}

void DeviceStatusNapi::OnDeviceStatusChangedDone(int32_t type, int32_t value, bool isOnce)
{
    CALL_DEBUG_ENTER;
    FI_HILOGD("value:%{public}d", value);
    OnEvent(type, ARG_1, value, isOnce);
}

int32_t DeviceStatusNapi::ConvertTypeToInt(const std::string &type)
{
    if (type == "absoluteStill") {
        return Type::TYPE_ABSOLUTE_STILL;
    } else if (type == "horizontalPosition") {
        return Type::TYPE_HORIZONTAL_POSITION;
    } else if (type == "verticalPosition") {
        return Type::TYPE_VERTICAL_POSITION;
    } else if (type == "still") {
        return Type::TYPE_STILL;
    } else if (type == "relativeStill") {
        return Type::TYPE_RELATIVE_STILL;
    } else if (type == "carBluetooth") {
        return Type::TYPE_CAR_BLUETOOTH;
    } else {
        return Type::TYPE_INVALID;
    }
}

bool DeviceStatusNapi::CheckArguments(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    int32_t arr[ARG_4] = { 0 };
    size_t argc = ARG_4;
    napi_value args[ARG_4] = { nullptr };
    napi_status status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (status != napi_ok) {
        FI_HILOGE("Failed to get_cb_info");
        return false;
    }
    for (size_t i = 0; i < ARG_4; i++) {
        napi_valuetype valueType = napi_undefined;
        status = napi_typeof(env, args[i], &valueType);
        if (status != napi_ok) {
            FI_HILOGE("Failed to get valueType");
            return false;
        }
        FI_HILOGD("valueType:%{public}d", valueType);
        arr[i] = valueType;
    }
    if (arr[ARG_0] != napi_string || arr[ARG_1] != napi_number || arr[ARG_2] != napi_number ||
        arr[ARG_3] != napi_function) {
        FI_HILOGE("Failed to get arguements");
        return false;
    }
    return true;
}

bool DeviceStatusNapi::IsMatchType(napi_env env, napi_value value, napi_valuetype type)
{
    CALL_DEBUG_ENTER;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, value, &valueType);
    if (status != napi_ok) {
        FI_HILOGE("Failed to get valueType");
        return false;
    }
    return valueType == type;
}

bool DeviceStatusNapi::CheckGetArguments(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    int32_t arr[ARG_2] = { 0 };
    size_t argc = ARG_2;
    napi_value args[ARG_2] = { nullptr };
    napi_status status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (status != napi_ok) {
        FI_HILOGE("Failed to get_cb_info");
        return false;
    }
    for (size_t i = 0; i < ARG_2; i++) {
        napi_valuetype valueType = napi_undefined;
        status = napi_typeof(env, args[i], &valueType);
        if (status != napi_ok) {
            FI_HILOGE("Failed to get valueType");
            return false;
        }
        FI_HILOGD("valueType:%{public}d", valueType);
        arr[i] = valueType;
    }
    if (arr[ARG_0] != napi_string || arr[ARG_1] != napi_function) {
        FI_HILOGE("Failed to get arguements");
        return false;
    }
    return true;
}

std::tuple<bool, napi_value, std::string, int32_t, int32_t> DeviceStatusNapi::CheckSubscribeParam(napi_env env,
    napi_callback_info info)
{
    std::tuple<bool, napi_value, std::string, int32_t, int64_t> result { false, nullptr, "", -1, -1 };
    size_t argc = ARG_4;
    napi_value args[ARG_4] = { nullptr };
    napi_status status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if ((status != napi_ok) || (argc < ARG_4)) {
        ThrowErr(env, PARAM_ERROR, "Bad parameters");
        return result;
    }
    if (!CheckArguments(env, info)) {
        ThrowErr(env, PARAM_ERROR, "Failed to get on arguments");
        return result;
    }
    size_t modLen = 0;
    status = napi_get_value_string_utf8(env, args[ARG_0], nullptr, 0, &modLen);
    if (status != napi_ok) {
        ThrowErr(env, PARAM_ERROR, "Failed to get string item");
        return result;
    }
    if (modLen < 0 || modLen > NAPI_BUF_LENGTH) {
        ThrowErr(env, PARAM_ERROR, "The string length invalid");
        return result;
    }
    char mode[NAPI_BUF_LENGTH] = { 0 };
    status = napi_get_value_string_utf8(env, args[ARG_0], mode, modLen + 1, &modLen);
    if (status != napi_ok) {
        ThrowErr(env, PARAM_ERROR, "Failed to get mode");
        return result;
    }
    int32_t eventMode = 0;
    status = napi_get_value_int32(env, args[ARG_1], &eventMode);
    if (status != napi_ok) {
        ThrowErr(env, PARAM_ERROR, "Failed to get event value item");
        return result;
    }
    int64_t latencyMode = 0;
    status = napi_get_value_int64(env, args[ARG_2], &latencyMode);
    if (status != napi_ok) {
        ThrowErr(env, PARAM_ERROR, "Failed to get latency value item");
        return result;
    }
    latencyMode = latencyMode / NANO;
    return std::make_tuple(true, args[ARG_3], std::string(mode), eventMode, latencyMode);
}

std::tuple<bool, napi_value, int32_t> DeviceStatusNapi::CheckGetParam(napi_env env, napi_callback_info info)
{
    std::tuple<bool, napi_value, int32_t> result { false, nullptr, -1 };
    size_t argc = ARG_2;
    napi_value args[ARG_2] = { nullptr };
    napi_status status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if ((status != napi_ok) || (argc < ARG_2)) {
        ThrowErr(env, PARAM_ERROR, "Bad parameters");
        return result;
    }
    if (!CheckGetArguments(env, info)) {
        ThrowErr(env, PARAM_ERROR, "Failed to get once arguments");
        return result;
    }
    size_t modLen = 0;
    napi_status napiStatus = napi_get_value_string_utf8(env, args[ARG_0], nullptr, 0, &modLen);
    if (napiStatus != napi_ok) {
        ThrowErr(env, PARAM_ERROR, "Failed to get string item");
        return result;
    }
    if (modLen < 0 || modLen > NAPI_BUF_LENGTH) {
        ThrowErr(env, PARAM_ERROR, "The string length invalid");
        return result;
    }
    char mode[NAPI_BUF_LENGTH] = { 0 };
    napiStatus = napi_get_value_string_utf8(env, args[ARG_0], mode, modLen + 1, &modLen);
    if (napiStatus != napi_ok) {
        ThrowErr(env, PARAM_ERROR, "Failed to get mode");
        return result;
    }
    int32_t type = ConvertTypeToInt(mode);
    if ((type != Type::TYPE_STILL) && (type != Type::TYPE_RELATIVE_STILL)) {
        ThrowErr(env, PARAM_ERROR, "Type is illegal");
        return result;
    }
    return std::make_tuple(true, args[ARG_1], type);
}

napi_value DeviceStatusNapi::GetParameters(napi_env env, size_t argc, const napi_value* args)
{
    CALL_DEBUG_ENTER;
    size_t modLen = 0;
    napi_status status = napi_get_value_string_utf8(env, args[0], nullptr, 0, &modLen);
    if (status != napi_ok) {
        ThrowErr(env, PARAM_ERROR, "Failed to get string item");
        return nullptr;
    }
    if (modLen < 0 || modLen > NAPI_BUF_LENGTH) {
        ThrowErr(env, PARAM_ERROR, "The string length invalid");
        return nullptr;
    }
    char mode[NAPI_BUF_LENGTH] = { 0 };
    status = napi_get_value_string_utf8(env, args[0], mode, modLen + 1, &modLen);
    if (status != napi_ok) {
        ThrowErr(env, PARAM_ERROR, "Failed to get mode");
        return nullptr;
    }
    int32_t type = DeviceStatusNapi::ConvertTypeToInt(mode);
    if ((type != Type::TYPE_STILL) && (type != Type::TYPE_RELATIVE_STILL)) {
        ThrowErr(env, PARAM_ERROR, "Type is illegal");
        return nullptr;
    }
    int32_t event = 0;
    status = napi_get_value_int32(env, args[1], &event);
    if (status != napi_ok) {
        ThrowErr(env, PARAM_ERROR, "Failed to get int32 item");
        return nullptr;
    }
    if ((event < ActivityEvent::ENTER) || (event > ActivityEvent::ENTER_EXIT)) {
        ThrowErr(env, PARAM_ERROR, "Event is illegal");
        return nullptr;
    }
    CHKPP(g_obj);
    if ((argc < 3) || IsMatchType(env, args[2], napi_undefined) || IsMatchType(env, args[2], napi_null)) {
        if (!g_obj->RemoveAllCallback(type)) {
            FI_HILOGE("Callback type is not exist");
            return nullptr;
        }
        UnsubscribeCallback(env, type, event);
        return nullptr;
    }
    FI_HILOGD("type:%{public}d, event:%{public}d", type, event);
    if (!IsMatchType(env, args[2], napi_function)) {
        ThrowErr(env, PARAM_ERROR, "get error callback type");
        return nullptr;
    }
    if (!g_obj->Off(type, args[2])) {
        FI_HILOGE("Not ready to unsubscribe for type:%{public}d", type);
        return nullptr;
    }
    UnsubscribeCallback(env, type, event);
    return nullptr;
}

napi_value DeviceStatusNapi::SubscribeDeviceStatusCallback(napi_env env, napi_callback_info info, napi_value handler,
    int32_t type, int32_t event, int32_t latency)
{
    CALL_DEBUG_ENTER;
    if (g_obj == nullptr) {
        g_obj = new (std::nothrow) DeviceStatusNapi(env);
        CHKPP(g_obj);
        FI_HILOGD("Didn't find object, so created it");
    }
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, &data);
    if (status != napi_ok) {
        FI_HILOGE("Failed to get_cb_info item");
        delete g_obj;
        g_obj = nullptr;
        return nullptr;
    }
    status = napi_wrap(env, thisArg, reinterpret_cast<void *>(g_obj),
        [](napi_env env, void *data, void *hint) {
            (void)env;
            (void)hint;
            CHKPV(data);
            DeviceStatusNapi *devicestatus = static_cast<DeviceStatusNapi *>(data);
            delete devicestatus;
            g_obj = nullptr;
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        FI_HILOGE("napi_wrap failed");
        delete g_obj;
        g_obj = nullptr;
        return nullptr;
    }
    if (!g_obj->On(type, handler, false)) {
        FI_HILOGE("type:%{public}d already exists", type);
        return nullptr;
    }
    std::lock_guard<std::mutex> guard(g_obj->mutex_);
    auto callbackIter = callbacks_.find(type);
    if (callbackIter != callbacks_.end()) {
        FI_HILOGD("Callback exists");
        return nullptr;
    }
    sptr<IRemoteDevStaCallback> callback = new (std::nothrow) DeviceStatusCallback(env);
    CHKPP(callback);
    int32_t subscribeRet = StationaryManager::GetInstance().SubscribeCallback(static_cast<Type>(type),
        static_cast<ActivityEvent>(event), static_cast<ReportLatencyNs>(latency), callback);
    if (subscribeRet != RET_OK) {
        ThrowErr(env, SERVICE_EXCEPTION, "On:Failed to SubscribeCallback");
        return nullptr;
    }
    auto ret = callbacks_.insert(std::pair<int32_t, sptr<IRemoteDevStaCallback>>(type, callback));
    if (!ret.second) {
        FI_HILOGE("Failed to insert");
    }
    return nullptr;
}

napi_value DeviceStatusNapi::SubscribeDeviceStatus(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    const auto [ret, handler, typeMode, event, latency] = CheckSubscribeParam(env, info);
    if (!ret) {
        FI_HILOGE("On:Failed to SubscribeDeviceStatus");
        return nullptr;
    }
    int32_t type = ConvertTypeToInt(typeMode);
    FI_HILOGD("type:%{public}d, event:%{public}d, latency:%{public}d", type, event, latency);
    if ((type != Type::TYPE_STILL) && (type != Type::TYPE_RELATIVE_STILL)) {
        ThrowErr(env, PARAM_ERROR, "Type is illegal");
        return nullptr;
    }
    if ((event < ActivityEvent::ENTER) || (event > ActivityEvent::ENTER_EXIT)) {
        ThrowErr(env, PARAM_ERROR, "Event is illegal");
        return nullptr;
    }
    if ((latency < ReportLatencyNs::SHORT) || (latency > ReportLatencyNs::LONG)) {
        ThrowErr(env, PARAM_ERROR, "Latency is illegal");
        return nullptr;
    }
    return SubscribeDeviceStatusCallback(env, info, handler, type, event, latency);
}

napi_value DeviceStatusNapi::UnsubscribeDeviceStatus(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 3;
    napi_value args[3] = { nullptr };
    napi_status status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (status != napi_ok) {
        ThrowErr(env, PARAM_ERROR, "Bad parameters");
        return nullptr;
    }
    if (argc < 2) {
        ThrowErr(env, PARAM_ERROR, "Param number is invalid");
        return nullptr;
    }
    return GetParameters(env, argc, args);
}

napi_value DeviceStatusNapi::UnsubscribeCallback(napi_env env, int32_t type, int32_t event)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(g_obj->mutex_);
    auto callbackIter = callbacks_.find(type);
    if (callbackIter == callbacks_.end()) {
        NAPI_ASSERT(env, false, "No existed callback");
        return nullptr;
    }
    int32_t unsubscribeRet = StationaryManager::GetInstance().UnsubscribeCallback(static_cast<Type>(type),
        static_cast<ActivityEvent>(event), callbackIter->second);
    if (unsubscribeRet != RET_OK) {
        ThrowErr(env, SERVICE_EXCEPTION, "Off:Failed to UnsubscribeCallback");
    }
    callbacks_.erase(type);
    return nullptr;
}

napi_value DeviceStatusNapi::GetDeviceStatus(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    const auto [ret, handler, type] = CheckGetParam(env, info);
    if (!ret) {
        FI_HILOGE("Once:Failed to GetDeviceStatus");
        return nullptr;
    }
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, &data);
    if (status != napi_ok) {
        FI_HILOGE("Failed to get_cb_info item");
        delete g_obj;
        g_obj = nullptr;
        return nullptr;
    }
    if (g_obj == nullptr) {
        g_obj = new (std::nothrow) DeviceStatusNapi(env);
        CHKPP(g_obj);
        status = napi_wrap(env, thisArg, reinterpret_cast<void *>(g_obj),
            [](napi_env env, void *data, void *hint) {
                (void)env;
                (void)hint;
                CHKPV(data);
                DeviceStatusNapi *devicestatus = static_cast<DeviceStatusNapi *>(data);
                delete devicestatus;
                g_obj = nullptr;
            },
            nullptr, nullptr);
        if (status != napi_ok) {
            FI_HILOGE("napi_wrap failed");
            delete g_obj;
            g_obj = nullptr;
            return nullptr;
        }
    }
    if (!g_obj->On(type, handler, true)) {
        FI_HILOGE("type:%{public}d already exists", type);
        return nullptr;
    }
    Data devicestatusData = StationaryManager::GetInstance().GetDeviceStatusData(static_cast<Type>(type));
    if (devicestatusData.type == Type::TYPE_INVALID) {
        ThrowErr(env, SERVICE_EXCEPTION, "Once:Failed to get device status data");
    }
    g_obj->OnDeviceStatusChangedDone(devicestatusData.type, devicestatusData.value, true);
    g_obj->OffOnce(devicestatusData.type, handler);
    return nullptr;
}

napi_value DeviceStatusNapi::EnumActivityEventConstructor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, &data);
    if (status != napi_ok) {
        FI_HILOGE("Failed to get_cb_info item");
        return nullptr;
    }
    napi_value global = nullptr;
    status = napi_get_global(env, &global);
    if (status != napi_ok) {
        FI_HILOGE("Failed to get_global item");
        return nullptr;
    }
    return thisArg;
}

napi_value DeviceStatusNapi::DeclareEventTypeInterface(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_value enter = nullptr;
    napi_status status = napi_create_int32(env, static_cast<int32_t>(ActivityEvent::ENTER), &enter);
    if (status != napi_ok) {
        FI_HILOGE("Failed to create ENTER item");
        return nullptr;
    }
    napi_value exit = nullptr;
    status = napi_create_int32(env, static_cast<int32_t>(ActivityEvent::EXIT), &exit);
    if (status != napi_ok) {
        FI_HILOGE("Failed to create EXIT item");
        return nullptr;
    }
    napi_value enter_exit = nullptr;
    status = napi_create_int32(env, static_cast<int32_t>(ActivityEvent::ENTER_EXIT), &enter_exit);
    if (status != napi_ok) {
        FI_HILOGE("Failed to create ENTER_EXIT item");
        return nullptr;
    }
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("ENTER", enter),
        DECLARE_NAPI_STATIC_PROPERTY("EXIT", exit),
        DECLARE_NAPI_STATIC_PROPERTY("ENTER_EXIT", enter_exit)
    };
    napi_value result = nullptr;
    status = napi_define_class(env, "ActivityEvent", NAPI_AUTO_LENGTH,
        EnumActivityEventConstructor, nullptr, sizeof(desc) / sizeof(*desc), desc, &result);
    if (status != napi_ok) {
        FI_HILOGE("Failed to define_class item");
        return nullptr;
    }
    status = napi_set_named_property(env, exports, "ActivityEvent", result);
    if (status != napi_ok) {
        FI_HILOGE("Failed to set_named_property item");
        return nullptr;
    }
    return exports;
}

napi_value DeviceStatusNapi::Init(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("on", SubscribeDeviceStatus),
        DECLARE_NAPI_FUNCTION("off", UnsubscribeDeviceStatus),
        DECLARE_NAPI_FUNCTION("once", GetDeviceStatus)
    };
    DeclareEventTypeInterface(env, exports);
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

EXTERN_C_START
/*
 * function for module exports
 */
static napi_value DeviceStatusInit(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_value ret = DeviceStatusNapi::Init(env, exports);
    return ret;
}
EXTERN_C_END

/*
 * Module definition
 */
static napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = "stationary",
    .nm_register_func = DeviceStatusInit,
    .nm_modname = "stationary",
    .nm_priv = (static_cast<void *>(0)),
    .reserved = {0}
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
