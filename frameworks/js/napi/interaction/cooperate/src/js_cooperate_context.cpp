/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

#include "js_cooperate_context.h"

#include "devicestatus_define.h"
#include "napi_constants.h"
#include "util_napi_error.h"

#undef LOG_TAG
#define LOG_TAG "JsCooperateContext"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr const char* COORDINATION_CLASS { "Coordination_class" };
const char* COORDINATION { "Coordination" };
constexpr std::string_view GET_VALUE_BOOL { "napi_get_value_bool" };
constexpr std::string_view GET_VALUE_INT32 { "napi_get_value_int32" };
constexpr std::string_view GET_VALUE_STRING_UTF8 { "napi_get_value_string_utf8" };
constexpr size_t MAX_STRING_LEN { 1024 };
} // namespace

JsCooperateContext::JsCooperateContext()
    : mgr_(std::make_shared<JsCooperateManager>()) {}

JsCooperateContext::~JsCooperateContext()
{
    std::lock_guard<std::mutex> guard(mutex_);
    auto jsCooperateManager = mgr_;
    mgr_.reset();
    if (jsCooperateManager != nullptr) {
        jsCooperateManager->ResetEnv();
    }
}

napi_value JsCooperateContext::Export(napi_env env, napi_value exports)
{
    CALL_INFO_TRACE;
    auto instance = CreateInstance(env);
    CHKPP(instance);
    DeclareDeviceCoordinationInterface(env, exports);
    DeclareDeviceCoordinationData(env, exports);
    return exports;
}

napi_value JsCooperateContext::Enable(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    size_t argc = TWO_PARAM;
    napi_value argv[TWO_PARAM] = { nullptr };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);

    if (argc == ZERO_PARAM) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Wrong number of parameters");
        return nullptr;
    }
    if (!UtilNapi::TypeOf(env, argv[ZERO_PARAM], napi_boolean)) {
        THROWERR(env, COMMON_PARAMETER_ERROR, "enable", "boolean");
        return nullptr;
    }
    bool enable = false;
    CHKRP(napi_get_value_bool(env, argv[ZERO_PARAM], &enable), GET_VALUE_BOOL);

    JsCooperateContext *jsDev = JsCooperateContext::GetInstance(env);
    CHKPP(jsDev);
    auto jsCooperateManager = jsDev->GetJsCoordinationMgr();
    CHKPP(jsCooperateManager);
    if (argc == ONE_PARAM) {
        return jsCooperateManager->Enable(env, enable);
    }
    if (!UtilNapi::TypeOf(env, argv[ONE_PARAM], napi_function)) {
        THROWERR(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsCooperateManager->Enable(env, enable, argv[ONE_PARAM]);
}

napi_value JsCooperateContext::Start(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    size_t argc = THREE_PARAM;
    napi_value argv[THREE_PARAM] = { nullptr };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);

    if (argc < TWO_PARAM) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Wrong number of parameters");
        return nullptr;
    }
    if (!UtilNapi::TypeOf(env, argv[ZERO_PARAM], napi_string)) {
        THROWERR(env, COMMON_PARAMETER_ERROR, "remoteNetworkDescriptor", "string");
        return nullptr;
    }
    if (!UtilNapi::TypeOf(env, argv[ONE_PARAM], napi_number)) {
        THROWERR(env, COMMON_PARAMETER_ERROR, "startDeviceId", "number");
        return nullptr;
    }
    char remoteNetworkDescriptor[MAX_STRING_LEN] = { 0 };
    int32_t startDeviceId = ZERO_PARAM;
    size_t length = ZERO_PARAM;
    CHKRP(napi_get_value_string_utf8(env, argv[ZERO_PARAM], remoteNetworkDescriptor,
        sizeof(remoteNetworkDescriptor), &length), GET_VALUE_STRING_UTF8);
    if (length >= MAX_STRING_LEN) {
        FI_HILOGE("remoteNetworkDescriptor length: %{public}zu, max len: %{public}zu",
            length, MAX_STRING_LEN);
    }
    CHKRP(napi_get_value_int32(env, argv[ONE_PARAM], &startDeviceId), GET_VALUE_INT32);

    JsCooperateContext *jsDev = JsCooperateContext::GetInstance(env);
    CHKPP(jsDev);
    auto jsCooperateManager = jsDev->GetJsCoordinationMgr();
    CHKPP(jsCooperateManager);
    if (argc == TWO_PARAM) {
        return jsCooperateManager->Start(env, remoteNetworkDescriptor, startDeviceId);
    }
    if (!UtilNapi::TypeOf(env, argv[TWO_PARAM], napi_function)) {
        THROWERR(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsCooperateManager->Start(env, std::string(remoteNetworkDescriptor), startDeviceId, argv[TWO_PARAM]);
}

napi_value JsCooperateContext::Stop(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    size_t argc = ONE_PARAM;
    napi_value argv[ONE_PARAM] = { nullptr };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);

    JsCooperateContext *jsDev = JsCooperateContext::GetInstance(env);
    CHKPP(jsDev);
    auto jsCooperateManager = jsDev->GetJsCoordinationMgr();
    CHKPP(jsCooperateManager);
    if (argc == ZERO_PARAM) {
        return jsCooperateManager->Stop(env);
    }
    if (!UtilNapi::TypeOf(env, argv[ZERO_PARAM], napi_function)) {
        THROWERR(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsCooperateManager->Stop(env, argv[ZERO_PARAM]);
}

napi_value JsCooperateContext::GetState(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    size_t argc = TWO_PARAM;
    napi_value argv[TWO_PARAM] = { nullptr };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);

    if (argc == ZERO_PARAM) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Incorrect parameter count");
        return nullptr;
    }
    if (!UtilNapi::TypeOf(env, argv[ZERO_PARAM], napi_string)) {
        THROWERR(env, COMMON_PARAMETER_ERROR, "deviceDescriptor", "string");
        return nullptr;
    }
    char deviceDescriptor[MAX_STRING_LEN] = { ZERO_PARAM };
    size_t length = ZERO_PARAM;
    CHKRP(napi_get_value_string_utf8(env, argv[ZERO_PARAM], deviceDescriptor,
        sizeof(deviceDescriptor), &length), GET_VALUE_STRING_UTF8);
    std::string deviceDescriptorTmp = deviceDescriptor;

    JsCooperateContext *jsDev = JsCooperateContext::GetInstance(env);
    CHKPP(jsDev);
    auto jsCooperateManager = jsDev->GetJsCoordinationMgr();
    CHKPP(jsCooperateManager);
    if (argc == ONE_PARAM) {
        return jsCooperateManager->GetState(env, deviceDescriptorTmp);
    }
    if (!UtilNapi::TypeOf(env, argv[ONE_PARAM], napi_function)) {
        THROWERR(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsCooperateManager->GetState(env, deviceDescriptorTmp, argv[ONE_PARAM]);
}

napi_value JsCooperateContext::On(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    napi_value argv[TWO_PARAM] = { nullptr };
    size_t argc = TWO_PARAM;
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc == ZERO_PARAM) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Mismatched parameter count");
        return nullptr;
    }

    if (!UtilNapi::TypeOf(env, argv[ZERO_PARAM], napi_string)) {
        THROWERR(env, COMMON_PARAMETER_ERROR, "type", "string");
        return nullptr;
    }
    char type[MAX_STRING_LEN] = { 0 };
    size_t length = ZERO_PARAM;
    CHKRP(napi_get_value_string_utf8(env, argv[ZERO_PARAM], type, sizeof(type), &length), GET_VALUE_STRING_UTF8);
    if (std::strcmp(type, "cooperation") != ZERO_PARAM) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Type must be cooperation");
        return nullptr;
    }
    JsCooperateContext *jsDev = JsCooperateContext::GetInstance(env);
    CHKPP(jsDev);
    auto jsCooperateManager = jsDev->GetJsCoordinationMgr();
    CHKPP(jsCooperateManager);
    if (!UtilNapi::TypeOf(env, argv[ONE_PARAM], napi_function)) {
        THROWERR(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    jsCooperateManager->RegisterListener(env, type, argv[ONE_PARAM]);
    return nullptr;
}

napi_value JsCooperateContext::Off(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    size_t argc = TWO_PARAM;
    napi_value argv[TWO_PARAM] = { nullptr };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);

    if (argc == ZERO_PARAM) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Wrong number of parameters");
        return nullptr;
    }
    if (!UtilNapi::TypeOf(env, argv[ZERO_PARAM], napi_string)) {
        THROWERR(env, COMMON_PARAMETER_ERROR, "type", "string");
        return nullptr;
    }
    char type[MAX_STRING_LEN] = { 0 };
    size_t length = ZERO_PARAM;
    CHKRP(napi_get_value_string_utf8(env, argv[ZERO_PARAM], type, sizeof(type), &length), GET_VALUE_STRING_UTF8);
    std::string typeTmp = type;

    JsCooperateContext *jsDev = JsCooperateContext::GetInstance(env);
    CHKPP(jsDev);
    auto jsCooperateManager = jsDev->GetJsCoordinationMgr();
    CHKPP(jsCooperateManager);
    if (argc == ONE_PARAM) {
        jsCooperateManager->UnregisterListener(env, typeTmp);
        return nullptr;
    }
    if (!UtilNapi::TypeOf(env, argv[ONE_PARAM], napi_function)) {
        THROWERR(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    jsCooperateManager->UnregisterListener(env, typeTmp, argv[ONE_PARAM]);
    return nullptr;
}

std::shared_ptr<JsCooperateManager> JsCooperateContext::GetJsCoordinationMgr()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return mgr_;
}

napi_value JsCooperateContext::CreateInstance(napi_env env)
{
    CALL_INFO_TRACE;
    napi_value global = nullptr;
    CHKRP(napi_get_global(env, &global), GET_GLOBAL);

    constexpr char className[] = "JsCooperateContext";
    napi_value jsClass = nullptr;
    napi_property_descriptor desc[] = {};
    napi_status status = napi_define_class(env, className, sizeof(className),
        JsCooperateContext::JsConstructor, nullptr, sizeof(desc) / sizeof(desc[ZERO_PARAM]), nullptr, &jsClass);
    CHKRP(status, DEFINE_CLASS);

    status = napi_set_named_property(env, global, COORDINATION_CLASS, jsClass);
    CHKRP(status, SET_NAMED_PROPERTY);

    napi_value jsInstance = nullptr;
    CHKRP(napi_new_instance(env, jsClass, ZERO_PARAM, nullptr, &jsInstance), NEW_INSTANCE);
    CHKRP(napi_set_named_property(env, global, COORDINATION, jsInstance),
        SET_NAMED_PROPERTY);

    JsCooperateContext *jsContext = nullptr;
    CHKRP(napi_unwrap(env, jsInstance, reinterpret_cast<void**>(&jsContext)), UNWRAP);
    CHKPP(jsContext);
    CHKRP(napi_create_reference(env, jsInstance, ONE_PARAM, &(jsContext->contextRef_)), CREATE_REFERENCE);

    uint32_t refCount = ZERO_PARAM;
    status = napi_reference_ref(env, jsContext->contextRef_, &refCount);
    if (status != napi_ok) {
        FI_HILOGE("ref is nullptr");
        napi_delete_reference(env, jsContext->contextRef_);
        return nullptr;
    }
    return jsInstance;
}

napi_value JsCooperateContext::JsConstructor(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    napi_value thisVar = nullptr;
    void *data = nullptr;
    CHKRP(napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data), GET_CB_INFO);

    JsCooperateContext *jsContext = new (std::nothrow) JsCooperateContext();
    CHKPP(jsContext);
    napi_status status = napi_wrap(env, thisVar, jsContext, [](napi_env env, void *data, void *hin) {
        FI_HILOGI("Jsvm ends");
        JsCooperateContext *context = static_cast<JsCooperateContext*>(data);
        delete context;
    }, nullptr, nullptr);
    if (status != napi_ok) {
        FI_HILOGE("%{public}s failed", std::string(WRAP).c_str());
        delete jsContext;
        auto infoTemp = std::string(__FUNCTION__) + ": " + std::string(WRAP) + " failed";
        napi_throw_error(env, nullptr, infoTemp.c_str());
        return nullptr;
    }
    return thisVar;
}

JsCooperateContext *JsCooperateContext::GetInstance(napi_env env)
{
    CALL_INFO_TRACE;
    napi_value global = nullptr;
    CHKRP(napi_get_global(env, &global), GET_GLOBAL);

    bool result = false;
    CHKRP(napi_has_named_property(env, global, COORDINATION, &result), HAS_NAMED_PROPERTY);
    if (!result) {
        FI_HILOGE("Coordination was not found");
        return nullptr;
    }

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    CHKPP(scope);
    napi_value object = nullptr;
    CHKRP_SCOPE(env, napi_get_named_property(env, global, COORDINATION, &object), GET_NAMED_PROPERTY, scope);
    if (object == nullptr) {
        napi_close_handle_scope(env, scope);
        FI_HILOGE("object is nullptr");
        return nullptr;
    }

    JsCooperateContext *instance = nullptr;
    CHKRP_SCOPE(env, napi_unwrap(env, object, reinterpret_cast<void**>(&instance)), UNWRAP, scope);
    if (instance == nullptr) {
        napi_close_handle_scope(env, scope);
        FI_HILOGE("instance is nullptr");
        return nullptr;
    }
    napi_close_handle_scope(env, scope);
    return instance;
}

void JsCooperateContext::DeclareDeviceCoordinationInterface(napi_env env, napi_value exports)
{
    napi_value infoStart = nullptr;
    CHKRV(napi_create_int32(env,
        static_cast<int32_t>(JsEventCooperateTarget::CooperateMessage::INFO_START), &infoStart), CREATE_INT32);
    napi_value infoSuccess = nullptr;
    CHKRV(napi_create_int32(env,
        static_cast<int32_t>(JsEventCooperateTarget::CooperateMessage::INFO_SUCCESS), &infoSuccess), CREATE_INT32);
    napi_value infoFail = nullptr;
    CHKRV(napi_create_int32(env, static_cast<int32_t>(JsEventCooperateTarget::CooperateMessage::INFO_FAIL), &infoFail),
        CREATE_INT32);
    napi_value stateOn = nullptr;
    CHKRV(napi_create_int32(env, static_cast<int32_t>(JsEventCooperateTarget::CooperateMessage::STATE_ON), &stateOn),
        CREATE_INT32);
    napi_value stateOff = nullptr;
    CHKRV(napi_create_int32(env, static_cast<int32_t>(JsEventCooperateTarget::CooperateMessage::STATE_OFF), &stateOff),
        CREATE_INT32);

    napi_property_descriptor msg[] = {
        DECLARE_NAPI_STATIC_PROPERTY("MSG_COOPERATE_INFO_START", infoStart),
        DECLARE_NAPI_STATIC_PROPERTY("MSG_COOPERATE_INFO_SUCCESS", infoSuccess),
        DECLARE_NAPI_STATIC_PROPERTY("MSG_COOPERATE_INFO_FAIL", infoFail),
        DECLARE_NAPI_STATIC_PROPERTY("MSG_COOPERATE_STATE_ON", stateOn),
        DECLARE_NAPI_STATIC_PROPERTY("MSG_COOPERATE_STATE_OFF", stateOff)
    };

    napi_value eventMsg = nullptr;
    CHKRV(napi_define_class(env, "EventMsg", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(msg) / sizeof(*msg), msg, &eventMsg), DEFINE_CLASS);
    CHKRV(napi_set_named_property(env, exports, "EventMsg", eventMsg), SET_NAMED_PROPERTY);
}

void JsCooperateContext::DeclareDeviceCoordinationData(napi_env env, napi_value exports)
{
    napi_property_descriptor functions[] = {
        DECLARE_NAPI_STATIC_FUNCTION("enable", Enable),
        DECLARE_NAPI_STATIC_FUNCTION("start", Start),
        DECLARE_NAPI_STATIC_FUNCTION("stop", Stop),
        DECLARE_NAPI_STATIC_FUNCTION("getState", GetState),
        DECLARE_NAPI_STATIC_FUNCTION("on", On),
        DECLARE_NAPI_STATIC_FUNCTION("off", Off)
    };
    CHKRV(napi_define_properties(env, exports,
        sizeof(functions) / sizeof(*functions), functions), DEFINE_PROPERTIES);
}

napi_value JsCooperateContext::EnumClassConstructor(napi_env env, napi_callback_info info)
{
    size_t argc = ZERO_PARAM;
    napi_value args[ONE_PARAM] = { nullptr };
    napi_value result = nullptr;
    void *data = nullptr;
    CHKRP(napi_get_cb_info(env, info, &argc, args, &result, &data), GET_CB_INFO);
    return result;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
