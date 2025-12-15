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

#include "on_screen_napi.h"

#include <mutex>

#include "devicestatus_define.h"
#include "fi_log.h"
#include "image_pixel_map_napi.h"
#include "napi_constants.h"
#include "on_screen_manager.h"
#include "on_screen_napi_error.h"
#include "pixel_map_napi.h"
#include "util_napi.h"

#undef LOG_TAG
#define LOG_TAG "OnScreenNapi"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
namespace {
constexpr uint8_t ARG_0 = 0;
constexpr uint8_t ARG_1 = 1;
constexpr uint8_t ARG_2 = 2;
constexpr uint8_t ARG_3 = 3;
constexpr int32_t DEFAULT_WINDOW_ID = -1;
OnScreenNapi *g_onScreenObj = nullptr;
std::mutex g_mtx;
constexpr size_t MAX_ARG_STR_LEN = 64;
std::unordered_map<std::string, napi_ref>  g_screenCallbacks;
sptr<OnScreenAwarenessCallback> g_callback = nullptr;
const std::set<std::string> CAP_LIST = {
    "contentUiTree",
    "contentUiOcr",
    "contentScreenshot",
    "contentLink",
    "contentUiTreeWithImage",
    "interactionTextSelection",
    "interactionClick",
    "interactionScroll",
    "scenarioReading",
    "scenarioShortVideo",
    "scenarioActivity",
    "scenarioTodo",
};
} // namespace

OnScreenNapi::OnScreenNapi(napi_env env, napi_value thisVar)
{
    env_ = env;
}

OnScreenNapi::~OnScreenNapi() {}

napi_value OnScreenNapi::Init(napi_env env, napi_value exports)
{
    FI_HILOGD("Enter");
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("sendControlEvent", SendControlEventNapi),
        DECLARE_NAPI_STATIC_FUNCTION("getPageContent", GetPageContentNapi),

        DECLARE_NAPI_STATIC_FUNCTION("subscribe", RegisterAwarenessCallback),
        DECLARE_NAPI_STATIC_FUNCTION("unsubscribe", UnregisterAwarenessCallback),
        DECLARE_NAPI_STATIC_FUNCTION("trigger", Trigger),
    };
    MSDP_CALL(napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    // 声明枚举值Scenario
    napi_value napiScenario;
    napi_status status = napi_create_object(env, &napiScenario);
    if (status != napi_ok) {
        FI_HILOGE("Failed create object");
        return nullptr;
    }
    bool ret = SetInt32Property(env, napiScenario, static_cast<int32_t>(Scenario::UNKNOWN), "UNKNOWN");
    ret = ret && SetInt32Property(env, napiScenario, static_cast<int32_t>(Scenario::ARTICLE), "ARTICLE");
    ret = ret && SetPropertyName(env, exports, "Scenario", napiScenario);
    if (!ret) {
        FI_HILOGE("Failed set enum scenario");
        return nullptr;
    }
    // 声明枚举值EventType
    napi_value napiEventType;
    status = napi_create_object(env, &napiEventType);
    if (status != napi_ok) {
        FI_HILOGE("Failed create object");
        return nullptr;
    }
    ret = SetInt32Property(env, napiEventType, static_cast<int32_t>(EventType::SCROLL_TO_HOOK), "SCROLL_TO_HOOK");
    ret = ret && SetPropertyName(env, exports, "EventType", napiEventType);
    if (!ret) {
        FI_HILOGE("Failed set enum eventtype");
        return nullptr;
    }
    FI_HILOGD("Exit");
    return exports;
}

bool OnScreenNapi::IsValidCap(const std::vector<std::string>& capList)
{
    bool ret = true;
    for (auto cap : capList) {
        ret = ret && CAP_LIST.find(cap) != CAP_LIST.end();
    }
    return ret;
}

bool OnScreenNapi::CheckCapList(const std::vector<std::string>& capList)
{
    bool ret = true;
    for (auto cap : capList) {
        ret = ret && g_screenCallbacks.find(cap) == g_screenCallbacks.end();
    }
    return ret;
}

bool OnScreenNapi::IsMatchType(napi_env env, napi_value value, napi_valuetype type)
{
    napi_valuetype paramType = napi_undefined;
    napi_status ret = napi_typeof(env, value, &paramType);
    if ((ret != napi_ok) || (paramType != type)) {
        FI_HILOGE("Type mismatch");
        return false;
    }
    return true;
}

bool OnScreenNapi::TransJsToStr(napi_env env, napi_value in, std::string &out)
{
    FI_HILOGD("Enter");
    napi_valuetype type = napi_undefined;
    if (napi_typeof(env, in, &type) != napi_ok || type != napi_string) {
        FI_HILOGE("input is not a string");
        return false;
    }
    size_t strLen = 0;
    napi_status status = napi_get_value_string_utf8(env, in, nullptr, 0, &strLen);
    if (status != napi_ok) {
        FI_HILOGE("Error string length invalid");
        return false;
    }
    if (strLen > MAX_ARG_STR_LEN) {
        FI_HILOGE("The string length invalid");
        return false;
    }
    std::vector<char> buf(strLen + 1);
    status = napi_get_value_string_utf8(env, in, buf.data(), strLen+1, &strLen);
    if (status != napi_ok) {
        FI_HILOGE("napi_get_value_string_utf8 failed");
        return false;
    }
    out = buf.data();
    return true;
}

bool OnScreenNapi::GetStringFromJs(napi_env env, const napi_value &value, const std::string &field,
    std::string &result)
{
    bool hasProperty = false;
    CHKCF(napi_has_named_property(env, value, field.c_str(), &hasProperty) == napi_ok && hasProperty,
        "napi_has_named_property failed");
    napi_value fieldValue = nullptr;
    CHKCF((napi_get_named_property(env, value, field.c_str(), &fieldValue) == napi_ok),
        "napi_get_named_property failed");
    return TransJsToStr(env, fieldValue, result);
}

bool OnScreenNapi::GetAwarenessCap(napi_env env, napi_value awarenessCap, size_t argc, AwarenessCap &cap)
{
    CHKCF(argc >= 1, "param is invalid");
    CHKCF(IsMatchType(env, awarenessCap, napi_object), "arg type mismatch");
    bool exist = false;
    CHKCF(napi_has_named_property(env, awarenessCap, "capList", &exist) == napi_ok && exist, "cap list not exist");
    napi_value capList = nullptr;
    CHKCF((napi_get_named_property(env, awarenessCap, "capList", &capList) == napi_ok), "napi get cap list fail");
    napi_valuetype valuetype = napi_undefined;
    CHKCF(napi_typeof(env, capList, &valuetype) == napi_ok, "valunapi_typeofetype fail");
    napi_value valueList;
    CHKCF(napi_get_property_names(env, capList, &valueList) == napi_ok, "get property names fail");
    uint32_t valueCount;
    napi_value elementName = nullptr;
    napi_value elementValue = nullptr;
    CHKCF(napi_get_array_length(env, valueList, &valueCount) == napi_ok, "napi_get_array_length fail");
    for (uint32_t index = 0; index < valueCount - 1; index++) {
        CHKCF(napi_get_element(env, valueList, index, &elementName) == napi_ok, "napi_get_element fail");
        std::string strName;
        std::string strValue;
        CHKCF(TransJsToStr(env, elementName, strName), "TransJsToStr name fail");
        CHKCF(napi_get_named_property(env, capList, strName.c_str(), &elementValue) == napi_ok,
            "napi_get_named_property fail");
        CHKCF(TransJsToStr(env, elementValue, strValue), "TransJsToStr value fail");
        cap.capList.push_back(strValue);
    }
    CHKCF(napi_has_named_property(env, awarenessCap, "description", &exist) == napi_ok,
        "napi_has_named_property failed");
    if (exist) {
        GetStringFromJs(env, awarenessCap, "description", cap.description);
    }
    return true;
}

bool OnScreenNapi::HandleOptionBool(napi_env env, std::string strName, napi_value boolValue, AwarenessOptions &option)
{
    bool result;
    CHKCF((napi_get_value_bool(env, boolValue, &result) == napi_ok), "napi value bool fail");
    option.entityInfo[strName] = result;
    return true;
}

bool OnScreenNapi::HandleOptionInt32(napi_env env, std::string strName, napi_value int32Value,
    AwarenessOptions &option)
{
    int32_t result;
    CHKCF((napi_get_value_int32(env, int32Value, &result) == napi_ok), "napi value int fail");
    option.entityInfo[strName] = result;
    return true;
}

bool OnScreenNapi::HandleOptionInt64(napi_env env, std::string strName, napi_value int64Value,
    AwarenessOptions &option)
{
    int64_t result;
    CHKCF((napi_get_value_int64(env, int64Value, &result) == napi_ok), "napi value int fail");
    option.entityInfo[strName] = result;
    return true;
}

bool OnScreenNapi::HandleOptionString(napi_env env, std::string strName, napi_value strValue,
    AwarenessOptions &option)
{
    std::string result;
    CHKCF((TransJsToStr(env, strValue, result) == napi_ok), "napi value int fail");
    option.entityInfo[strName] = result;
    return true;
}

bool OnScreenNapi::HandleOptionObject(napi_env env, std::string strName, napi_value objValue,
    AwarenessOptions &option)
{
    std::string httpLink;
    std::string deepLink;
    if (GetStringFromJs(env, objValue, "httpLink", httpLink) == napi_ok && GetStringFromJs(env, objValue, "deepLink",
        deepLink) == napi_ok) {
        AwarenessInfoPageLink result = { httpLink, deepLink};
        option.entityInfo[strName] = result;
    } else {
        std::shared_ptr<Media::PixelMap> result = Media::PixelMapNapi::GetPixelMap(env, objValue);
        option.entityInfo[strName] = result;
    }
    return true;
}

bool OnScreenNapi::HandleOptionArray(napi_env env, std::string strName, napi_value arrayValue,
    AwarenessOptions &option)
{
    uint32_t length = 0;
    CHKCF((napi_get_array_length(env, arrayValue, &length) == napi_ok), "napi_get_array_length fail");
    std::vector<std::string> strArr;
    std::vector<AwarenessInfoImageId> infoArr;
    for (size_t i = 0; i < length; ++i) {
        napi_value element = nullptr;
        AwarenessInfoImageId imageId;
        CHKCF((napi_get_element(env, arrayValue, i, &element) == napi_ok), "napi_get_element fail");
        napi_valuetype valuetype = napi_undefined;
        CHKCF(napi_typeof(env, element, &valuetype) == napi_ok, "napi_typeof failed");
        if (valuetype == napi_string) {
            std::string strResult;
            CHKCF(TransJsToStr(env, element, strResult), "TransJsToStr fail");
            strArr.push_back(strResult);
        } else if (valuetype == napi_object && GetStringFromJs(env, element, "compId", imageId.compId) == napi_ok &&
            GetStringFromJs(env, element, "arkDataId", imageId.arkDataId) == napi_ok) {
            infoArr.push_back(imageId);
        } else {
            FI_HILOGE("unknown array type");
            return false;
        }
    }
    if (!strArr.empty()) {
        option.entityInfo[strName] = strArr;
    } else if (!infoArr.empty()) {
        option.entityInfo[strName] = infoArr;
    }
    return true;
}

bool OnScreenNapi::HandleOptionElement(napi_env env, std::string strName, napi_value elementValue,
    AwarenessOptions &option)
{
    napi_valuetype elementType = napi_undefined;
    CHKCF(napi_typeof(env, elementValue, &elementType) == napi_ok, "napi_typeof failed");
    switch (elementType) {
        case napi_boolean: {
            CHKCF(HandleOptionBool(env, strName, elementValue, option), "napi value bool fail");
            break;
        }
        case napi_number: {
            CHKCF(HandleOptionInt32(env, strName, elementValue, option), "napi value int32 fail");
            break;
        }
        case napi_string: {
            CHKCF(HandleOptionString(env, strName, elementValue, option), "napi value str fail");
            break;
        }
        case napi_bigint: {
            CHKCF(HandleOptionInt64(env, strName, elementValue, option), "napi value int64 fail");
            break;
        }
        case napi_object: {
            bool isArray = false;
            CHKCF((napi_is_array(env, elementValue, &isArray) == napi_ok && isArray), "napi_is_array fail");
            if (isArray) {
                CHKCF(HandleOptionArray(env, strName, elementValue, option), "napi value array fail");
            } else {
                CHKCF(HandleOptionObject(env, strName, elementValue, option), "napi value obj fail");
            }
            break;
        }
        default:
            break;
    }
    return true;
}

bool OnScreenNapi::GetAwarenessOption(napi_env env, napi_value awarenessOption, AwarenessOptions &option)
{
    CHKCF(IsMatchType(env, awarenessOption, napi_object), "arg type mismatch");
    napi_value valueList = nullptr;
    uint32_t valueCount = 0;
    napi_value elementName = nullptr;
    napi_value elementValue = nullptr;
    CHKCF(napi_get_property_names(env, awarenessOption, &valueList) == napi_ok, "get property names fail");
    CHKCF(napi_get_array_length(env, valueList, &valueCount) == napi_ok, "get array length fail");
    for (uint32_t index = 0; index < valueCount; index++) {
        CHKCF(napi_get_element(env, valueList, index, &elementName) == napi_ok, "get element fail");
        std::string strName;
        CHKCF(TransJsToStr(env, elementName, strName), "get str name failed");
        CHKCF(napi_get_named_property(env, awarenessOption, strName.c_str(), &elementValue) == napi_ok,
            "get named property fail");
        CHKCF(HandleOptionElement(env, strName, elementValue, option), "handle element failed");
    }
    return true;
}

napi_value OnScreenNapi::Trigger(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
    size_t argc = ARG_2;
    napi_value args[ARG_2] = { nullptr };
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr);
    if (status != napi_ok || argc < 1) {
        ThrowOnScreenErr(env, RET_PARAM_ERR, "napi_get_cb_info failed");
        return nullptr;
    }
    AwarenessCap cap;
    if (!GetAwarenessCap(env, args[ARG_0], argc, cap)) {
        ThrowOnScreenErr(env, RET_PARAM_ERR, "param is invalid");
        return nullptr;
    }
    AwarenessOptions option;
    if (argc == ARG_2 && !GetAwarenessOption(env, args[ARG_1], option)) {
        ThrowOnScreenErr(env, RET_PARAM_ERR, "option is invalid");
        return nullptr;
    }
    {
        std::lock_guard lockGrd(g_mtx);
        if (!ConstructOnScreen(env, jsThis)) {
            ThrowOnScreenErr(env, RET_SERVICE_EXCEPTION, "failed to get g_onScreenObj");
            return nullptr;
        }
    }
    napi_value promise = nullptr;
    napi_deferred deferred = nullptr;
    status = napi_create_promise(env, &deferred, &promise);
    if (status != napi_ok) {
        ThrowOnScreenErr(env, RET_SERVICE_EXCEPTION, "Failed to create promise");
        return nullptr;
    }
    TriggerAsyncContext* asyncContext = new (std::nothrow) TriggerAsyncContext();
    CHKPP(asyncContext);
    asyncContext->env = env;
    asyncContext->deferred = deferred;
    asyncContext->cap = cap;
    asyncContext->option = option;
    if (!TriggerExec(asyncContext)) {
        FI_HILOGE("get page content execution failed");
        delete asyncContext;
        return nullptr;
    }
    return promise;
}

bool OnScreenNapi::ConstructStringVector(napi_env env, napi_value &jsValue, std::vector<std::string> strVector)
{
    CHKCF(napi_create_array_with_length(env, strVector.size(), &jsValue) == napi_ok, "create bool failed");
    for (size_t i = 0; i < strVector.size(); ++i) {
        napi_value strObj;
        CHKCF(napi_create_string_utf8(env, strVector[i].c_str(), strVector[i].size(), &strObj) == napi_ok,
            "create str failed");
        CHKCF(napi_set_element(env, jsValue, i, strObj) == napi_ok, "add str to vector failed");
    }
    return true;
}
bool OnScreenNapi::ConstructObjectVector(napi_env env, napi_value &jsValue,
    std::vector<OnScreen::AwarenessInfoImageId> objVector)
{
    CHKCF(napi_create_array_with_length(env, objVector.size(), &jsValue) == napi_ok, "create bool failed");
    for (size_t i = 0; i < objVector.size(); ++i) {
        napi_value obj;
        CHKCF(napi_create_object(env, &obj) == napi_ok, "create obj failed");
        CHKCF(SetStringProperty(env, obj, objVector[i].compId, "compId"), "set compId failed");
        CHKCF(SetStringProperty(env, obj, objVector[i].arkDataId, "arkDataId"), "set arkDataId failed");
        CHKCF(napi_set_element(env, jsValue, i, obj) == napi_ok, "add str to vector failed");
    }
    return true;
}

bool OnScreenNapi::ConstructValueObj(napi_env env, napi_value &jsValue, ValueObj valueObj)
{
    std::visit([env, &jsValue](auto&& arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, bool>) {
            CHKCF(napi_get_boolean(env, arg, &jsValue) == napi_ok, "create bool failed");
            return true;
        } else if constexpr (std::is_same_v<T, int32_t>) {
            CHKCF(napi_create_int32(env, arg, &jsValue) == napi_ok, "create int32 failed");
            return true;
        } else if constexpr (std::is_same_v<T, int64_t>) {
            CHKCF(napi_create_int64(env, arg, &jsValue) == napi_ok, "create int64 failed");
            return true;
        } else if constexpr (std::is_same_v<T, std::string>) {
            CHKCF(napi_create_string_utf8(env, arg.c_str(), arg.size(), &jsValue) == napi_ok, "create str failed");
            return true;
        } else if constexpr (std::is_same_v<T, OnScreen::AwarenessInfoPageLink>) {
            CHKCF(napi_create_object(env, &jsValue) == napi_ok, "create jsValue failed");
            CHKCF(SetStringProperty(env, jsValue, arg.httpLink, "httpLink"), "set httpLink failed");
            CHKCF(SetStringProperty(env, jsValue, arg.deepLink, "deepLink"), "set deepLink failed");
            return true;
        } else if constexpr (std::is_same_v<T, std::shared_ptr<Media::PixelMap>>) {
            jsValue = Media::PixelMapNapi::CreatePixelMap(env, arg);
            CHKCF(jsValue != nullptr, "create pixel map failed");
            return true;
        } else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
            CHKCF(ConstructStringVector(env, jsValue, arg), "set str vector failed");
            return true;
        } else if constexpr (std::is_same_v<T, std::vector<OnScreen::AwarenessInfoImageId>>) {
            CHKCF(ConstructObjectVector(env, jsValue, arg), "set obj vector failed");
            return true;
        }
        }, valueObj);
    return true;
}

bool OnScreenNapi::ConstructAwarenessEntityInfo(napi_env env, napi_value &jsEntity,
    const std::map<std::string, ValueObj>& infoMap)
{
    napi_value entityInfo;
    CHKCF(napi_create_object(env, &entityInfo) == napi_ok, "create entityInfo failed");
    for (const auto& [key, value] : infoMap) {
        napi_value jsKey;
        napi_value jsValue;
        CHKCF(napi_create_string_utf8(env, key.c_str(), NAPI_AUTO_LENGTH, &jsKey) == napi_ok, "create str failed");
        CHKCF(ConstructValueObj(env, jsValue, value), "create value obj failed");
        CHKCF(napi_set_property(env, entityInfo, jsKey, jsValue) == napi_ok, "set property failed");
    }
    CHKCF(napi_set_named_property(env, jsEntity, "entityInfo", entityInfo) == napi_ok, "set property failed");
    return true;
}

bool OnScreenNapi::ConstructAwarenessEntityInfoVector(napi_env env, napi_value &awarenessInfoObj,
    const std::vector<OnscreenEntityInfo>& vec)
{
    napi_value jsArray;
    CHKCF(napi_create_array_with_length(env, vec.size(), &jsArray) == napi_ok, "create array failed");
    for (size_t i = 0; i < vec.size(); ++i) {
        napi_value jsEntity;
        CHKCF(napi_create_object(env, &jsEntity) == napi_ok, "create jsEntity failed");
        CHKCF(SetStringProperty(env, jsEntity, vec[i].entityName, "entityName"), "set entityName failed");
        ConstructAwarenessEntityInfo(env, jsEntity, vec[i].entityInfo);
        napi_set_element(env, jsArray, i, jsEntity);
    }
    CHKCF(napi_set_named_property(env, awarenessInfoObj, "entityInfo", jsArray) == napi_ok, "set property failed");
    return true;
}

bool OnScreenNapi::ConstructAwarenessInfoObj(napi_env env, napi_value &awarenessInfoObj,
    const OnscreenAwarenessInfo& info)
{
    CHKCF(napi_create_object(env, &awarenessInfoObj) == napi_ok, "create OnscreenAwarenessInfo failed");
    CHKCF(SetInt32Property(env, awarenessInfoObj, info.resultCode, "resultCode"), "create resultCode failed");
    CHKCF(SetInt64Property(env, awarenessInfoObj, info.timestamp, "timestamp"), "create timestamp failed");
    CHKCF(SetStringProperty(env, awarenessInfoObj, info.bundleName, "bundleName"), "create bundleName failed");
    CHKCF(SetStringProperty(env, awarenessInfoObj, info.appID, "appID"), "create appID failed");
    CHKCF(SetInt32Property(env, awarenessInfoObj, info.appIndex, "appIndex"), "create appIndex failed");
    CHKCF(SetStringProperty(env, awarenessInfoObj, info.pageId, "pageId"), "create pageId failed");
    CHKCF(SetStringProperty(env, awarenessInfoObj, info.sampleId, "sampleId"), "create sampleId failed");
    CHKCF(SetInt32Property(env, awarenessInfoObj, info.collectStrategy, "collectStrategy"),
        "create collectStrategy failed");
    CHKCF(SetInt64Property(env, awarenessInfoObj, info.displayId, "displayId"), "create displayId failed");
    CHKCF(SetInt32Property(env, awarenessInfoObj, info.windowId, "windowId"), "create windowId failed");
    CHKCF(ConstructAwarenessEntityInfoVector(env, awarenessInfoObj, info.entityInfo), "EntityInfoVector failed");
    return true;
}

bool OnScreenNapi::TriggerExec(TriggerAsyncContext *asyncContext)
{
    CHKPF(asyncContext);
    CHKPF(asyncContext->env);
    CHKPF(asyncContext->deferred);
    napi_value resource = nullptr;
    std::string funcName = "triggerExec";
    napi_create_string_utf8(asyncContext->env, "triggerExec", funcName.size(), &resource);
    CHKRF(napi_create_async_work(asyncContext->env, nullptr, resource, TriggerExecCB,
        TriggerCompCB, static_cast<void*>(asyncContext), &asyncContext->work), "CREATE_ASYNC_WORK");
    CHKRF(napi_queue_async_work_with_qos(asyncContext->env, asyncContext->work, napi_qos_default), "QUEUE_ASYNC_WORK");
    FI_HILOGI("exec trigger succ");
    return true;
}

void OnScreenNapi::TriggerExecCB(napi_env env, void *data)
{
    CHKPV(data);
    CHKPV(env);
    std::lock_guard lockGuard(g_mtx);
    TriggerAsyncContext* execAsyncContext = static_cast<TriggerAsyncContext*>(data);
    execAsyncContext->result = OnScreenManager::GetInstance().Trigger(execAsyncContext->cap, execAsyncContext->option,
        execAsyncContext->info);
}

void OnScreenNapi::TriggerCompCB(napi_env env, napi_status status, void *data)
{
    CHKPV(data);
    CHKPV(env);
    std::lock_guard lockGrd(g_mtx);
    std::unique_ptr<TriggerAsyncContext> ctx(static_cast<TriggerAsyncContext*>(data));
    CHKPV(ctx);
    CHKPV(ctx->deferred);
    napi_value errVal = nullptr;
    napi_value infoObj = nullptr;
    napi_status retStatus = napi_ok;
    if (ctx->result != RET_OK) {
        auto retMsg = GetOnScreenErrMsg(ctx->result);
        if (retMsg != std::nullopt) {
            ThrowOnScreenErrByPromise(env, ctx->result, retMsg.value(), errVal);
        } else {
            ThrowOnScreenErrByPromise(env, RET_SERVICE_EXCEPTION, "service exception", errVal);
        }
        retStatus = napi_reject_deferred(env, ctx->deferred, errVal);
    } else {
        if (!ConstructAwarenessInfoObj(env, infoObj, ctx->info)) {
            ThrowOnScreenErrByPromise(env, RET_SERVICE_EXCEPTION, "service exception", errVal);
            retStatus = napi_reject_deferred(env, ctx->deferred, errVal);
        }
        retStatus = napi_resolve_deferred(env, ctx->deferred, infoObj);
    }
    if (retStatus != napi_ok) {
        FI_HILOGE("napi pack defer err, result = %{public}d, status = %{public}d", ctx->result, retStatus);
    }
    napi_delete_async_work(env, ctx->work);
}

void OnScreenNapi::UpsertScreenCallback(napi_env env, const AwarenessCap& cap, napi_ref handlerRef)
{
    FI_HILOGD("enter");
    for (auto capItem : cap.capList) {
        g_screenCallbacks[capItem] = handlerRef;
    }
}

void OnScreenNapi::RemoveScreenCallback(napi_env env, const AwarenessCap& cap, napi_ref handlerRef)
{
    FI_HILOGD("enter");
    for (auto capItem : cap.capList) {
        auto it = g_screenCallbacks.find(capItem);
        if (it == g_screenCallbacks.end()) {
            continue;
        }
        g_screenCallbacks.erase(it);
    }
}

napi_value OnScreenNapi::RegisterAwarenessCallback(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
    size_t argc = 3;
    napi_value args[ARG_3] = { nullptr };
    napi_value jsThis = nullptr;
    napi_value result = nullptr;
    if (napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr) != napi_ok || argc < ARG_2) {
        ThrowOnScreenErr(env, RET_SERVICE_EXCEPTION, "napi_get_cb_info failed, expected 3 args");
        return nullptr;
    }
    AwarenessCap cap;
    if ((!GetAwarenessCap(env, args[ARG_0], argc, cap)) || (!IsValidCap(cap.capList))) {
        ThrowOnScreenErr(env, RET_PARAM_ERR, "param is invalid");
        return nullptr;
    }
    AwarenessOptions option;
    if (argc == ARG_3 && !GetAwarenessOption(env, args[ARG_2], option)) {
        ThrowOnScreenErr(env, RET_PARAM_ERR, "param is invalid");
        return nullptr;
    }
    // Get Callback
    napi_ref handlerRef = nullptr;
    {
        std::lock_guard lockGrd(g_mtx);
        if (!ConstructOnScreen(env, jsThis)) {
            ThrowOnScreenErr(env, RET_SERVICE_EXCEPTION, "failed to get g_onScreenObj");
            return nullptr;
        }
        if (g_callback == nullptr) {
            g_callback = new (std::nothrow) OnScreenAwarenessCallback(env);
            CHKPP(g_callback);
        }
        if (napi_create_reference(env, args[ARG_1], 1, &handlerRef) != napi_ok) {
            ThrowOnScreenErr(env, RET_PARAM_ERR, "can not get callback");
            if (handlerRef != nullptr) {
                napi_delete_reference(env, handlerRef);
            }
            return nullptr;
        }
        UpsertScreenCallback(env, cap, handlerRef);
    }

    OnScreenManager::GetInstance().RegisterAwarenessCallback(cap, g_callback, option);
    napi_get_undefined(env, &result);
    return result;
}

napi_value OnScreenNapi::UnregisterAwarenessCallback(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
    size_t argc = 2;
    napi_value args[ARG_2] = { nullptr };
    napi_value jsThis = nullptr;
    napi_value result = nullptr;
    if (napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr) != napi_ok || argc < 1) {
        ThrowOnScreenErr(env, RET_SERVICE_EXCEPTION, "napi_get_cb_info failed, expected 3 args");
        return nullptr;
    }
    AwarenessCap cap;
    if ((!GetAwarenessCap(env, args[ARG_0], argc, cap)) || (!IsValidCap(cap.capList))) {
        ThrowOnScreenErr(env, RET_PARAM_ERR, "param is invalid");
        return nullptr;
    }
    if (CheckCapList(cap.capList)) {
        ThrowOnScreenErr(env, RET_PARAM_ERR, "not regist yet");
        return nullptr;
    }
    napi_ref handlerRef = nullptr;
    {
        std::lock_guard lockGrd(g_mtx);
        if (napi_create_reference(env, args[ARG_1], 1, &handlerRef) != napi_ok) {
            ThrowOnScreenErr(env, RET_PARAM_ERR, "can not get callback");
            if (handlerRef != nullptr) {
                napi_delete_reference(env, handlerRef);
            }
            return nullptr;
        }
        RemoveScreenCallback(env, cap, handlerRef);
    }
    OnScreenManager::GetInstance().UnregisterAwarenessCallback(cap, g_callback);
    napi_get_undefined(env, &result);
    return result;
}

OnScreenAwarenessCallback::~OnScreenAwarenessCallback()
{
    if (env_ == nullptr) {
        return;
    }
    for (auto ref : onRef) {
        napi_delete_reference(env_, ref);
    }
    onRef.clear();
}

void OnScreenAwarenessCallback::OnScreenAwareness(const OnscreenAwarenessInfo& info)
{
    sptr<OnScreenAwarenessCallback> self(this);
    std::vector<napi_ref> refSnapshot;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        refSnapshot.assign(onRef.begin(), onRef.end());
    }

    auto task = [self, info]() {
        for (const auto& [key, value] : g_screenCallbacks) {
            napi_value handler = nullptr;
            {
                std::lock_guard<std::mutex> lk(g_mtx);
                if (napi_get_reference_value(self->env_, value, &handler) != napi_ok) {
                    FI_HILOGE("napi_get_reference_value failed");
                    return;
                }
            }
            napi_value result;
            if (!OnScreenNapi::ConstructAwarenessInfoObj(self->env_, result, info)) {
                FI_HILOGE("Failed to ConstructAwarenessInfoObj");
                continue;
            }
            napi_value callResult = nullptr;
            napi_call_function(self->env_, nullptr, handler, 1, &result, &callResult);
        }
    };
    if (napi_send_event(self->env_, task, napi_eprio_immediate) != napi_ok) {
        FI_HILOGE("Failed to SendEvent");
    }
}

bool OnScreenNapi::SetBoolProperty(napi_env env, napi_value targetObj, bool value, const char *propName)
{
    napi_value prop = nullptr;
    napi_status ret = napi_get_boolean(env, value, &prop);
    if (ret != napi_ok) {
        FI_HILOGE("napi_get_boolean failed");
        return false;
    }
    return SetPropertyName(env, targetObj, propName, prop);
}

napi_value OnScreenNapi::GetPageContentNapi(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
    size_t argc = ARG_1;
    napi_value args[ARG_1] = { nullptr };
    napi_value jsThis = nullptr;
    ContentOption option;
    napi_status status = napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr);
    if (status != napi_ok) {
        ThrowOnScreenErr(env, RET_SERVICE_EXCEPTION, "napi_get_cb_info failed");
        return nullptr;
    }
    if (!GetContentOption(env, args, argc, option)) {
        ThrowOnScreenErr(env, RET_PARAM_ERR, "param is invalid");
        return nullptr;
    }
    {
        std::lock_guard lockGrd(g_mtx);
        if (!ConstructOnScreen(env, jsThis)) {
            ThrowOnScreenErr(env, RET_SERVICE_EXCEPTION, "failed to get g_onScreenObj");
            return nullptr;
        }
    }
    napi_value promise = nullptr;
    napi_deferred deferred = nullptr;
    status = napi_create_promise(env, &deferred, &promise);
    if (status != napi_ok) {
        ThrowOnScreenErr(env, RET_SERVICE_EXCEPTION, "Failed to create promise");
        return nullptr;
    }
    GetPageContentAsyncContext* asyncContext = new (std::nothrow) GetPageContentAsyncContext();
    CHKPP(asyncContext);
    asyncContext->env = env;
    asyncContext->deferred = deferred;
    asyncContext->option = option;
    FI_HILOGD("invoke get page content, windowid = %{public}d, contentUnderstand = %{public}d, pageLink = %{public}d,"
        "textOnly = %{public}d, minParaLen = %{public}d, maxParaLen = %{public}d", asyncContext->option.windowId,
        asyncContext->option.contentUnderstand, asyncContext->option.pageLink, asyncContext->option.textOnly,
        asyncContext->option.paragraphSizeRange.minSize, asyncContext->option.paragraphSizeRange.maxSize);
    if (!GetPageContentExec(asyncContext)) {
        FI_HILOGE("get page content execution failed");
        delete asyncContext;
        return nullptr;
    }
    return promise;
}

napi_value OnScreenNapi::SendControlEventNapi(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
    size_t argc = ARG_1;
    napi_value args[ARG_1] = { nullptr };
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr);
    if (status != napi_ok) {
        ThrowOnScreenErr(env, RET_SERVICE_EXCEPTION, "napi_get_cb_info failed");
        return nullptr;
    }
    ControlEvent event;
    if (!GetControlEvent(env, args, argc, event)) {
        ThrowOnScreenErr(env, RET_PARAM_ERR, "param is invalid");
        return nullptr;
    }
    {
        std::lock_guard lockGrd(g_mtx);
        if (!ConstructOnScreen(env, jsThis)) {
            ThrowOnScreenErr(env, RET_SERVICE_EXCEPTION, "failed to get g_onScreenObj");
            return nullptr;
        }
    }
    napi_value promise = nullptr;
    napi_deferred deferred = nullptr;
    status = napi_create_promise(env, &deferred, &promise);
    if (status != napi_ok) {
        ThrowOnScreenErr(env, RET_SERVICE_EXCEPTION, "Failed to create promise");
        return nullptr;
    }
    SendControlEventAsyncContext* asyncContext = new (std::nothrow) SendControlEventAsyncContext();
    CHKPP(asyncContext);
    asyncContext->env = env;
    asyncContext->deferred = deferred;
    asyncContext->event = event;
    FI_HILOGD("invoke send control event, windowid = %{public}d, sessionId = %{public}" PRId64
        ", eventType = %{public}d, hookid = %{public}" PRId64, asyncContext->event.windowId,
        asyncContext->event.sessionId, asyncContext->event.eventType, asyncContext->event.hookId);
    if (!SendControlEventExec(asyncContext)) {
        FI_HILOGE("send control event execution failed");
        delete asyncContext;
        return nullptr;
    }
    return promise;
}

bool OnScreenNapi::ConstructOnScreen(napi_env env, napi_value jsThis)
{
    if (g_onScreenObj == nullptr) {
        g_onScreenObj = new (std::nothrow) OnScreenNapi(env, jsThis);
        if (g_onScreenObj == nullptr) {
            FI_HILOGE("faild to get g_onScreenObj");
            return false;
        }
        napi_status status = napi_wrap(env, jsThis, reinterpret_cast<void *>(g_onScreenObj),
            [](napi_env env, void *data, void *hint) {
                (void)env;
                (void)hint;
                if (data != nullptr) {
                    OnScreenNapi *onScreen = reinterpret_cast<OnScreenNapi *>(data);
                    delete onScreen;
                }
            }, nullptr, nullptr);
        if (status != napi_ok) {
            delete g_onScreenObj;
            g_onScreenObj = nullptr;
            FI_HILOGE("napi_wrap failed");
            return false;
        }
    }
    return true;
}

bool OnScreenNapi::GetContentOption(napi_env env, napi_value *args, size_t argc, ContentOption &option)
{
    if (argc == 0) {
        FI_HILOGD("param is not passed, use default param");
        return true;
    }
    if (argc != ARG_1) {
        return false;
    }
    napi_value contentOptionObj = args[ARG_0];
    bool ret = GetInt32FromJs(env, contentOptionObj, "windowId", option.windowId, false);
    ret = ret && GetBoolFromJs(env, contentOptionObj, "contentUnderstand", option.contentUnderstand, false);
    ret = ret && GetBoolFromJs(env, contentOptionObj, "pageLink", option.pageLink, false);
    ret = ret && GetBoolFromJs(env, contentOptionObj, "textOnly", option.textOnly, false);
    if (!ret) {
        FI_HILOGE("get content option failed");
    }
    if (option.windowId < DEFAULT_WINDOW_ID) {
        FI_HILOGE("windowId is invalid");
        return false;
    }
    return ret;
}

bool OnScreenNapi::GetControlEvent(napi_env env, napi_value *args, size_t argc, ControlEvent &event)
{
    if (argc != ARG_1) {
        return false;
    }
    napi_value eventObj = args[ARG_0];
    int32_t eventType = 0;
    bool ret = GetInt32FromJs(env, eventObj, "windowId", event.windowId, true);
    ret = ret && GetInt64FromJs(env, eventObj, "sessionId", event.sessionId, true);
    ret = ret && GetInt32FromJs(env, eventObj, "eventType", eventType, true);
    ret = ret && GetInt64FromJs(env, eventObj, "hookId", event.hookId, false);
    if (eventType <= static_cast<int32_t>(EventType::UNKNOWN) || eventType >= static_cast<int32_t>(EventType::END)) {
        FI_HILOGE("event type is invalid");
        return false;
    } else {
        event.eventType = static_cast<EventType>(eventType);
    }
    if (!ret) {
        FI_HILOGE("get control event failed");
    }
    if (event.windowId < 0 || event.sessionId < 0 || event.hookId < 0) {
        FI_HILOGE("windowId or sessionId or hookId is invalid");
        return false;
    }
    return ret;
}

bool OnScreenNapi::GetInt32FromJs(napi_env env, const napi_value &value, const std::string &field,
    int32_t &result, bool isNecessary)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, value, field.c_str(), &hasProperty) != napi_ok) {
        FI_HILOGE("napi_has_named_property failed");
        return false;
    }
    if (!hasProperty) {
        FI_HILOGW("napi dont have this property");
        // 如果是必要的，则返回false，如果不必要，则返回true，使用默认值
        return !isNecessary;
    }
    napi_value fieldValue = nullptr;
    napi_valuetype valueType = napi_undefined;
    if (napi_get_named_property(env, value, field.c_str(), &fieldValue) != napi_ok) {
        FI_HILOGE("napi_get_named_property failed");
        return false;
    }
    if (napi_typeof(env, fieldValue, &valueType) != napi_ok) {
        FI_HILOGE("typeof failed");
        return false;
    }
    if ((!isNecessary) && valueType == napi_undefined) {
        FI_HILOGW("isNecessary is false and valueType is undefined");
        return true;
    }
    if (valueType != napi_number) {
        FI_HILOGE("valueType is not number");
        return false;
    }
    if (napi_get_value_int32(env, fieldValue, &result) != napi_ok) {
        FI_HILOGE("napi_get_value_int32 failed");
        return false;
    }
    return true;
}

bool OnScreenNapi::GetInt64FromJs(napi_env env, const napi_value &value, const std::string &field,
    int64_t &result, bool isNecessary)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, value, field.c_str(), &hasProperty) != napi_ok) {
        FI_HILOGE("napi_has_named_property failed");
        return false;
    }
    if (!hasProperty) {
        FI_HILOGW("napi dont have this property");
        // 如果是必要的，则返回false，如果不必要，则返回true，使用默认值
        return !isNecessary;
    }
    napi_value fieldValue = nullptr;
    napi_valuetype valueType = napi_undefined;
    if (napi_get_named_property(env, value, field.c_str(), &fieldValue) != napi_ok) {
        FI_HILOGE("napi_get_named_property failed");
        return false;
    }
    if (napi_typeof(env, fieldValue, &valueType) != napi_ok) {
        FI_HILOGE("typeof failed");
        return false;
    }
    if ((!isNecessary) && valueType == napi_undefined) {
        FI_HILOGW("isNecessary is false and valueType is undefined");
        return true;
    }
    if (valueType != napi_number) {
        FI_HILOGE("valueType is not number");
        return false;
    }
    if (napi_get_value_int64(env, fieldValue, &result) != napi_ok) {
        FI_HILOGE("napi_get_value_int64 failed");
        return false;
    }
    return true;
}

bool OnScreenNapi::GetBoolFromJs(napi_env env, const napi_value &value, const std::string &field,
    bool &result, bool isNecessary)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, value, field.c_str(), &hasProperty) != napi_ok) {
        FI_HILOGE("napi_has_named_property failed");
        return false;
    }
    if (!hasProperty) {
        FI_HILOGW("napi dont have this property");
        // 如果是必要的，则返回false，如果不必要，则返回true，使用默认值
        return !isNecessary;
    }
    napi_value fieldValue = nullptr;
    napi_valuetype valueType = napi_undefined;
    if (napi_get_named_property(env, value, field.c_str(), &fieldValue) != napi_ok) {
        FI_HILOGE("napi_get_named_property failed");
        return false;
    }
    if (napi_typeof(env, fieldValue, &valueType) != napi_ok) {
        FI_HILOGE("typeof failed");
        return false;
    }
    if ((!isNecessary) && valueType == napi_undefined) {
        FI_HILOGW("isNecessary is false and valueType is undefined");
        return true;
    }
    if (valueType != napi_boolean) {
        FI_HILOGE("valueType is not bool");
        return false;
    }
    if (napi_get_value_bool(env, fieldValue, &result) != napi_ok) {
        FI_HILOGE("napi_get_value_bool failed");
        return false;
    }
    return true;
}

bool OnScreenNapi::SetInt32Property(napi_env env, napi_value targetObj, int32_t value, const char *propName)
{
    napi_value prop = nullptr;
    napi_status ret = napi_create_int32(env, value, &prop);
    if (ret != napi_ok) {
        FI_HILOGE("napi_create_int32 failed");
        return false;
    }
    return SetPropertyName(env, targetObj, propName, prop);
}

bool OnScreenNapi::SetInt64Property(napi_env env, napi_value targetObj, int64_t value, const char *propName)
{
    napi_value prop = nullptr;
    napi_status ret = napi_create_int64(env, value, &prop);
    if (ret != napi_ok) {
        FI_HILOGE("napi_create_int64 failed");
        return false;
    }
    return SetPropertyName(env, targetObj, propName, prop);
}

bool OnScreenNapi::SetStringProperty(napi_env env, napi_value targetObj, const std::string &value,
    const char *propName)
{
    napi_value prop = nullptr;
    napi_status ret = napi_create_string_utf8(env, value.c_str(), value.size(), &prop);
    if (ret != napi_ok) {
        FI_HILOGE("napi_create_string_utf8 failed");
        return false;
    }
    return SetPropertyName(env, targetObj, propName, prop);
}

bool OnScreenNapi::ConstructParagraphObj(napi_env env, napi_value &retObj, const Paragraph &value)
{
    retObj = nullptr;
    if (napi_create_object(env, &retObj) != napi_ok) {
        FI_HILOGE("create obj failed");
        retObj = nullptr;
        return false;
    }
    bool ret = SetInt64Property(env, retObj, value.hookId, "hookId");
    ret = ret && SetInt32Property(env, retObj, value.chapterId, "chapterId");
    ret = ret && SetStringProperty(env, retObj, value.title, "title");
    ret = ret && SetStringProperty(env, retObj, value.content, "text");
    if (!ret) {
        FI_HILOGE("create paragrah obj failed");
        return false;
    }
    return true;
}

bool OnScreenNapi::SetParagraphVecProperty(napi_env env, napi_value targetObj, const std::vector<Paragraph> paragraphs,
    const char *propName)
{
    napi_value paraArray = nullptr;
    if (napi_create_array(env, &paraArray) != napi_ok) {
        FI_HILOGE("failed to create array");
        return false;
    }
    for (size_t i = 0; i < paragraphs.size(); i++) {
        napi_value element = nullptr;
        if (!ConstructParagraphObj(env, element, paragraphs[i])) {
            FI_HILOGE("failed to create para, i = %{public}zu", i);
            return false;
        }
        if (napi_set_element(env, paraArray, i, element) != napi_ok) {
            FI_HILOGE("failed to set element, i = %{public}zu", i);
            return false;
        }
    }
    return SetPropertyName(env, targetObj, propName, paraArray);
}

bool OnScreenNapi::SetPropertyName(napi_env env, napi_value targetObj, const char *propName, napi_value propValue)
{
    napi_status status = napi_set_named_property(env, targetObj, propName, propValue);
    if (status != napi_ok) {
        FI_HILOGE("Failed to set the name property");
        return false;
    }
    return true;
}

bool OnScreenNapi::ConstructPageContentObj(napi_env env, napi_value &pageContentObj,
    const GetPageContentAsyncContext* ctx)
{
    if (napi_create_object(env, &pageContentObj) != napi_ok) {
        FI_HILOGE("create pageContent failed");
        return false;
    }
    bool ret = SetInt32Property(env, pageContentObj, ctx->pageContent.windowId, "windowId");
    ret = ret && SetInt64Property(env, pageContentObj, ctx->pageContent.sessionId, "sessionId");
    ret = ret && SetStringProperty(env, pageContentObj, ctx->pageContent.bundleName, "bundleName");
    if (ctx->option.contentUnderstand) {
        ret = ret && SetInt32Property(env, pageContentObj, static_cast<int32_t>(ctx->pageContent.scenario), "scenario");
        ret = ret && SetStringProperty(env, pageContentObj, ctx->pageContent.title, "title");
        ret = ret && SetStringProperty(env, pageContentObj, ctx->pageContent.content, "content");
    }
    if (ctx->option.pageLink) {
        ret = ret && SetStringProperty(env, pageContentObj, ctx->pageContent.pageLink, "pageLink");
    }
    if (ctx->option.textOnly) {
        ret = ret && SetParagraphVecProperty(env, pageContentObj, ctx->pageContent.paragraphs, "paragraphs");
    }
    if (!ret) {
        FI_HILOGE("construct page content failed");
        return false;
    }
    return true;
}

bool OnScreenNapi::GetPageContentExec(GetPageContentAsyncContext *asyncContext)
{
    CHKPF(asyncContext);
    CHKPF(asyncContext->env);
    CHKPF(asyncContext->deferred);
    napi_value resource = nullptr;
    std::string funcName = "getPageContentExec";
    napi_create_string_utf8(asyncContext->env, "getPageContentExec", funcName.size(), &resource);
    CHKRF(napi_create_async_work(asyncContext->env, nullptr, resource, GetPageContentExecCB,
        GetPageContentCompCB, static_cast<void*>(asyncContext), &asyncContext->work), "CREATE_ASYNC_WORK");
    CHKRF(napi_queue_async_work_with_qos(asyncContext->env, asyncContext->work, napi_qos_default), "QUEUE_ASYNC_WORK");
    FI_HILOGI("exec get page content succ");
    return true;
}

void OnScreenNapi::GetPageContentExecCB(napi_env env, void *data)
{
    CHKPV(data);
    CHKPV(env);
    std::lock_guard lockGuard(g_mtx);
    GetPageContentAsyncContext* execAsyncContext = static_cast<GetPageContentAsyncContext*>(data);
    execAsyncContext->result = OnScreenManager::GetInstance().GetPageContent(
        execAsyncContext->option, execAsyncContext->pageContent);
}

void OnScreenNapi::GetPageContentCompCB(napi_env env, napi_status status, void *data)
{
    CHKPV(data);
    CHKPV(env);
    std::lock_guard lockGrd(g_mtx);
    GetPageContentAsyncContext* ctx = static_cast<GetPageContentAsyncContext*>(data);
    CHKPV(ctx->deferred);
    napi_value errVal = nullptr;
    napi_value pageContentObj = nullptr;
    napi_status retStatus = napi_ok;
    if (ctx->result != RET_OK) {
        auto retMsg = GetOnScreenErrMsg(ctx->result);
        if (retMsg != std::nullopt) {
            ThrowOnScreenErrByPromise(env, ctx->result, retMsg.value(), errVal);
        } else {
            ThrowOnScreenErrByPromise(env, RET_SERVICE_EXCEPTION, "service exception", errVal);
        }
        retStatus = napi_reject_deferred(env, ctx->deferred, errVal);
    } else {
        if (!ConstructPageContentObj(env, pageContentObj, ctx)) {
            ThrowOnScreenErrByPromise(env, RET_SERVICE_EXCEPTION, "service exception", errVal);
            retStatus = napi_reject_deferred(env, ctx->deferred, errVal);
        }
        retStatus = napi_resolve_deferred(env, ctx->deferred, pageContentObj);
    }
    if (retStatus != napi_ok) {
        FI_HILOGE("napi pack defer err, result = %{public}d, status = %{public}d", ctx->result, retStatus);
    }
    napi_delete_async_work(env, ctx->work);
    delete ctx;
    ctx = nullptr;
}

bool OnScreenNapi::SendControlEventExec(SendControlEventAsyncContext *asyncContext)
{
    CHKPF(asyncContext);
    CHKPF(asyncContext->env);
    CHKPF(asyncContext->deferred);
    napi_value resource = nullptr;
    std::string funcName = "sendControlEventExec";
    napi_create_string_utf8(asyncContext->env, "sendControlEventExec", funcName.size(), &resource);
    CHKRF(napi_create_async_work(asyncContext->env, nullptr, resource, SendControlEventExecCB,
        SendControlEventCompCB, static_cast<void*>(asyncContext), &asyncContext->work), "CREATE_ASYNC_WORK");
    CHKRF(napi_queue_async_work_with_qos(asyncContext->env, asyncContext->work, napi_qos_default), "QUEUE_ASYNC_WORK");
    FI_HILOGI("exec send control event succ");
    return true;
}

void OnScreenNapi::SendControlEventExecCB(napi_env env, void *data)
{
    CHKPV(data);
    CHKPV(env);
    std::lock_guard lockGuard(g_mtx);
    SendControlEventAsyncContext* execAsyncContext = static_cast<SendControlEventAsyncContext*>(data);
    execAsyncContext->result = OnScreenManager::GetInstance().SendControlEvent(
        execAsyncContext->event);
}

void OnScreenNapi::SendControlEventCompCB(napi_env env, napi_status status, void *data)
{
    CHKPV(data);
    CHKPV(env);
    std::lock_guard lockGrd(g_mtx);
    SendControlEventAsyncContext* ctx = static_cast<SendControlEventAsyncContext*>(data);
    CHKPV(ctx->deferred);
    napi_value errVal = nullptr;
    napi_status retStatus = napi_ok;
    napi_value retVal = nullptr;
    if (napi_create_object(env, &retVal) != napi_ok) {
        FI_HILOGE("send control event create obj failed");
        ThrowOnScreenErrByPromise(env, RET_SERVICE_EXCEPTION, "service exception", errVal);
        napi_reject_deferred(env, ctx->deferred, errVal);
        napi_delete_async_work(env, ctx->work);
        delete ctx;
        ctx = nullptr;
        return;
    }
    if (ctx->result != RET_OK) {
        auto retMsg = GetOnScreenErrMsg(ctx->result);
        if (retMsg != std::nullopt) {
            ThrowOnScreenErrByPromise(env, ctx->result, retMsg.value(), errVal);
        } else {
            ThrowOnScreenErrByPromise(env, RET_SERVICE_EXCEPTION, "service exception", errVal);
        }
        retStatus = napi_reject_deferred(env, ctx->deferred, errVal);
    } else {
        retStatus = napi_resolve_deferred(env, ctx->deferred, retVal);
    }
    if (retStatus != napi_ok) {
        FI_HILOGE("napi pack defer err, result = %{public}d, status = %{public}d", ctx->result, retStatus);
    }
    napi_delete_async_work(env, ctx->work);
    delete ctx;
    ctx = nullptr;
}

EXTERN_C_START
/*
 * function for module exports
 */
static napi_value OnScreenNapiInit(napi_env env, napi_value exports)
{
    FI_HILOGD("Enter");
    napi_value ret = OnScreenNapi::Init(env, exports);
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
    .nm_filename = "multimodalAwareness.onScreen",
    .nm_register_func = OnScreenNapiInit,
    .nm_modname = "multimodalAwareness.onScreen",
    .nm_priv = (static_cast<void *>(nullptr)),
    .reserved = { nullptr }
};

/*
 * Module registration
 */
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&g_module);
}
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS