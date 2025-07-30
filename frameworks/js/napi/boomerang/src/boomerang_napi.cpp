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

#include "boomerang_napi.h"

#include <js_native_api.h>

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "image_pixel_map_napi.h"
#include "image_pixel_map_mdk.h"
#include "pixel_map_napi.h"

#include "boomerang_manager.h"
#include "boomerang_napi_error.h"
#include "devicestatus_client.h"
#include "devicestatus_define.h"
#include "napi_constants.h"
#include "util_napi_error.h"

#undef LOG_TAG
#define LOG_TAG "BoomerangNapi"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr size_t ARG_0{0};
constexpr size_t ARG_1{1};
constexpr size_t ARG_2{2};
constexpr size_t ARG_3{3};
inline constexpr size_t MAX_STRING_LEN{1024};
const std::vector<std::string> vecDeviceStatusValue{"VALUE_ENTER", "VALUE_EXIT"};
thread_local BoomerangNapi *g_obj = nullptr;
constexpr uint32_t BITMAP_TRAVERSE_STEP = 4;
// bitmap green值偏移量
constexpr uint32_t GREEN_TRAVERSE_STEP = 1;
// bitmap red值偏移量
constexpr uint32_t RED_TRAVERSE_STEP = 2;
// bitmap alpha值偏移量
constexpr uint32_t ALPHA_TRAVERSE_STEP = 3;
// 图片的格式,格式为BGRA_8888
constexpr uint32_t PIXEL_FORMAT = 4;
// 图片的alpha类型,RGB前乘alpha
constexpr uint32_t ALPHA_TYPE = 2;
constexpr uint32_t ALPHA_SHIFT = 24;
constexpr uint32_t RED_SHIFT = 16;
constexpr uint32_t GREEN_SHIFT = 8;
constexpr int32_t VALIDATA_ON_PARAM = 1;
constexpr int32_t VALIDATA_OFF_PARAM = 2;
constexpr int32_t MAX_LENGTH = 128;
constexpr int32_t MIN_IMAGE_PIXEL = 1080;
constexpr char const *URL_CHARACTERES =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=|";
}  // namespace
std::map<int32_t, sptr<IRemoteBoomerangCallback>> BoomerangNapi::callbacks_;
napi_ref BoomerangNapi::boomerangValueRef_ = nullptr;

void BoomerangCallback::OnScreenshotResult(const BoomerangData &screenshotData)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    data_ = screenshotData;
    auto task = [this]() {
        FI_HILOGI("Execute lamdba");
        EmitOnEvent(&this->data_);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        FI_HILOGE("Failed to SendEvent");
    }
}

void BoomerangCallback::OnNotifyMetadata(const std::string &metadata)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    metadata_ = metadata;
    auto task = [this]() {
        FI_HILOGI("Execute lamdba");
        EmitOnMetadata(this->env_, this->metadata_, this->deferred_);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        FI_HILOGE("Failed to SendEvent");
    }
}

void BoomerangCallback::OnEncodeImageResult(std::shared_ptr<Media::PixelMap> pixelMap)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    pixelMap_ = pixelMap;
    auto task = [this]() {
        FI_HILOGI("Execute lamdba");
        EmitOnEncodeImage(this->env_, this->pixelMap_, this->deferred_);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        FI_HILOGE("Failed to SendEvent");
    }
}

void BoomerangCallback::EmitOnEvent(BoomerangData *data)
{
    BoomerangNapi *boomerangNapi = BoomerangNapi::GetDeviceStatusNapi();
    CHKPV(boomerangNapi);
    int32_t type = static_cast<int32_t>(data->type);
    int32_t status = static_cast<int32_t>(data->status);
    boomerangNapi->OnScreenshot(type, status, false);
}

void BoomerangCallback::EmitOnMetadata(napi_env env, std::string metadata, napi_deferred deferred)
{
    BoomerangNapi *boomerangNapi = BoomerangNapi::GetDeviceStatusNapi();
    CHKPV(boomerangNapi);
    boomerangNapi->OnMetadata(env, metadata, false, deferred);
}

void BoomerangCallback::EmitOnEncodeImage(napi_env env, std::shared_ptr<Media::PixelMap> pixelMap,
    napi_deferred deferred)
{
    if (env == nullptr || pixelMap == nullptr) {
        FI_HILOGI("EmitOnEncodeImage pixelMap is nullptr");
        return;
    }
    BoomerangNapi *boomerangNapi = BoomerangNapi::GetDeviceStatusNapi();
    CHKPV(boomerangNapi);
    boomerangNapi->OnEncodeImage(env, pixelMap, deferred);
}

void BoomerangNapi::OnScreenshot(int32_t type, int32_t status, bool isOnce)
{
    CALL_DEBUG_ENTER;
    OnEvent(type, ARG_1, status, isOnce);
}

void BoomerangNapi::OnMetadata(napi_env env, std::string metadata, bool isOnce, napi_deferred deferred)
{
    CALL_DEBUG_ENTER;
    auto processContext = [](napi_env env, napi_deferred deferred, const std::string &metadata) -> void {
        if (env == nullptr || deferred == nullptr) {
            return;
        }

        napi_value result;
        napi_status status = napi_create_string_utf8(env, metadata.c_str(), NAPI_AUTO_LENGTH, &result);
        if (status != napi_ok) {
            FI_HILOGE("Failed to create string utf8");
            return;
        }

        status = napi_resolve_deferred(env, deferred, result);
        if (status != napi_ok) {
            FI_HILOGE("Failed to resolve deferred");
            return;
        }
    };

    processContext(env, deferred, metadata);
}

void BoomerangNapi::OnEncodeImage(napi_env env, std::shared_ptr<Media::PixelMap> pixelMap, napi_deferred deferred)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(encodeMutex_);
    CHKPV(pixelMap);
    CHKPV(deferred);

    napi_value pixelMapNapi;
    uint32_t width = static_cast<uint32_t>(pixelMap->GetWidth());
    uint32_t height = static_cast<uint32_t>(pixelMap->GetHeight());
    const unsigned char *data = pixelMap->GetPixels();
    CHKPV(data);
    uint32_t rowStride = static_cast<uint32_t>(pixelMap->GetRowStride());
    uint32_t bufferSize = width * height * BITMAP_TRAVERSE_STEP;
    uint8_t *pixelArrayBuffer = new (std::nothrow) uint8_t[bufferSize];
    CHKPV(pixelArrayBuffer);
    for (uint32_t y = 0; y < height; ++y) {
        for (uint32_t x = 0; x < width; ++x) {
            uint32_t pixIndex = y * rowStride + x * BITMAP_TRAVERSE_STEP;
            uint32_t b = data[pixIndex];
            uint32_t g = data[pixIndex + GREEN_TRAVERSE_STEP];
            uint32_t r = data[pixIndex + RED_TRAVERSE_STEP];
            uint32_t a = data[pixIndex + ALPHA_TRAVERSE_STEP];
            uint32_t arrayIndex = (y * width + (x)) * BITMAP_TRAVERSE_STEP;
            uint32_t pixelValue = ((a << ALPHA_SHIFT) | (r << RED_SHIFT) | (g << GREEN_SHIFT) | b);
            *(reinterpret_cast<uint32_t *>(pixelArrayBuffer + arrayIndex)) = pixelValue;
        }
    }

    struct OhosPixelMapCreateOps createOps;
    createOps.width = width;
    createOps.height = height;
    createOps.pixelFormat = PIXEL_FORMAT;
    createOps.alphaType = ALPHA_TYPE;
    int32_t res = OH_PixelMap_CreatePixelMap(env, createOps, (uint8_t *)pixelArrayBuffer, bufferSize, &pixelMapNapi);
    if (res != 0 || pixelMapNapi == nullptr) {
        FI_HILOGI("wrap create pixelMap failed");
        delete[] pixelArrayBuffer;
        return;
    }
    if (deferred != nullptr) {
        napi_resolve_deferred(env, deferred, pixelMapNapi);
    }
}

BoomerangNapi *BoomerangNapi::GetDeviceStatusNapi()
{
    return g_obj;
}

BoomerangNapi::BoomerangNapi(napi_env env) : BoomerangEvent(env)
{
    env_ = env;
    boomerangValueRef_ = nullptr;
    DeviceStatusClient::GetInstance().RegisterDeathListener([this] {
        FI_HILOGI("Receive death notification");
        callbacks_.clear();
        ClearEventMap();
    });
}

BoomerangNapi::~BoomerangNapi()
{
    if (boomerangValueRef_ != nullptr) {
        napi_delete_reference(env_, boomerangValueRef_);
    }
}

napi_value BoomerangNapi::Register(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    size_t argc = 3;
    napi_value argv[3] = {nullptr};
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < ARG_2) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Wrong number of parameters");
        return nullptr;
    }
    if (!CheckArguments(env, info, VALIDATA_ON_PARAM)) {
        ThrowErr(env, PARAM_ERROR, "Failed to get on arguments");
        return nullptr;
    }

    char eventType[MAX_STRING_LEN] = {0};
    size_t eventLength = 0;
    CHKRP(napi_get_value_string_utf8(env, argv[0], eventType, sizeof(eventType), &eventLength), CREATE_STRING_UTF8);

    int32_t type = ConvertTypeToInt(eventType);

    char bundleName[MAX_STRING_LEN] = {0};
    size_t strLength = 0;
    CHKRP(napi_get_value_string_utf8(env, argv[1], bundleName, sizeof(bundleName), &strLength), CREATE_STRING_UTF8);
    return SubscribeMeatadataCallback(env, info, argv[ARG_2], type, bundleName);
}

napi_value BoomerangNapi::SubscribeMeatadataCallback(
    napi_env env, napi_callback_info info, napi_value handler, int32_t type, std::string bundleName)
{
    CALL_DEBUG_ENTER;
    if (!InitNapiObject(env, info)) {
        return nullptr;
    }
    if (!g_obj->On(type, handler, false)) {
        FI_HILOGE("type:%{public}d already exists", type);
        return nullptr;
    }

    auto callbackIter = callbacks_.find(type);
    if (callbackIter != callbacks_.end()) {
        FI_HILOGD("Callback exists");
        return nullptr;
    }

    sptr<IRemoteBoomerangCallback> callback = new (std::nothrow) BoomerangCallback(env, nullptr);
    CHKPP(callback);
    int32_t subscribeRet =
        BoomerangManager::GetInstance().SubscribeCallback(static_cast<BoomerangType>(type), bundleName, callback);
    if (subscribeRet != RET_OK) {
        ThrowErr(env,
            SUBSCRIBE_FAILED,
            "Subscribe Failed. Possible causes: 1. Abnormal system capability; 2. IPC communication abnormality; 3. "
            "Algorithm loading exception.");
        return nullptr;
    }
    auto ret = callbacks_.insert(std::pair<int32_t, sptr<IRemoteBoomerangCallback>>(type, callback));
    if (!ret.second) {
        FI_HILOGE("Failed to insert");
    }
    return nullptr;
}

napi_value BoomerangNapi::NotifyMetadataBindingEvent(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Wrong number of parameters");
        return nullptr;
    }
    if (!UtilNapi::TypeOf(env, argv[0], napi_string)) {
        THROWERR(env, COMMON_PARAMETER_ERROR, "type", "string");
        return nullptr;
    }

    char bundleName[MAX_STRING_LEN] = {0};
    size_t strLength = 0;
    CHKRP(napi_get_value_string_utf8(env, argv[0], bundleName, sizeof(bundleName), &strLength), CREATE_STRING_UTF8);

    if (!InitNapiObject(env, info)) {
        THROWERR_CUSTOM(env, HANDLER_FAILD, "Internal handling failed. File creation failed.");
        return nullptr;
    }

    auto asyncContext = new (std::nothrow) AsyncContext();
    CHKPP(asyncContext);
    asyncContext->env = env;
    napi_value promise = nullptr;
    napi_deferred deferred = nullptr;
    napi_status status = napi_create_promise(env, &deferred, &promise);
    if (status != napi_ok) {
        THROWERR_CUSTOM(env, HANDLER_FAILD, "Internal handling failed. File creation failed.");
        return nullptr;
    }

    asyncContext->deferred = deferred;
    sptr<IRemoteBoomerangCallback> callback = new (std::nothrow) BoomerangCallback(env, deferred);
    CHKPP(callback);
    bool result = CreateMetadataExecution(env, asyncContext, bundleName, callback);
    if (!result) {
        FI_HILOGE("notify metadataBinding event error by Create execution");
        delete asyncContext;
    }
    return promise;
}

napi_value BoomerangNapi::SubmitMetadata(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Wrong number of parameters");
        return nullptr;
    }
    if (!UtilNapi::TypeOf(env, argv[0], napi_string)) {
        THROWERR(env, COMMON_PARAMETER_ERROR, "type", "string");
        return nullptr;
    }

    char metadata[MAX_STRING_LEN] = {0};
    size_t strLength = 0;
    CHKRP(napi_get_value_string_utf8(env, argv[0], metadata, sizeof(metadata), &strLength), CREATE_STRING_UTF8);

    int32_t result = BoomerangManager::GetInstance().SubmitMetadata(metadata);
    if (result != RET_OK) {
        ThrowErr(env, HANDLER_FAILD, "Internal handling failed. File creation failed.");
    }
    return nullptr;
}

napi_value BoomerangNapi::BoomerangEncodeImage(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(encodeMutex_);
    size_t argc = 2;
    napi_value argv[2] = {nullptr};
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < ARG_2) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Wrong number of parameters");
        return nullptr;
    }
    if (UtilNapi::TypeOf(env, argv[0], napi_undefined) || UtilNapi::TypeOf(env, argv[0], napi_null)) {
        THROWERR(env, COMMON_PARAMETER_ERROR, "data", "pixelmap");
        return nullptr;
    }
    if (!UtilNapi::TypeOf(env, argv[1], napi_string)) {
        THROWERR(env, COMMON_PARAMETER_ERROR, "type", "string");
        return nullptr;
    }

    std::shared_ptr<Media::PixelMap> pixelMap = Media::PixelMapNapi::GetPixelMap(env, argv[0]);
    CHKPP(pixelMap);

    char metadata[MAX_STRING_LEN] = {0};
    size_t strLength = 0;
    CHKRP(napi_get_value_string_utf8(env, argv[1], metadata, sizeof(metadata), &strLength), CREATE_STRING_UTF8);

    if (!ValidateEncodeParam(metadata, pixelMap)) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "The parameters do not meet the requirements");
        return nullptr;
    }
    if (!InitNapiObject(env, info)) {
        THROWERR_CUSTOM(env, HANDLER_FAILD, "Internal handling failed. File creation failed.");
        return nullptr;
    }
    return HandleBoomerangEncodeImage(env, pixelMap, metadata);
}

napi_value BoomerangNapi::DecodeImage(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Wrong number of parameters");
        return nullptr;
    }
    if (UtilNapi::TypeOf(env, argv[0], napi_undefined) || UtilNapi::TypeOf(env, argv[0], napi_null)) {
        THROWERR(env, COMMON_PARAMETER_ERROR, "data", "pixelmap");
        return nullptr;
    }

    std::shared_ptr<Media::PixelMap> pixelMap = Media::PixelMapNapi::GetPixelMap(env, argv[0]);
    CHKPP(pixelMap);
    if (!InitNapiObject(env, info)) {
        THROWERR_CUSTOM(env, HANDLER_FAILD, "Internal handling failed. File creation failed.");
        return nullptr;
    }

    auto asyncContext = new (std::nothrow) AsyncContext();
    CHKPP(asyncContext);
    napi_value promise = nullptr;
    napi_deferred deferred = nullptr;
    napi_status status = napi_create_promise(env, &deferred, &promise);
    if (status != napi_ok) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "decode image error by create promise");
        return nullptr;
    }

    asyncContext->deferred = deferred;
    asyncContext->env = env;
    sptr<IRemoteBoomerangCallback> callback = new (std::nothrow) BoomerangCallback(env, deferred);
    CHKPP(callback);
    bool result = CreateDecodeImageExecution(env, asyncContext, pixelMap, callback);
    if (!result) {
        FI_HILOGE("decode image error by Create execution");
        delete asyncContext;
    }
    return promise;
}

napi_value BoomerangNapi::UnRegister(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    size_t argc = 3;
    napi_value argv[3] = {nullptr};
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);

    if (!CheckArguments(env, info, VALIDATA_OFF_PARAM)) {
        ThrowErr(env, PARAM_ERROR, "failed to get on arguments");
        return nullptr;
    }
    char eventType[MAX_STRING_LEN] = {0};
    size_t eventLength = 0;
    CHKRP(napi_get_value_string_utf8(env, argv[0], eventType, sizeof(eventType), &eventLength), CREATE_STRING_UTF8);

    int32_t type = ConvertTypeToInt(eventType);

    char bundleName[MAX_STRING_LEN] = {0};
    size_t strLength = 0;
    CHKRP(napi_get_value_string_utf8(env, argv[1], bundleName, sizeof(bundleName), &strLength), CREATE_STRING_UTF8);

    CHKPP(g_obj);
    if (!g_obj->Off(type)) {
        FI_HILOGE("Not ready to unsubscribe for type:%{public}d", type);
        return nullptr;
    }
    auto callbackIter = callbacks_.find(type);
    if (callbackIter == callbacks_.end()) {
        NAPI_ASSERT(env, false, "No existed callback");
        return nullptr;
    }
    int32_t unsubscribeRet = BoomerangManager::GetInstance().UnsubscribeCallback(
        static_cast<BoomerangType>(type), bundleName, callbackIter->second);
    if (unsubscribeRet != RET_OK) {
        ThrowErr(env,
            UNSUBSCRIBE_FAILED,
            "Unsubscribe Failed. Possible causes: 1. Abnormal system capability; 2. IPC communication abnormality.");
    }
    callbacks_.erase(type);
    return nullptr;
}

bool BoomerangNapi::ValidateEncodeParam(std::string metadata, std::shared_ptr<Media::PixelMap> pixelMap)
{
    if (metadata.empty() || metadata.size() > MAX_LENGTH) {
        FI_HILOGE("The metadata data size does not comply with the specifications");
        return false;
    }

    size_t pos = metadata.find_first_not_of(URL_CHARACTERES);
    if (pos != std::string::npos) {
        FI_HILOGE("There are illegal characters present in metadata");
        return false;
    }

    if (pixelMap->GetWidth() < MIN_IMAGE_PIXEL || pixelMap->GetHeight() < MIN_IMAGE_PIXEL) {
        FI_HILOGE("The image size does not meet the requirements");
        return false;
    }
    return true;
}

napi_value BoomerangNapi::HandleBoomerangEncodeImage(napi_env env, std::shared_ptr<Media::PixelMap> pixelMap,
    std::string metadata)
{
    napi_value promise = nullptr;
    napi_deferred deferred = nullptr;
    napi_status status = napi_create_promise(env, &deferred, &promise);
    if (status != napi_ok) {
        THROWERR_CUSTOM(env, HANDLER_FAILD, "Internal handling failed. File creation failed.");
        return nullptr;
    }

    sptr<IRemoteBoomerangCallback> callback = new (std::nothrow) BoomerangCallback(env, deferred);
    CHKPP(callback);
    auto asyncContext = new (std::nothrow) AsyncContext();
    CHKPP(asyncContext);
    asyncContext->env = env;
    asyncContext->deferred = deferred;
    bool result = CreateEncodeImageExecution(env, asyncContext, metadata, pixelMap, callback);
    if (!result) {
        FI_HILOGE("encode image error by Create execution");
        delete asyncContext;
        return nullptr;
    }
    return promise;
}

bool BoomerangNapi::InitNapiObject(napi_env env, napi_callback_info info)
{
    if (g_obj == nullptr) {
        g_obj = new (std::nothrow) BoomerangNapi(env);
        CHKPF(g_obj);
        FI_HILOGD("Didn't find object, so created it");
    }
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, &data);
    if (status != napi_ok) {
        FI_HILOGE("Failed to get_cb_info item");
        delete g_obj;
        g_obj = nullptr;
        return false;
    }
    status = napi_wrap(
        env,
        thisArg,
        reinterpret_cast<void *>(g_obj),
        [](napi_env env, void *data, void *hint) {
            (void)env;
            (void)hint;
            CHKPV(data);
            BoomerangNapi *deviceStatus = static_cast<BoomerangNapi *>(data);
            delete deviceStatus;
            g_obj = nullptr;
        },
        nullptr,
        nullptr);
    if (status != napi_ok) {
        FI_HILOGE("napi_wrap failed");
        delete g_obj;
        g_obj = nullptr;
        return false;
    }
    return true;
}

bool BoomerangNapi::CheckArguments(napi_env env, napi_callback_info info, int32_t validataType)
{
    CALL_DEBUG_ENTER;
    int32_t arr[ARG_3] = {0};
    size_t argc = ARG_3;
    napi_value args[ARG_3] = {nullptr};
    napi_status status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (status != napi_ok) {
        FI_HILOGE("Failed to get_cb_info");
        return false;
    }
    for (size_t i = 0; i < ARG_3; i++) {
        napi_valuetype valueType = napi_undefined;
        status = napi_typeof(env, args[i], &valueType);
        if (status != napi_ok) {
            FI_HILOGE("Failed to get valueType");
            return false;
        }
        FI_HILOGD("valueType:%{public}d", valueType);
        arr[i] = valueType;
    }
    if (validataType == VALIDATA_ON_PARAM) {
        if (arr[ARG_0] != napi_string || arr[ARG_1] != napi_string || arr[ARG_2] != napi_function) {
            FI_HILOGE("Failed to get arguments");
            return false;
        }
    }
    if (validataType == VALIDATA_OFF_PARAM) {
        if (arr[ARG_0] != napi_string || arr[ARG_1] != napi_string) {
            FI_HILOGE("Failed to get arguments");
            return false;
        }
    }
    return true;
}

bool BoomerangNapi::CreateMetadataExecution(napi_env env, AsyncContext *asyncContext,
    std::string bundleName, sptr<IRemoteBoomerangCallback> callback)
{
    if (asyncContext == nullptr || callback == nullptr) {
        FI_HILOGE("not init notify metadata asyncContext");
        return false;
    }
    asyncContext->callback = callback;
    asyncContext->bundleName = bundleName;
    napi_value resource = nullptr;
    std::string funcName = "NotifyMetadata";
    napi_create_string_utf8(env, "NotifyMetadata", funcName.length(), &resource);
    CHKRF(napi_create_async_work(env, nullptr, resource, NotifyMetadataExecuteCB, NotifyMetadataCompleteCB,
        static_cast<void*>(asyncContext), &asyncContext->work), CREAT_ASYNC_WORK);
    CHKRF(napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default), QUEUE_ASYNC_WORK);
    return true;
}
 
bool BoomerangNapi::CreateEncodeImageExecution(napi_env env, AsyncContext *asyncContext,
    std::string metadata, std::shared_ptr<Media::PixelMap> pixelMap, sptr<IRemoteBoomerangCallback> callback)
{
    if (asyncContext == nullptr) {
        FI_HILOGE("not init encode image asyncContext");
        return false;
    }
    asyncContext->callback = callback;
    asyncContext->metadata = metadata;
    asyncContext->pixelMap = pixelMap;
    napi_value resource = nullptr;
    std::string funcName = "EncodeImage";
    napi_create_string_utf8(env, "EncodeImage", funcName.length(), &resource);
    CHKRF(napi_create_async_work(env, nullptr, resource, EncodeImageExecuteCB, EncodeImageCompleteCB,
        static_cast<void*>(asyncContext), &asyncContext->work), CREAT_ASYNC_WORK);
    CHKRF(napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default), QUEUE_ASYNC_WORK);
    return true;
}
 
bool BoomerangNapi::CreateDecodeImageExecution(napi_env env, AsyncContext *asyncContext,
    std::shared_ptr<Media::PixelMap> pixelMap, sptr<IRemoteBoomerangCallback> callback)
{
    if (env == nullptr || asyncContext == nullptr) {
        FI_HILOGE("not init env or encode image asyncContext");
        return false;
    }
    asyncContext->callback = callback;
    asyncContext->pixelMap = pixelMap;
    napi_value resource = nullptr;
    std::string funcName = "DecodeImage";
    napi_create_string_utf8(env, "DecodeImage", funcName.length(), &resource);
    CHKRF(napi_create_async_work(env, nullptr, resource, DecodeImageExecuteCB, DecodeImageCompleteCB,
        static_cast<void*>(asyncContext), &asyncContext->work), CREAT_ASYNC_WORK);
    CHKRF(napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default), QUEUE_ASYNC_WORK);
    return true;
}
 
void BoomerangNapi::NotifyMetadataExecuteCB(napi_env env, void* data)
{
    std::lock_guard<std::mutex> guard(mutex_);
    auto innerAsyncContext = static_cast<AsyncContext*>(data);
    std::string bundleName = static_cast<std::string>(innerAsyncContext->bundleName);
    sptr<IRemoteBoomerangCallback> callback = static_cast<sptr<IRemoteBoomerangCallback>>(innerAsyncContext->callback);
    if (bundleName.empty() || callback == nullptr) {
        FI_HILOGE("bundleName or callback is error");
        return;
    }
    innerAsyncContext->result = BoomerangManager::GetInstance().NotifyMetadataBindingEvent(bundleName, callback);
}

void BoomerangNapi::NotifyMetadataCompleteCB(napi_env env, napi_status status, void* data)
{
    std::lock_guard<std::mutex> guard(mutex_);
    auto outerAsyncContext = static_cast<AsyncContext*>(data);
    int32_t result = static_cast<int32_t>(outerAsyncContext->result);
    if (result != RET_OK) {
        ProcessErrorResult(env, result, HANDLER_FAILD, outerAsyncContext);
    }
    napi_delete_async_work(outerAsyncContext->env, outerAsyncContext->work);
    delete outerAsyncContext;
    outerAsyncContext = nullptr;
}
 
void BoomerangNapi::EncodeImageExecuteCB(napi_env env, void* data)
{
    std::lock_guard<std::mutex> guard(encodeMutex_);
    auto  innerAsyncContext = static_cast<AsyncContext*>(data);
    std::string metadata = static_cast<std::string>(innerAsyncContext->metadata);
    sptr<IRemoteBoomerangCallback> callback = static_cast<sptr<IRemoteBoomerangCallback>>(innerAsyncContext->callback);
    auto pixelMap = static_cast<std::shared_ptr<Media::PixelMap>>(innerAsyncContext->pixelMap);
    if (metadata.empty() || callback == nullptr || pixelMap == nullptr) {
        FI_HILOGE("bundleName or callback or pixelMap is error");
        return;
    }
    innerAsyncContext->result = BoomerangManager::GetInstance().BoomerangEncodeImage(pixelMap, metadata, callback);
}

void BoomerangNapi::EncodeImageCompleteCB(napi_env env, napi_status status, void* data)
{
    std::lock_guard<std::mutex> guard(encodeMutex_);
    auto outerAsyncContext = static_cast<AsyncContext*>(data);
    int32_t result = static_cast<int32_t>(outerAsyncContext->result);
    ProcessErrorResult(env, result, ENCODE_FAILED, outerAsyncContext);
    napi_delete_async_work(outerAsyncContext->env, outerAsyncContext->work);
    delete outerAsyncContext;
    outerAsyncContext = nullptr;
}

void BoomerangNapi::DecodeImageExecuteCB(napi_env env, void* data)
{
    AsyncContext*  innerAsyncContext = static_cast<AsyncContext*>(data);
    auto pixelMap = static_cast<std::shared_ptr<Media::PixelMap>>(innerAsyncContext->pixelMap);
    sptr<IRemoteBoomerangCallback> callback = static_cast<sptr<IRemoteBoomerangCallback>>(innerAsyncContext->callback);
    if (pixelMap == nullptr || callback == nullptr) {
        FI_HILOGE("callback or pixelMap is error");
        return;
    }
    innerAsyncContext->result = BoomerangManager::GetInstance().BoomerangDecodeImage(pixelMap, callback);
}
 
void BoomerangNapi::DecodeImageCompleteCB(napi_env env, napi_status status, void* data)
{
    std::lock_guard<std::mutex> guard(encodeMutex_);
    auto outerAsyncContext = static_cast<AsyncContext*>(data);
    int32_t result = static_cast<int32_t>(outerAsyncContext->result);
    if (result != RET_OK) {
        ProcessErrorResult(env, result, DECODE_FAILED, outerAsyncContext);
    }
    napi_delete_async_work(outerAsyncContext->env, outerAsyncContext->work);
    delete outerAsyncContext;
    outerAsyncContext = nullptr;
}

bool BoomerangNapi::IsSameHandle(napi_env env, napi_value handle, napi_ref ref)
{
    CALL_INFO_TRACE;
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    CHKPF(scope);
    napi_value handlerTemp = nullptr;
    CHKRF_SCOPE(env, napi_get_reference_value(env, ref, &handlerTemp), GET_REFERENCE_VALUE, scope);
    bool isEqual = false;
    CHKRF_SCOPE(env, napi_strict_equals(env, handle, handlerTemp, &isEqual), STRICT_EQUALS, scope);
    napi_close_handle_scope(env, scope);
    return isEqual;
}

int32_t BoomerangNapi::ConvertTypeToInt(const std::string &type)
{
    if (type == "operationSubmitMetadata") {
        return BoomerangType::BOOMERANG_TYPE_BOOMERANG;
    } else {
        return BoomerangType::BOOMERANG_TYPE_INVALID;
    }
}

void BoomerangNapi::ProcessErrorResult(napi_env env, int32_t result, int32_t code, AsyncContext* asyncContext)
{
    if (env == nullptr || asyncContext == nullptr || !asyncContext->deferred) {
        FI_HILOGE("Parameter error for %{public}d. Please check", code);
        return;
    }

    if (result == RET_OK) {
        FI_HILOGI("handler requset success");
        return;
    }

    napi_value intValue;
    int32_t callResult = (result == RET_ERR) ? code : result;
    napi_create_int32(env, callResult, &intValue);
    FI_HILOGI("callback the error result:%{public}d", callResult);
    napi_reject_deferred(env, asyncContext->deferred, intValue);
}

napi_value BoomerangNapi::Init(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("on", Register),
        DECLARE_NAPI_STATIC_FUNCTION("off", UnRegister),
        DECLARE_NAPI_STATIC_FUNCTION("notifyMetadataBindingEvent", NotifyMetadataBindingEvent),
        DECLARE_NAPI_STATIC_FUNCTION("submitMetadata", SubmitMetadata),
        DECLARE_NAPI_STATIC_FUNCTION("encodeImage", BoomerangEncodeImage),
        DECLARE_NAPI_STATIC_FUNCTION("decodeImage", DecodeImage),
    };
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
    napi_value ret = BoomerangNapi::Init(env, exports);
    return ret;
}
EXTERN_C_END

/*
 * Module definition
 */
static napi_module g_module = {.nm_version = 1,
    .nm_flags = 0,
    .nm_filename = "multimodalAwareness.metadataBinding",
    .nm_register_func = DeviceStatusInit,
    .nm_modname = "multimodalAwareness.metadataBinding",
    .nm_priv = (static_cast<void *>(0)),
    .reserved = {0}};

/*
 * Module registration
 */
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&g_module);
}
}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS