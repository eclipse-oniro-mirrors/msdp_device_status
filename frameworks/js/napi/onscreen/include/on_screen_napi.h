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

#ifndef ONSCREEN_NAPI_H
#define ONSCREEN_NAPI_H

#include <uv.h>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "on_screen_callback_stub.h"
#include "on_screen_data.h"
#include "on_screen_manager.h"
#include "on_screen_napi_data.h"
#include "pixel_map_napi.h"
#include "screen_event_napi.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
class OnScreenAwarenessCallback : public OnScreenCallbackStub {
public:
    explicit OnScreenAwarenessCallback(napi_env env) : env_(env) {}
    ~OnScreenAwarenessCallback();
    void OnScreenAwareness(const OnscreenAwarenessInfo& info) override;

public:
    sptr<IRemoteOnScreenCallback> callback;
    std::set<napi_ref> onRef;
    napi_env env_ { nullptr };
};

class OnScreenNapi {
public:
    explicit OnScreenNapi(napi_env env, napi_value thisVar);
    ~OnScreenNapi();

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value GetPageContentNapi(napi_env env, napi_callback_info info);
    static napi_value SendControlEventNapi(napi_env env, napi_callback_info info);
    // perception
    static napi_value RegisterAwarenessCallback(napi_env env, napi_callback_info info);
    static napi_value UnregisterAwarenessCallback(napi_env env, napi_callback_info info);
    static napi_value Trigger(napi_env env, napi_callback_info info);
    static bool ConstructAwarenessInfoObj(napi_env env, napi_value &awarenessInfoObj,
        const OnscreenAwarenessInfo& info);

private:
    static bool ConstructOnScreen(napi_env env, napi_value jsThis);
    static bool GetContentOption(napi_env env, napi_value *args, size_t argc, ContentOption &option);
    static bool GetControlEvent(napi_env env, napi_value *args, size_t argc, ControlEvent &event);
    // utils
    static bool SetInt32Property(napi_env env, napi_value targetObj, int32_t value, const char *propName);
    static bool SetInt64Property(napi_env env, napi_value targetObj, int64_t value, const char *propName);
    static bool SetStringProperty(napi_env env, napi_value targetObj, const std::string &value, const char *propName);
    static bool ConstructParagraphObj(napi_env env, napi_value &retObj, const Paragraph &value);
    static bool SetParagraphVecProperty(napi_env env, napi_value targetObj, const std::vector<Paragraph> paragraphs,
        const char *propName);
    static bool GetInt32FromJs(napi_env env, const napi_value &value, const std::string &field,
        int32_t &result, bool isNecessary);
    static bool GetInt64FromJs(napi_env env, const napi_value &value, const std::string &field,
        int64_t &result, bool isNecessary);
    static bool GetBoolFromJs(napi_env env, const napi_value &value, const std::string &field,
        bool &result, bool isNecessary);
    static bool SetPropertyName(napi_env env, napi_value targetObj, const char *propName, napi_value propValue);
    static bool ConstructPageContentObj(napi_env env, napi_value &pageContentObj,
        const GetPageContentAsyncContext* ctx);
    // GetPageContent
    static bool GetPageContentExec(GetPageContentAsyncContext *asyncContext);
    static void GetPageContentExecCB(napi_env env, void *data);
    static void GetPageContentCompCB(napi_env env, napi_status status, void *data);
    // SendControlEvent
    static bool SendControlEventExec(SendControlEventAsyncContext *asyncContext);
    static void SendControlEventExecCB(napi_env env, void *data);
    static void SendControlEventCompCB(napi_env env, napi_status status, void *data);

    // perception
    static bool GetAwarenessCap(napi_env env, napi_value awarenessCap, size_t argc, AwarenessCap &cap);
    static bool GetAwarenessOption(napi_env env, napi_value awarenessOption, AwarenessOptions &option);
    static bool HandleOptionElement(napi_env env, std::string strName, napi_value elementValue,
        AwarenessOptions &option);
    static bool HandleOptionBool(napi_env env, std::string strName, napi_value boolValue, AwarenessOptions &option);
    static bool HandleOptionInt32(napi_env env, std::string strName, napi_value int32Value, AwarenessOptions &option);
    static bool HandleOptionInt64(napi_env env, std::string strName, napi_value int64Value, AwarenessOptions &option);
    static bool HandleOptionString(napi_env env, std::string strName, napi_value strValue, AwarenessOptions &option);
    static bool HandleOptionObject(napi_env env, std::string strName, napi_value objValue, AwarenessOptions &option);
    static bool HandleOptionArray(napi_env env, std::string strName, napi_value arrayValue, AwarenessOptions &option);

    static bool TransJsToStr(napi_env env, napi_value in, std::string &out);
    static bool IsMatchType(napi_env env, napi_value value, napi_valuetype type);
    static bool GetStringFromJs(napi_env env, const napi_value &value, const std::string &field, std::string &result);
    static bool GetPixelMapFromJs(napi_env env, const napi_value &value, const std::string &field,
        std::shared_ptr<Media::PixelMap> &result);
    static bool SetBoolProperty(napi_env env, napi_value targetObj, bool value, const char *propName);
    static bool IsValidCap(const std::vector<std::string>& capList);
    static bool CheckCapList(const std::vector<std::string>& capList);

    static bool TriggerExec(TriggerAsyncContext *asyncContext);
    static void TriggerExecCB(napi_env env, void *data);
    static void TriggerCompCB(napi_env env, napi_status status, void *data);
    static void UpsertScreenCallback(napi_env env, const AwarenessCap& cap, napi_ref handlerRef);
    static void RemoveScreenCallback(napi_env env, const AwarenessCap& cap, napi_ref handlerRef);
    static bool ConstructAwarenessEntityInfoVector(napi_env env, napi_value &retObj,
        const std::vector<OnscreenEntityInfo>& vec);
    static bool ConstructAwarenessEntityInfo(napi_env env, napi_value &jsEntity,
        const std::map<std::string, ValueObj>& infoMap);
    static bool ConstructValueObj(napi_env env, napi_value &jsValue, ValueObj valueObj);
    static bool ConstructStringVector(napi_env env, napi_value &jsValue, std::vector<std::string> strVector);
    static bool ConstructObjectVector(napi_env env, napi_value &jsValue,
        std::vector<OnScreen::AwarenessInfoImageId> objVector);

    napi_env env_;
};
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // ONSCREEN_NAPI_H