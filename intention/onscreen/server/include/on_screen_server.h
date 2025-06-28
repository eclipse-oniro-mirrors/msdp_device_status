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

#ifndef ON_SCREEN_SERVER_H
#define ON_SCREEN_SERVER_H

#include "bundle_mgr_interface.h"
#include "i_plugin.h"
#include "on_screen_data.h"
#include "window_manager.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
// TODO deathrepcient for bundlemgr
class OnScreenServer {
public:
    OnScreenServer() = default;
    virtual ~OnScreenServer() = default;
    int32_t GetPageContent(CallingContext &context, const ContentOption &option, PageContent &pageContent);
    int32_t SendControlEvent(CallingContext &context, const ControlEvent &event);
private:
    int32_t GetPageInfo(const std::string &window, const std::string &option, std::string &pageInfo);
    int32_t LoadHAExpandClient();
    int32_t UnloadHAExpandClient();
    int32_t ConnectBundleMgr();
    void ResetBundleMgr();
    int32_t ConstructPageContent(const ContentOption &option, const sptr<Rosen::WindowInfo> windowInfo,
        PageContent &pageContent);
    int32_t GetAppInfo(const sptr<Rosen::WindowInfo> windowInfo, AppInfo &appinfo);
    int32_t ContentUnderstand(const std::string pageInfo, PageContent &pageContent);
    int32_t GetPageLink(const std::string pageInfo, PageContent &pageContent);
    int32_t GetParagraphs(const std::string pageInfo, PageContent &pageContent);

    sptr<AppExecFwk::IBundleMgr> bundleMgrProxy_ = nullptr;
};
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // ON_SCREEN_SERVER_H