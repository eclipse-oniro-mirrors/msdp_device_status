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

#ifndef OHOS_ANI_ONSCREENAWARENESS_H
#define OHOS_ANI_ONSCREENAWARENESS_H

#include "ohos.multimodalAwareness.onScreen.proj.hpp"
#include "ohos.multimodalAwareness.onScreen.impl.hpp"
#include "ani.h"
#include "fi_log.h"
#include <map>
#include <stdexcept>
#include <set>
#include "taihe/runtime.hpp"
#include "on_screen_manager.h"
#include "on_screen_callback_stub.h"

namespace ANI::MultimodalAwareness {

void RegisterAwarenessCallback(ohos::multimodalAwareness::onScreen::OnscreenAwarenessCap capability,
    taihe::callback_view<void(ohos::multimodalAwareness::onScreen::OnscreenAwarenessInfo const &)> callback,
    taihe::optional_view<ohos::multimodalAwareness::onScreen::OnscreenAwarenessOptions> options);
void UnregisterAwarenessCallback(ohos::multimodalAwareness::onScreen::OnscreenAwarenessCap capability,
    taihe::optional_view<taihe::callback<void(
    ohos::multimodalAwareness::onScreen::OnscreenAwarenessInfo const &)>> callback);
ohos::multimodalAwareness::onScreen::OnscreenAwarenessInfo TriggerSync(
    ohos::multimodalAwareness::onScreen::OnscreenAwarenessCap capability,
    taihe::optional_view<ohos::multimodalAwareness::onScreen::OnscreenAwarenessOptions> options);
} // namespace ANI::MultimodalAwareness
#endif // OHOS_ANI_ONSCREENAWARENESS_H
