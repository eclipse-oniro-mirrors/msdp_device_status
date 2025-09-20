/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "drag_drawing.h"

#include <atomic>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <limits>
#include <shared_mutex>
#include <string>
#include <unistd.h>

#include <dlfcn.h>
#include "display_info.h"

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#include "hitrace_meter.h"
#endif // OHOS_BUILD_ENABLE_ARKUI_X
#include "include/core/SkTextBlob.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "input_manager.h"
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#include "parameters.h"
#endif // OHOS_BUILD_ENABLE_ARKUI_X
#include "pointer_event.h"
#include "pointer_style.h"
#include "render/rs_filter.h"
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#include "screen_manager.h"
#endif // OHOS_BUILD_ENABLE_ARKUI_X
#include "string_ex.h"
#include "transaction/rs_interfaces.h"
#include "ui/rs_surface_extractor.h"
#include "ui/rs_surface_node.h"
#include "ui/rs_ui_director.h"

#include "animation_curve.h"
#include "devicestatus_define.h"
#include "drag_data_manager.h"
#ifdef MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
#include "drag_hisysevent.h"
#endif // MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
#include "include/util.h"

#undef LOG_TAG
#define LOG_TAG "DragDrawing"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t BASELINE_DENSITY { 160 };
constexpr int32_t DEVICE_INDEPENDENT_PIXEL { 40 };
constexpr int32_t MAGIC_INDEPENDENT_PIXEL { 25 };
constexpr int32_t MAGIC_STYLE_OPT { 1 };
constexpr int32_t DRAG_NUM_ONE { 1 };
constexpr int32_t STRING_PX_LENGTH { 2 };
constexpr int32_t EIGHT_SIZE { 8 };
constexpr int32_t TWELVE_SIZE { 12 };
constexpr int64_t START_TIME { 181154000809 };
constexpr int64_t INTERVAL_TIME { 16666667 };
constexpr int32_t SVG_WIDTH { 40 };
constexpr float SCALE_THRESHOLD_EIGHT { 1.0F * INT32_MAX / (SVG_WIDTH + EIGHT_SIZE) };
constexpr float SCALE_THRESHOLD_TWELVE { 1.0F * INT32_MAX / (SVG_WIDTH + TWELVE_SIZE) };
constexpr int32_t SUCCESS_ANIMATION_DURATION { 300 };
constexpr int32_t ANIMATION_DURATION { 400 };
constexpr int32_t VIEW_BOX_POS { 2 };
constexpr int32_t BACKGROUND_FILTER_INDEX { 0 };
constexpr int32_t ASYNC_ROTATE_TIME { 150 };
constexpr int32_t PIXEL_MAP_INDEX { 1 };
constexpr int32_t DRAG_STYLE_INDEX { 2 };
constexpr int32_t MOUSE_ICON_INDEX { 3 };
constexpr int32_t SHORT_DURATION { 55 };
constexpr int32_t LONG_DURATION { 90 };
constexpr int32_t FIRST_PIXELMAP_INDEX { 0 };
constexpr int32_t SECOND_PIXELMAP_INDEX { 1 };
constexpr int32_t LAST_SECOND_PIXELMAP { 2 };
constexpr int32_t LAST_THIRD_PIXELMAP { 3 };
constexpr size_t TOUCH_NODE_MIN_COUNT { 3 };
constexpr size_t MOUSE_NODE_MIN_COUNT { 4 };
constexpr float DEFAULT_SCALING { 1.0f };
constexpr float BEGIN_ALPHA { 1.0f };
constexpr float END_ALPHA { 0.0f };
constexpr float START_STYLE_ALPHA { 1.0f };
constexpr float END_STYLE_ALPHA { 0.0f };
constexpr float BEGIN_SCALE { 1.0f };
constexpr float END_SCALE_FAIL { 1.2f };
constexpr float END_SCALE_SUCCESS { 0.0f };
#ifndef OHOS_BUILD_PC_PRODUCT
constexpr float DEFAULT_PIVOT { 0.0f };
#else
constexpr int32_t DOT_PER_INCH { 160 };
#endif // OHOS_BUILD_PC_PRODUCT
constexpr float HALF_PIVOT { 0.5f };
constexpr float START_STYLE_SCALE { 1.0f };
constexpr float STYLE_CHANGE_SCALE { 1.1f };
constexpr float STYLE_MAX_SCALE { 1.2f };
constexpr float STYLE_END_SCALE { 1.0f };
constexpr float SVG_ORIGINAL_SIZE { 40.0f };
constexpr float DEFAULT_POSITION_X { 0.0f };
constexpr float BLUR_SIGMA_SCALE { 0.57735f };
constexpr float RADIUS_VP { 23.0f };
constexpr float DEFAULT_SATURATION { 1.05f };
constexpr float DEFAULT_BRIGHTNESS { 1.05f };
constexpr float INCREASE_RATIO { 1.22f };
constexpr float DRAG_WINDOW_POSITION_Z { 6999.0f };
constexpr float DEFAULT_ANGLE { 0.0f };
constexpr float POSITIVE_ANGLE { 8.0f };
constexpr float NEGATIVE_ANGLE { -8.0f };
constexpr float DEFAULT_ALPHA { 1.0f };
constexpr float FIRST_PIXELMAP_ALPHA { 0.6f };
constexpr float SECOND_PIXELMAP_ALPHA { 0.3f };
constexpr float HALF_RATIO { 0.5f };
constexpr float ROTATION_0 { 0.0f };
constexpr float ROTATION_90 { 90.0f };
constexpr float ROTATION_360 { 360.0f };
constexpr float ROTATION_270 { 270.0f };
constexpr float ZOOM_IN_SCALE { 1.03f };
constexpr float ZOOM_OUT_SCALE { 0.9f };
constexpr float ZOOM_END_SCALE { 1.0f };
#ifdef OHOS_ENABLE_PULLTHROW
constexpr float THROW_SLIP_TIME { 616.0f };
constexpr float BREATHE_TIME { 600.0f };
constexpr float BREATHE_REPEAT { 50 };
constexpr float BREATHE_SCALE { 0.1f };
constexpr float ZOOMOUT_PULLTHROW { 400.0f };
constexpr float APP_WIDTH { 110 };
#endif // OHOS_ENABLE_PULLTHROW
constexpr uint32_t TRANSPARENT_COLOR_ARGB { 0x00000000 };
constexpr int32_t DEFAULT_MOUSE_SIZE { 1 };
constexpr int32_t DEFAULT_COLOR_VALUE { 0 };
constexpr int32_t INVALID_COLOR_VALUE { -1 };
constexpr int32_t GLOBAL_WINDOW_ID { -1 };
constexpr int32_t MOUSE_DRAG_CURSOR_CIRCLE_STYLE { 41 };
constexpr int32_t CURSOR_CIRCLE_MIDDLE { 2 };
constexpr int32_t TWICE_SIZE { 2 };
constexpr int32_t NUM_ONE { 1 };
constexpr int32_t NUM_TWO { 2 };
constexpr int32_t NUM_FOUR { 4 };
constexpr int32_t ALPHA_DURATION { 350 };
constexpr int32_t DRAG_END_DURATION { 200 };
constexpr int32_t ZOOM_DURATION { 300 };
constexpr int32_t ZOOM_IN_DURATION { 350 };
constexpr int32_t ZOOM_OUT_DURATION { 250 };
const Rosen::RSAnimationTimingCurve CURVE =
    Rosen::RSAnimationTimingCurve::CreateCubicCurve(0.2f, 0.0f, 0.2f, 1.0f);
const Rosen::RSAnimationTimingCurve SPRING = Rosen::RSAnimationTimingCurve::CreateSpring(0.347f, 0.99f, 0.0f);
constexpr float DEFAULT_SPRING_RESPONSE = 0.347f;
constexpr float MIN_SPRING_RESPONSE = 0.001f;
constexpr float DEL_SPRING_RESPONSE = 0.005f;
constexpr float THRESHOLD_DISTANCE_SQUARE = 3.0f;
constexpr int32_t HEX_FF { 0xFF };
const std::string RENDER_THREAD_NAME { "os_dargRenderRunner" };
constexpr float BEZIER_000 { 0.00f };
constexpr float BEZIER_020 { 0.20f };
constexpr float BEZIER_030 { 0.30f };
constexpr float BEZIER_033 { 0.33f };
constexpr float BEZIER_040 { 0.40f };
constexpr float BEZIER_060 { 0.60f };
constexpr float BEZIER_067 { 0.67f };
constexpr float BEZIER_100 { 1.00f };
constexpr float MIN_OPACITY { 0.0f };
constexpr float MAX_OPACITY { 1.0f };
constexpr int32_t TIME_DRAG_CHANGE_STYLE { 50 };
constexpr int32_t TIME_DRAG_STYLE { 100 };
constexpr int32_t TIME_STOP_FAIL_WINDOW { 125 };
constexpr int32_t TIME_STOP_SUCCESS_WINDOW { 250 };
constexpr int32_t TIME_STOP_SUCCESS_STYLE { 150 };
constexpr int32_t TIME_STOP { 0 };
constexpr int64_t TIME_SLEEP { 30000 };
constexpr int32_t INTERRUPT_SCALE { 15 };
constexpr int32_t TIMEOUT_MS { 500 };
constexpr float MAX_SCREEN_WIDTH_SM { 600.0f };
constexpr float MAX_SCREEN_WIDTH_MD { 840.0f };
constexpr float MAX_SCREEN_WIDTH_LG { 1440.0f };
constexpr float SCALE_TYPE_FIRST = 2.0;
constexpr float SCALE_TYPE_SECOND = 3.0;
constexpr float SCALE_TYPE_THIRD = 4.0;
const std::string THREAD_NAME { "os_AnimationEventRunner" };
const std::string SUPER_HUB_THREAD_NAME { "os_SuperHubEventRunner" };
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
const std::string COPY_DRAG_PATH { "/system/etc/device_status/drag_icon/Copy_Drag.svg" };
const std::string COPY_ONE_DRAG_PATH { "/system/etc/device_status/drag_icon/Copy_One_Drag.svg" };
const std::string FORBID_DRAG_PATH { "/system/etc/device_status/drag_icon/Forbid_Drag.svg" };
const std::string FORBID_ONE_DRAG_PATH { "/system/etc/device_status/drag_icon/Forbid_One_Drag.svg" };
const std::string MOVE_DRAG_PATH { "/system/etc/device_status/drag_icon/Move_Drag.svg" };
const std::string COPY_DRAG_RTL_PATH { "/system/etc/device_status/drag_icon/Copy_Drag_RTL.svg" };
const std::string COPY_ONE_DRAG_RTL_PATH { "/system/etc/device_status/drag_icon/Copy_One_Drag_RTL.svg" };
const std::string FORBID_DRAG_RTL_PATH { "/system/etc/device_status/drag_icon/Forbid_Drag_RTL.svg" };
const std::string FORBID_ONE_DRAG_RTL_PATH { "/system/etc/device_status/drag_icon/Forbid_One_Drag_RTL.svg" };
const std::string MOVE_DRAG_RTL_PATH { "/system/etc/device_status/drag_icon/Move_Drag_RTL.svg" };
#else
const std::string COPY_DRAG_NAME { "/base/media/Copy_Drag.svg" };
const std::string COPY_ONE_DRAG_NAME { "/base/media/Copy_One_Drag.svg" };
const std::string FORBID_DRAG_NAME { "/base/media/Forbid_Drag.svg" };
const std::string FORBID_ONE_DRAG_NAME { "/base/media/Forbid_One_Drag.svg" };
const std::string MOVE_DRAG_NAME { "/base/media/Move_Drag.svg" };
#endif // OHOS_BUILD_ENABLE_ARKUI_X
const std::string MOUSE_DRAG_DEFAULT_PATH { "/system/etc/device_status/drag_icon/Mouse_Drag_Default.svg" };
const std::string MOUSE_DRAG_MAGIC_DEFAULT_PATH { "/system/etc/device_status/drag_icon/Mouse_Drag_Magic_Default.svg" };
const std::string MOUSE_DRAG_CURSOR_CIRCLE_PATH { "/system/etc/device_status/drag_icon/Mouse_Drag_Cursor_Circle.png" };
const std::string DRAG_DROP_EXTENSION_SO_PATH { "/system/lib64/drag_drop_ext/libdrag_drop_ext.z.so" };
const std::string BIG_FOLDER_LABEL { "scb_folder" };
struct DrawingInfo g_drawingInfo;
static std::shared_mutex g_pixelMapLock;
struct DragData g_dragDataForSuperHub;

bool CheckNodesValid()
{
    FI_HILOGD("enter");
    if (g_drawingInfo.nodes.size() <= DRAG_STYLE_INDEX) {
        FI_HILOGE("The index is out of bounds, node size is %{public}zu", g_drawingInfo.nodes.size());
        return false;
    } else if (g_drawingInfo.nodes.empty() || g_drawingInfo.nodes[DRAG_STYLE_INDEX] == nullptr) {
        FI_HILOGE("Nodes invalid");
        return false;
    }

#ifndef OHOS_BUILD_PC_PRODUCT
    if ((g_drawingInfo.sourceType == MMI::PointerEvent::SOURCE_TYPE_MOUSE) &&
        (g_drawingInfo.nodes.size() < MOUSE_NODE_MIN_COUNT)) {
        FI_HILOGE("Nodes size invalid when mouse type, node size:%{public}zu", g_drawingInfo.nodes.size());
        return false;
    }
#endif // OHOS_BUILD_PC_PRODUCT

    if ((g_drawingInfo.sourceType == MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN) &&
        (g_drawingInfo.nodes.size() < TOUCH_NODE_MIN_COUNT)) {
        FI_HILOGE("Nodes size invalid when touchscreen type, node size:%{public}zu", g_drawingInfo.nodes.size());
        return false;
    }
    return true;
}

float GetScaling()
{
    if (g_drawingInfo.isExistScalingValue) {
        return g_drawingInfo.scalingValue;
    }
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#ifndef OHOS_BUILD_PC_PRODUCT
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDisplayById(g_drawingInfo.displayId);
    if (display == nullptr) {
        FI_HILOGD("Get display info failed, display:%{public}d", g_drawingInfo.displayId);
        display = Rosen::DisplayManager::GetInstance().GetDisplayById(0);
        if (display == nullptr) {
            FI_HILOGE("Get display info failed, display is nullptr");
            return DEFAULT_SCALING;
        }
    }
    int32_t deviceDpi = display->GetDpi();
#else
    sptr<Rosen::DisplayInfo> displayInfo =
        Rosen::DisplayManager::GetInstance().GetVisibleAreaDisplayInfoById(g_drawingInfo.displayId);
    if (displayInfo == nullptr) {
        FI_HILOGD("Get display info failed, display:%{public}d", g_drawingInfo.displayId);
        displayInfo = Rosen::DisplayManager::GetInstance().GetVisibleAreaDisplayInfoById(0);
        if (displayInfo == nullptr) {
            FI_HILOGE("Get display info failed, display is nullptr");
            return DEFAULT_SCALING;
        }
    }
    int32_t deviceDpi = displayInfo->GetVirtualPixelRatio() * DOT_PER_INCH;
#endif // OHOS_BUILD_PC_PRODUCT
#else
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDefaultDisplaySync();
    if (display == nullptr) {
        FI_HILOGE("Get display info failed, display is nullptr");
        return DEFAULT_SCALING;
    }
    sptr<Rosen::DisplayInfo> info = display->GetDisplayInfo();
    if (info == nullptr) {
        FI_HILOGE("Get info failed, info is nullptr");
        return DEFAULT_SCALING;
    }
    int32_t deviceDpi = info->GetDensityDpi();
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    FI_HILOGD("displayId:%{public}d, deviceDpi:%{public}d", g_drawingInfo.displayId, deviceDpi);
    if (deviceDpi < -std::numeric_limits<float>::epsilon()) {
        FI_HILOGE("Invalid deviceDpi:%{public}d", deviceDpi);
        return DEFAULT_SCALING;
    }
    g_drawingInfo.scalingValue = (1.0 * deviceDpi * DEVICE_INDEPENDENT_PIXEL / BASELINE_DENSITY) / SVG_ORIGINAL_SIZE;
    g_drawingInfo.isExistScalingValue = true;
    return g_drawingInfo.scalingValue;
}
} // namespace

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
int32_t DragDrawing::Init(const DragData &dragData, IContext* context, bool isLongPressDrag)
#else
int32_t DragDrawing::Init(const DragData &dragData, bool isLongPressDrag)
#endif // OHOS_BUILD_ENABLE_ARKUI_X
{
    FI_HILOGI("enter");
    int32_t checkDragDataResult = CheckDragData(dragData);
    if (INIT_SUCCESS != checkDragDataResult) {
        return checkDragDataResult;
    }
    InitDrawingInfo(dragData, isLongPressDrag);
    UpdateDragDataForSuperHub(dragData);
    CreateWindow();
    CHKPR(g_drawingInfo.surfaceNode, INIT_FAIL);
    if (InitLayer() != RET_OK) {
        FI_HILOGE("Init layer failed");
        return INIT_FAIL;
    }
    DragAnimationData dragAnimationData;
    if (!CheckNodesValid() || InitDragAnimationData(dragAnimationData) != RET_OK) {
        FI_HILOGE("Init drag animation data or check nodes valid failed");
        return INIT_FAIL;
    }
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    LoadDragDropLib();
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    OnStartDrag(dragAnimationData);
    if (!g_drawingInfo.multiSelectedNodes.empty()) {
        g_drawingInfo.isCurrentDefaultStyle = true;
        UpdateDragStyle(DragCursorStyle::MOVE);
    }
    if (g_drawingInfo.filterInfo.enableAnimation) {
        preDragPositionX_ = 0.0f;
        preDragPositionY_ = 0.0f;
        allAnimationCnt_ = 1;
    }
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    context_ = context;
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    CHKPR(rsUiDirector_, INIT_FAIL);
    if (g_drawingInfo.sourceType != MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        rsUiDirector_->SendMessages();
        return INIT_SUCCESS;
    }

#ifndef OHOS_BUILD_PC_PRODUCT
    if (DrawMouseIcon() != RET_OK) {
        FI_HILOGE("Draw mouse icon failed");
        return INIT_FAIL;
    }
#endif // OHOS_BUILD_PC_PRODUCT

    rsUiDirector_->SendMessages();
    FI_HILOGI("leave");
    return INIT_SUCCESS;
}

int32_t DragDrawing::CheckDragData(const DragData &dragData)
{
    if (g_drawingInfo.isRunning) {
        FI_HILOGE("Drag drawing is running, can not init again");
        return INIT_CANCEL;
    }
    if (dragData.shadowInfos.empty()) {
        FI_HILOGE("ShadowInfos is empty");
        return INIT_FAIL;
    }
    for (const auto &shadowInfo : dragData.shadowInfos) {
        CHKPR(shadowInfo.pixelMap, INIT_FAIL);
    }
    if ((dragData.sourceType != MMI::PointerEvent::SOURCE_TYPE_MOUSE) &&
        (dragData.sourceType != MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN)) {
        FI_HILOGE("Invalid sourceType:%{public}d", dragData.sourceType);
        return INIT_FAIL;
    }
    if (dragData.dragNum < 0) {
        FI_HILOGE("Invalid dragNum:%{public}d", dragData.dragNum);
        return INIT_FAIL;
    }
    return INIT_SUCCESS;
}

void DragDrawing::Draw(int32_t displayId, int32_t displayX, int32_t displayY, bool isNeedAdjustDisplayXY,
    bool isMultiSelectedAnimation)
{
    if (screenRotateState_) {
        FI_HILOGD("Doing screen rotation, ignore draw drag window");
        return;
    }
    if (isRunningRotateAnimation_) {
        FI_HILOGD("Doing rotate drag window animate, ignore draw drag window");
        return;
    }
    if (displayId < 0) {
        FI_HILOGE("Invalid displayId:%{public}d", displayId);
        return;
    }
    int32_t mousePositionX = displayX;
    int32_t mousePositionY = displayY;
    if (isNeedAdjustDisplayXY) {
        RotateDisplayXY(displayX, displayY);
        mousePositionX = displayX;
        mousePositionY = displayY;
        g_drawingInfo.currentPositionX = static_cast<float>(displayX);
        g_drawingInfo.currentPositionY = static_cast<float>(displayY);
        AdjustRotateDisplayXY(displayX, displayY);
    }
    g_drawingInfo.displayId = displayId;
    g_drawingInfo.displayX = displayX;
    g_drawingInfo.displayY = displayY;
    if (displayX < 0) {
        g_drawingInfo.displayX = 0;
    }
    if (displayY < 0) {
        g_drawingInfo.displayY = 0;
    }
    int32_t adjustSize = TWELVE_SIZE * GetScaling();
    int32_t positionX = g_drawingInfo.displayX + g_drawingInfo.pixelMapX;
    int32_t positionY = g_drawingInfo.displayY + g_drawingInfo.pixelMapY - adjustSize;
    CHKPV(g_drawingInfo.parentNode);
    auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
    CHKPV(currentPixelMap);
    g_drawingInfo.parentNode->SetBounds(positionX, positionY, currentPixelMap->GetWidth(),
        currentPixelMap->GetHeight() + adjustSize);
    g_drawingInfo.parentNode->SetFrame(positionX, positionY, currentPixelMap->GetWidth(),
        currentPixelMap->GetHeight() + adjustSize);
#ifndef OHOS_BUILD_PC_PRODUCT
    if (g_drawingInfo.sourceType == MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        DoDrawMouse(mousePositionX, mousePositionY);
    }
#endif // OHOS_BUILD_PC_PRODUCT
    if (!g_drawingInfo.multiSelectedNodes.empty() && !g_drawingInfo.multiSelectedPixelMaps.empty()) {
        MultiSelectedAnimation(positionX, positionY, adjustSize, isMultiSelectedAnimation);
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void DragDrawing::UpdateDragNodeBoundsAndFrame(float x, float y, float w, float h)
{
    auto parentNode = g_drawingInfo.parentNode;
    CHKPV(parentNode);
    if (!g_drawingInfo.filterInfo.enableAnimation) {
        parentNode->SetBounds(x, y, w, h);
        parentNode->SetFrame(x, y, w, h);
        return;
    }
    allAnimationCnt_++;
    auto springResponse =
        std::max(DEFAULT_SPRING_RESPONSE - DEL_SPRING_RESPONSE * allAnimationCnt_, MIN_SPRING_RESPONSE);
    auto distance = (preDragPositionX_ - x) * (preDragPositionX_ - x) +
        (preDragPositionY_ - y) * (preDragPositionY_ - y);
    preDragPositionX_ = x;
    preDragPositionY_ = y;
    if (springResponse <= MIN_SPRING_RESPONSE && distance < THRESHOLD_DISTANCE_SQUARE) {
        g_drawingInfo.filterInfo.enableAnimation = false;
    }
    Rosen::RSAnimationTimingProtocol protocol;
    protocol.SetDuration(ANIMATION_DURATION);
    const Rosen::RSAnimationTimingCurve curve =
        Rosen::RSAnimationTimingCurve::CreateSpring(springResponse, 0.99f, 0.0f);
    Rosen::RSNode::Animate(protocol, curve, [&]() {
        CHKPV(parentNode);
        parentNode->SetBounds(x, y, w, h);
        parentNode->SetFrame(x, y, w, h);
    });
}

void DragDrawing::UpdateDragPosition(int32_t displayId, float displayX, float displayY)
{
    if (screenRotateState_) {
        FI_HILOGD("Doing screen rotation, ignore update drag position");
        return;
    }
    if (displayId < 0) {
        FI_HILOGE("Invalid displayId:%{public}d", displayId);
        return;
    }
    RotatePosition(displayX, displayY);
    g_drawingInfo.currentPositionX = displayX;
    g_drawingInfo.currentPositionY = displayY;
    g_drawingInfo.displayId = displayId;
    g_drawingInfo.displayX = static_cast<int32_t>(displayX);
    g_drawingInfo.displayY = static_cast<int32_t>(displayY);
#ifndef OHOS_BUILD_PC_PRODUCT
    float mousePositionX = displayX;
    float mousePositionY = displayY;
#endif // OHOS_BUILD_PC_PRODUCT
    AdjustRotateDisplayXY(displayX, displayY);
    g_drawingInfo.x = displayX;
    g_drawingInfo.y = displayY;
    if (displayX < 0) {
        g_drawingInfo.displayX = 0;
    }
    if (displayY < 0) {
        g_drawingInfo.displayY = 0;
    }
    float adjustSize = TWELVE_SIZE * GetScaling();
    float positionX = g_drawingInfo.x + g_drawingInfo.pixelMapX;
    float positionY = g_drawingInfo.y + g_drawingInfo.pixelMapY - adjustSize;
    auto parentNode = g_drawingInfo.parentNode;
    auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
    CHKPV(parentNode);
    CHKPV(currentPixelMap);
    UpdateDragNodeBoundsAndFrame(positionX, positionY, currentPixelMap->GetWidth(),
        currentPixelMap->GetHeight() + adjustSize);
#ifndef OHOS_BUILD_PC_PRODUCT
    if (g_drawingInfo.sourceType == MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        UpdateMousePosition(mousePositionX, mousePositionY);
    }
#endif // OHOS_BUILD_PC_PRODUCT
    if (!g_drawingInfo.multiSelectedNodes.empty() && !g_drawingInfo.multiSelectedPixelMaps.empty()) {
        DoMultiSelectedAnimation(positionX, positionY, adjustSize);
    }
    if (rsUiDirector_ != nullptr) {
        rsUiDirector_->SendMessages();
    } else {
        FI_HILOGE("rsUiDirector_ is nullptr");
    }
}

void DragDrawing::DoMultiSelectedAnimation(float positionX, float positionY, float adjustSize,
    bool isMultiSelectedAnimation)
{
    if (isMultiSelectedAnimation) {
        isMultiSelectedAnimation = needMultiSelectedAnimation_;
    }
    size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
    size_t multiSelectedPixelMapsSize = g_drawingInfo.multiSelectedPixelMaps.size();
    for (size_t i = 0; (i < multiSelectedNodesSize) && (i < multiSelectedPixelMapsSize); ++i) {
        std::shared_ptr<Rosen::RSCanvasNode> multiSelectedNode = g_drawingInfo.multiSelectedNodes[i];
        std::shared_ptr<Media::PixelMap> multiSelectedPixelMap = g_drawingInfo.multiSelectedPixelMaps[i];
        auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
        CHKPV(currentPixelMap);
        CHKPV(multiSelectedNode);
        CHKPV(multiSelectedPixelMap);
        float multiSelectedPositionX = positionX + (static_cast<float>(currentPixelMap->GetWidth()) / TWICE_SIZE) -
            (static_cast<float>(multiSelectedPixelMap->GetWidth()) / TWICE_SIZE);
        float multiSelectedPositionY = positionY + (static_cast<float>(currentPixelMap->GetHeight()) / TWICE_SIZE) -
            (static_cast<float>(multiSelectedPixelMap->GetHeight()) / TWICE_SIZE - adjustSize);
        if (isMultiSelectedAnimation) {
            Rosen::RSAnimationTimingProtocol protocol;
            if (i == FIRST_PIXELMAP_INDEX) {
                protocol.SetDuration(SHORT_DURATION);
            } else {
                protocol.SetDuration(LONG_DURATION);
            }
            Rosen::RSNode::Animate(protocol, Rosen::RSAnimationTimingCurve::EASE_IN_OUT, [&]() {
                multiSelectedNode->SetBounds(multiSelectedPositionX, multiSelectedPositionY,
                    multiSelectedPixelMap->GetWidth(), multiSelectedPixelMap->GetHeight());
                multiSelectedNode->SetFrame(multiSelectedPositionX, multiSelectedPositionY,
                    multiSelectedPixelMap->GetWidth(), multiSelectedPixelMap->GetHeight());
            }, []() { FI_HILOGD("DoMultiSelectedAnimation end"); });
        } else {
            multiSelectedNode->SetBounds(multiSelectedPositionX, multiSelectedPositionY,
                multiSelectedPixelMap->GetWidth(), multiSelectedPixelMap->GetHeight());
            multiSelectedNode->SetFrame(multiSelectedPositionX, multiSelectedPositionY,
                multiSelectedPixelMap->GetWidth(), multiSelectedPixelMap->GetHeight());
        }
    }
}

int32_t DragDrawing::UpdateDragStyle(DragCursorStyle style)
{
    FI_HILOGD("style:%{public}d", style);
    if ((style < DragCursorStyle::DEFAULT) || (style > DragCursorStyle::MOVE)) {
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#ifdef MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
        DragDFX::WriteUpdateDragStyle(style, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
#endif // MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
#endif // OHOS_BUILD_ENABLE_ARKUI_X
        FI_HILOGE("Invalid style:%{public}d", style);
        return RET_ERR;
    }
    if ((style == DragCursorStyle::DEFAULT) ||
        ((style == DragCursorStyle::MOVE) && (g_drawingInfo.currentDragNum == DRAG_NUM_ONE))) {
        return UpdateDefaultDragStyle(style);
    }
    return UpdateValidDragStyle(style);
}

int32_t DragDrawing::UpdateShadowPic(const ShadowInfo &shadowInfo)
{
    FI_HILOGD("enter");
    CHKPR(shadowInfo.pixelMap, RET_ERR);
    DragDrawing::UpdataGlobalPixelMapLocked(shadowInfo.pixelMap);
    g_drawingInfo.pixelMapX = shadowInfo.x;
    g_drawingInfo.pixelMapY = shadowInfo.y;
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return RET_ERR;
    }
    if (g_drawingInfo.nodes.size() <= PIXEL_MAP_INDEX) {
        FI_HILOGE("The index is out of bounds, node size is %{public}zu", g_drawingInfo.nodes.size());
        return RET_ERR;
    }
    std::shared_ptr<Rosen::RSCanvasNode> shadowNode = g_drawingInfo.nodes[PIXEL_MAP_INDEX];
    CHKPR(shadowNode, RET_ERR);
    DrawShadow(shadowNode);
    float scalingValue = GetScaling();
    if (SCALE_THRESHOLD_TWELVE < scalingValue || fabsf(SCALE_THRESHOLD_TWELVE - scalingValue) < EPSILON) {
        FI_HILOGE("Invalid scalingValue:%{public}f", scalingValue);
        return RET_ERR;
    }
#ifndef OHOS_BUILD_PC_PRODUCT
    if (g_drawingInfo.sourceType == MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        DrawMouseIcon();
    }
#endif // OHOS_BUILD_PC_PRODUCT
    ProcessFilter();
    Draw(g_drawingInfo.displayId, g_drawingInfo.displayX, g_drawingInfo.displayY, false);
    Rosen::Rotation rotation = GetRotation(g_drawingInfo.displayId);
    RotateDragWindow(rotation);
    Rosen::RSTransaction::FlushImplicitTransaction();
    CHKPR(rsUiDirector_, RET_ERR);
    rsUiDirector_->SendMessages();
    FI_HILOGD("leave");
    return RET_OK;
}

int32_t DragDrawing::UpdatePixelMapsAngleAndAlpha()
{
    FI_HILOGD("enter");
    size_t mulNodesSize = g_drawingInfo.multiSelectedNodes.size();
    if (mulNodesSize <= 0) {
        FI_HILOGE("No pixelmap add");
        return RET_ERR;
    }
    if (mulNodesSize == 1) {
        g_drawingInfo.multiSelectedNodes.front()->SetRotation(POSITIVE_ANGLE);
        g_drawingInfo.multiSelectedNodes.front()->SetAlpha(FIRST_PIXELMAP_ALPHA);
    } else if (mulNodesSize == LAST_SECOND_PIXELMAP) {
        g_drawingInfo.multiSelectedNodes.back()->SetRotation(NEGATIVE_ANGLE);
        g_drawingInfo.multiSelectedNodes.back()->SetAlpha(SECOND_PIXELMAP_ALPHA);
    } else {
        g_drawingInfo.rootNode->RemoveChild(g_drawingInfo.multiSelectedNodes[mulNodesSize - LAST_THIRD_PIXELMAP]);
        g_drawingInfo.multiSelectedNodes[mulNodesSize - LAST_SECOND_PIXELMAP ]->SetRotation(POSITIVE_ANGLE);
        g_drawingInfo.multiSelectedNodes[mulNodesSize - LAST_SECOND_PIXELMAP ]->SetAlpha(FIRST_PIXELMAP_ALPHA);
        g_drawingInfo.multiSelectedNodes.back()->SetRotation(NEGATIVE_ANGLE);
        g_drawingInfo.multiSelectedNodes.back()->SetAlpha(SECOND_PIXELMAP_ALPHA);
    }
    FI_HILOGD("leave");
    return RET_OK;
}

int32_t DragDrawing::UpdatePixeMapDrawingOrder()
{
    FI_HILOGD("enter");
    std::shared_ptr<Rosen::RSCanvasNode> pixelMapNode = g_drawingInfo.nodes[PIXEL_MAP_INDEX];
    std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
    CHKPR(pixelMapNode, RET_ERR);
    CHKPR(dragStyleNode, RET_ERR);
    CHKPR(g_drawingInfo.parentNode, RET_ERR);
    CHKPR(g_drawingInfo.rootNode, RET_ERR);
    g_drawingInfo.multiSelectedNodes.emplace_back(pixelMapNode);
    g_drawingInfo.parentNode->RemoveChild(dragStyleNode);
    g_drawingInfo.parentNode->RemoveChild(pixelMapNode);

    int32_t adjustSize = TWELVE_SIZE * GetScaling();
    int32_t positionX = g_drawingInfo.displayX + g_drawingInfo.pixelMapX;
    int32_t positionY = g_drawingInfo.displayY + g_drawingInfo.pixelMapY - adjustSize;
    auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
    int32_t pixelMapWidth = currentPixelMap->GetWidth();
    int32_t pixelMapHeight = currentPixelMap->GetHeight();
    pixelMapNode->SetBounds(positionX, positionY + adjustSize, pixelMapWidth, pixelMapHeight);
    pixelMapNode->SetFrame(positionX, positionY + adjustSize, pixelMapWidth, pixelMapHeight);

    std::shared_ptr<Rosen::RSCanvasNode> addSelectedNode = Rosen::RSCanvasNode::Create();
    CHKPR(addSelectedNode, RET_ERR);
    g_drawingInfo.nodes[PIXEL_MAP_INDEX] = addSelectedNode;
    g_drawingInfo.parentNode->AddChild(addSelectedNode);
    g_drawingInfo.parentNode->AddChild(dragStyleNode);
    g_drawingInfo.rootNode->AddChild(g_drawingInfo.multiSelectedNodes.back());
    g_drawingInfo.rootNode->RemoveChild(g_drawingInfo.parentNode);
    g_drawingInfo.rootNode->AddChild(g_drawingInfo.parentNode);
#ifndef OHOS_BUILD_PC_PRODUCT
    if (g_drawingInfo.sourceType == MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        std::shared_ptr<Rosen::RSCanvasNode> mouseIconNode = g_drawingInfo.nodes[MOUSE_ICON_INDEX];
        CHKPR(mouseIconNode, RET_ERR);
        g_drawingInfo.rootNode->RemoveChild(mouseIconNode);
        g_drawingInfo.rootNode->AddChild(mouseIconNode);
    }
#endif // OHOS_BUILD_PC_PRODUCT
    if (UpdatePixelMapsAngleAndAlpha() != RET_OK) {
        FI_HILOGE("setPixelMapsAngleAndAlpha failed");
        return RET_ERR;
    }
    DrawShadow(pixelMapNode);
    FI_HILOGD("leave");
    return RET_OK;
}

int32_t DragDrawing::AddSelectedPixelMap(std::shared_ptr<OHOS::Media::PixelMap> pixelMap)
{
    FI_HILOGD("enter");
    CHKPR(pixelMap, RET_ERR);
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return RET_ERR;
    }

    auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
    g_drawingInfo.multiSelectedPixelMaps.emplace_back(currentPixelMap);
    DragDrawing::UpdataGlobalPixelMapLocked(pixelMap);
    if (UpdatePixeMapDrawingOrder() != RET_OK) {
        FI_HILOGE("Update pixeMap drawing order failed");
        return RET_ERR;
    }
    Draw(g_drawingInfo.displayId, g_drawingInfo.displayX, g_drawingInfo.displayY, false);
    g_drawingInfo.currentDragNum = g_drawingInfo.multiSelectedPixelMaps.size() + 1;
    if (UpdateDragStyle(g_drawingInfo.currentStyle) != RET_OK) {
        FI_HILOGE("Update drag style failed");
        return RET_ERR;
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
    FI_HILOGD("leave");
    return RET_OK;
}

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
void DragDrawing::OnDragSuccess(IContext* context)
#else
void DragDrawing::OnDragSuccess()
#endif // OHOS_BUILD_ENABLE_ARKUI_X
{
    FI_HILOGI("enter");
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return;
    }
    if (g_drawingInfo.nodes.size() <= PIXEL_MAP_INDEX || g_drawingInfo.nodes.size() <= DRAG_STYLE_INDEX) {
        FI_HILOGE("The index is out of bounds, node size is %{public}zu", g_drawingInfo.nodes.size());
        return;
    }
    std::shared_ptr<Rosen::RSCanvasNode> shadowNode = g_drawingInfo.nodes[PIXEL_MAP_INDEX];
    CHKPV(shadowNode);
    std::shared_ptr<Rosen::RSCanvasNode> styleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
    CHKPV(styleNode);
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    g_drawingInfo.context = context;
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    OnStopDragSuccess(shadowNode, styleNode);
    FI_HILOGI("leave");
}

void DragDrawing::LongPressDragFail()
{
    FI_HILOGD("enter");
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return;
    }
    ResetAnimationParameter();
    Rosen::RSAnimationTimingProtocol protocolAlphaChanged;
    protocolAlphaChanged.SetDuration(DRAG_END_DURATION);
    Rosen::RSNode::Animate(protocolAlphaChanged, CURVE, [&]() {
        CHKPV(g_drawingInfo.parentNode);
        g_drawingInfo.parentNode->SetAlpha(END_ALPHA);
        if (!g_drawingInfo.multiSelectedNodes.empty()) {
            size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
            for (size_t i = 0; i < multiSelectedNodesSize; ++i) {
                std::shared_ptr<Rosen::RSCanvasNode> multiSelectedNode = g_drawingInfo.multiSelectedNodes[i];
                CHKPV(multiSelectedNode);
                multiSelectedNode->SetAlpha(END_ALPHA);
            }
        }
        std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
        CHKPV(dragStyleNode);
        dragStyleNode->SetAlpha(END_ALPHA);
    },  []() { FI_HILOGD("AlphaChanged end"); });

    Rosen::RSAnimationTimingProtocol protocolZoomIn;
    protocolZoomIn.SetDuration(DRAG_END_DURATION);
    Rosen::RSNode::Animate(protocolZoomIn, CURVE, [&]() {
        CHKPV(g_drawingInfo.parentNode);
        g_drawingInfo.parentNode->SetScale(ZOOM_END_SCALE);
        if (!g_drawingInfo.multiSelectedNodes.empty()) {
            size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
            for (size_t i = 0; i < multiSelectedNodesSize; ++i) {
                std::shared_ptr<Rosen::RSCanvasNode> multiSelectedNode = g_drawingInfo.multiSelectedNodes[i];
                CHKPV(multiSelectedNode);
                multiSelectedNode->SetScale(ZOOM_END_SCALE);
            }
        }
        std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
        CHKPV(dragStyleNode);
        dragStyleNode->SetScale(ZOOM_END_SCALE);
    },  [&]() {
        FI_HILOGD("ZoomIn end");
        ResetAnimationFlag();
    });
    g_drawingInfo.startNum = START_TIME;
    g_drawingInfo.needDestroyDragWindow = false;
    StartVsync();
    FI_HILOGD("leave");
}

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
void DragDrawing::OnDragFail(IContext* context, bool isLongPressDrag)
#else
void DragDrawing::OnDragFail()
#endif // OHOS_BUILD_ENABLE_ARKUI_X
{
    FI_HILOGI("enter");
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    if (isLongPressDrag) {
        LongPressDragFail();
        return;
    }
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    std::shared_ptr<Rosen::RSSurfaceNode> surfaceNode = g_drawingInfo.surfaceNode;
    CHKPV(surfaceNode);
    std::shared_ptr<Rosen::RSNode> rootNode = g_drawingInfo.rootNode;
    CHKPV(rootNode);
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    g_drawingInfo.context = context;
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    OnStopDragFail(surfaceNode, rootNode);
    FI_HILOGI("leave");
}

void DragDrawing::EraseMouseIcon()
{
    FI_HILOGI("enter");
    if (g_drawingInfo.nodes.size() < MOUSE_NODE_MIN_COUNT) {
        FI_HILOGE("Nodes size invalid, node size:%{public}zu", g_drawingInfo.nodes.size());
        return;
    }
    if (g_drawingInfo.nodes.size() <= MOUSE_ICON_INDEX) {
        FI_HILOGE("The index is out of bounds, node size is %{public}zu", g_drawingInfo.nodes.size());
        return;
    }
    std::shared_ptr<Rosen::RSCanvasNode> mouseIconNode = g_drawingInfo.nodes[MOUSE_ICON_INDEX];
    CHKPV(mouseIconNode);
    if (drawMouseIconModifier_ != nullptr) {
        mouseIconNode->RemoveModifier(drawMouseIconModifier_);
        drawMouseIconModifier_ = nullptr;
    }
    CHKPV(g_drawingInfo.rootNode);
    g_drawingInfo.rootNode->RemoveChild(mouseIconNode);
    CHKPV(rsUiDirector_);
    rsUiDirector_->SendMessages();
    FI_HILOGI("leave");
}

void DragDrawing::DestroyDragWindow()
{
    FI_HILOGI("enter");
    ResetParameter();
    RemoveModifier();
    ClearMultiSelectedData();
    if (!g_drawingInfo.nodes.empty()) {
        g_drawingInfo.nodes.clear();
        g_drawingInfo.nodes.shrink_to_fit();
    }
#ifdef OHOS_BUILD_INTERNAL_DROP_ANIMATION
    g_drawingInfo.curvesMaskNode = nullptr;
    g_drawingInfo.lightNode = nullptr;
#endif // OHOS_BUILD_INTERNAL_DROP_ANIMATION
    if (g_drawingInfo.parentNode != nullptr) {
        g_drawingInfo.parentNode->ClearChildren();
        g_drawingInfo.parentNode.reset();
        g_drawingInfo.parentNode = nullptr;
    }
    if (g_drawingInfo.rootNode != nullptr) {
        g_drawingInfo.rootNode->ClearChildren();
        g_drawingInfo.rootNode.reset();
        g_drawingInfo.rootNode = nullptr;
    }
    if (g_drawingInfo.surfaceNode != nullptr) {
        g_drawingInfo.surfaceNode->DetachFromWindowContainer(screenId_);
        screenId_ = 0;
        g_drawingInfo.displayId = -1;
        g_drawingInfo.surfaceNode = nullptr;
        Rosen::RSTransaction::FlushImplicitTransaction();
    }
#ifdef OHOS_BUILD_ENABLE_ARKUI_X
    CHKPV(callback_);
    callback_();
    window_ = nullptr;
    g_dragDataForSuperHub = {};
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    CHKPV(rsUiDirector_);
    rsUiDirector_->SetRoot(-1);
    rsUiDirector_->SendMessages();
    FI_HILOGI("leave");
}

void DragDrawing::UpdateDrawingState()
{
    FI_HILOGD("enter");
    g_drawingInfo.isRunning = false;
    FI_HILOGD("leave");
}

void DragDrawing::UpdateDragWindowState(
    bool visible, bool isZoomInAndAlphaChanged, const std::shared_ptr<Rosen::RSTransaction>& rsTransaction)
{
    CHKPV(g_drawingInfo.surfaceNode);
    if (visible && isZoomInAndAlphaChanged) {
        FI_HILOGI("UpdateDragWindowState in animation");
        if (!CheckNodesValid()) {
            FI_HILOGE("Check nodes valid failed");
            return;
        }
        CHKPV(g_drawingInfo.parentNode);
        g_drawingInfo.parentNode->SetAlpha(0.0f);
        if (!g_drawingInfo.multiSelectedNodes.empty()) {
            size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
            for (size_t i = 0; i < multiSelectedNodesSize; ++i) {
                std::shared_ptr<Rosen::RSCanvasNode> multiSelectedNode = g_drawingInfo.multiSelectedNodes[i];
                CHKPV(multiSelectedNode);
                multiSelectedNode->SetAlpha(0.0f);
            }
        }
        std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
        CHKPV(dragStyleNode);
        dragStyleNode->SetAlpha(0.0f);
        g_drawingInfo.surfaceNode->SetVisible(true);
        LongPressDragAnimation();
        Rosen::RSTransaction::FlushImplicitTransaction();
    } else {
        if (rsTransaction != nullptr) {
            Rosen::RSTransaction::FlushImplicitTransaction();
            rsTransaction->Begin();
            g_drawingInfo.surfaceNode->SetVisible(visible);
            rsTransaction->Commit();
        } else {
            g_drawingInfo.surfaceNode->SetVisible(visible);
            Rosen::RSTransaction::FlushImplicitTransaction();
        }
    }
    FI_HILOGI("Drag surfaceNode %{public}s success", visible ? "show" : "hide");
}

void DragDrawing::LongPressDragAlphaAnimation()
{
    FI_HILOGD("enter");
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return;
    }
    Rosen::RSAnimationTimingProtocol protocolAlphaChanged;
    protocolAlphaChanged.SetDuration(ALPHA_DURATION);
    Rosen::RSNode::Animate(protocolAlphaChanged, CURVE, [&]() {
        CHKPV(g_drawingInfo.parentNode);
        g_drawingInfo.parentNode->SetAlpha(1.0f);
        if (!g_drawingInfo.multiSelectedNodes.empty()) {
            size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
            for (size_t i = 0; i < multiSelectedNodesSize; ++i) {
                std::shared_ptr<Rosen::RSCanvasNode> multiSelectedNode = g_drawingInfo.multiSelectedNodes[i];
                CHKPV(multiSelectedNode);
                multiSelectedNode->SetAlpha(1.0f);
            }
        }
        std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
        CHKPV(dragStyleNode);
        dragStyleNode->SetAlpha(1.0f);
    },  []() { FI_HILOGD("AlphaChanged end"); });
}

#ifdef OHOS_ENABLE_PULLTHROW
void DragDrawing::SetHovering(double tx, double ty, std::shared_ptr<MMI::PointerEvent> pointerEvent)
{
    FI_HILOGI("enter");
    CHKPV(pointerEvent);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    pointerItem.SetDisplayX(tx);
    pointerItem.SetDisplayY(ty);
    pointerEvent->UpdatePointerItem(pointerEvent->GetPointerId(), pointerItem);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_PULL_MOVE);
    MMI::InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    pullThrowAnimationXCompleted_ = false;
    pullThrowAnimationYCompleted_ = false;
}

void DragDrawing::PullThrowAnimation(double tx, double ty, float vx,
    float vy, std::shared_ptr<MMI::PointerEvent> pointerEvent)
{
    FI_HILOGI("enter");
    CHKPV(pointerEvent);
    auto parentNode = g_drawingInfo.parentNode;
    auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
    CHKPV(parentNode);
    CHKPV(currentPixelMap);
    const Rosen::RSAnimationTimingProtocol THROW_SLIP_TIMING_PROTOCOL(std::round(THROW_SLIP_TIME)); // animation time
    const Rosen::RSAnimationTimingCurve THROW_SLIP_CURVE_X =
        Rosen::RSAnimationTimingCurve::CreateSpringCurve(vx, 1.0f, 128.0f, 30.0f);
    const Rosen::RSAnimationTimingCurve THROW_SLIP_CURVE_Y =
        Rosen::RSAnimationTimingCurve::CreateSpringCurve(vy, 1.0f, 128.0f, 30.0f);
    int32_t adjustSize = TWELVE_SIZE * GetScaling();
    int32_t positionX = tx + g_drawingInfo.pixelMapX;
    int32_t positionY = ty + g_drawingInfo.pixelMapY - adjustSize;
    // 执行动画X
    ResetAnimationParameter();
    Rosen::RSNode::Animate(THROW_SLIP_TIMING_PROTOCOL, THROW_SLIP_CURVE_X, [&]() {
        CHKPV(g_drawingInfo.parentNode);
        g_drawingInfo.parentNode->SetFramePositionX(positionX);
        if (!g_drawingInfo.multiSelectedNodes.empty()) {
            size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
            for (size_t i = 0; i < multiSelectedNodesSize; ++i) {
                std::shared_ptr<Rosen::RSCanvasNode> multiSelectedNode = g_drawingInfo.multiSelectedNodes[i];
                CHKPV(multiSelectedNode);
                multiSelectedNode->SetFramePositionX(positionX);
            }
        }
    },  [this, pointerEvent, tx, ty]() {
        FI_HILOGI("PullThrowAnimationX end");
        if (pullThrowAnimationYCompleted_) {
            PullThrowBreatheAnimation();
            SetHovering(tx, ty, pointerEvent);
            SetScaleAnimation();
        } else {
            pullThrowAnimationXCompleted_ = true;
        }
    });

    // 执行动画Y
    Rosen::RSNode::Animate(THROW_SLIP_TIMING_PROTOCOL, THROW_SLIP_CURVE_Y, [&]() {
        CHKPV(g_drawingInfo.parentNode);
        g_drawingInfo.parentNode->SetFramePositionY(positionY);
        if (!g_drawingInfo.multiSelectedNodes.empty()) {
            size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
            for (size_t i = 0; i < multiSelectedNodesSize; ++i) {
                std::shared_ptr<Rosen::RSCanvasNode> multiSelectedNode = g_drawingInfo.multiSelectedNodes[i];
                CHKPV(multiSelectedNode);
                multiSelectedNode->SetFramePositionY(positionY);
            }
        }
    },  [this, pointerEvent, tx, ty]() {
        FI_HILOGI("PullThrowAnimationY end");
        if (pullThrowAnimationXCompleted_) {
            PullThrowBreatheAnimation();
            SetHovering(tx, ty, pointerEvent);
            SetScaleAnimation();
        } else {
            pullThrowAnimationYCompleted_ = true;
        }
    });
    Rosen::RSTransaction::FlushImplicitTransaction();
    FI_HILOGI("leave");
    return;
}

void DragDrawing::SetScaleAnimation()
{
    FI_HILOGI("enter");
    auto parentNode = g_drawingInfo.parentNode;
    CHKPV(parentNode);
    Rosen::RSAnimationTimingProtocol scaleSlipTimingProtocol(std::round(THROW_SLIP_TIME)); // animation time
    Rosen::RSAnimationTimingCurve scaleCurve = Rosen::RSAnimationTimingCurve::LINEAR;

    scaleSlipTimingProtocol.SetAutoReverse(false);
    scaleSlipTimingProtocol.SetRepeatCount(1);
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    pullThrowScale_ = CalculatePullThrowScale();
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    parentNode->SetScale(1.0f);
    if (!g_drawingInfo.multiSelectedNodes.empty()) {
        size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
        for (size_t i = 0; i < multiSelectedNodesSize; ++i) {
            std::shared_ptr<Rosen::RSCanvasNode> multiSelectedNode = g_drawingInfo.multiSelectedNodes[i];
            CHKPV(multiSelectedNode);
            multiSelectedNode->SetScale(1.0f);
        }
    }
    Rosen::RSNode::Animate(scaleSlipTimingProtocol, scaleCurve, [&]() {
        CHKPV(g_drawingInfo.parentNode);
        g_drawingInfo.parentNode->SetScale(pullThrowScale_);
        if (!g_drawingInfo.multiSelectedNodes.empty()) {
            size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
            for (size_t i = 0; i < multiSelectedNodesSize; ++i) {
                std::shared_ptr<Rosen::RSCanvasNode> multiSelectedNode = g_drawingInfo.multiSelectedNodes[i];
                CHKPV(multiSelectedNode);
                multiSelectedNode->SetScale(pullThrowScale_);
            }
        }
    },  [&]() {
        FI_HILOGI("pullthrow Scale end");
    });
    Rosen::RSTransaction::FlushImplicitTransaction();
    FI_HILOGI("leave");
    return;
}

void DragDrawing::PullThrowBreatheAnimation()
{
    FI_HILOGI("enter");
    auto parentNode = g_drawingInfo.parentNode;
    CHKPV(parentNode);
    Rosen::RSAnimationTimingProtocol BREATHE_TIMING_PROTOCOL(std::round(BREATHE_TIME)); // animation time
    Rosen::RSAnimationTimingCurve BREATHE_CURVE = Rosen::RSAnimationTimingCurve::LINEAR;

    BREATHE_TIMING_PROTOCOL.SetAutoReverse(true);
    BREATHE_TIMING_PROTOCOL.SetRepeatCount(BREATHE_REPEAT);
 
    // 执行动画
    parentNode->SetScale(pullThrowScale_ - BREATHE_SCALE);
    if (!g_drawingInfo.multiSelectedNodes.empty()) {
        size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
        for (size_t i = 0; i < multiSelectedNodesSize; ++i) {
            std::shared_ptr<Rosen::RSCanvasNode> multiSelectedNode = g_drawingInfo.multiSelectedNodes[i];
            CHKPV(multiSelectedNode);
            multiSelectedNode->SetScale(pullThrowScale_ - BREATHE_SCALE);
        }
    }
    Rosen::RSNode::Animate(BREATHE_TIMING_PROTOCOL, BREATHE_CURVE, [&]() {
        CHKPV(g_drawingInfo.parentNode);
        g_drawingInfo.parentNode->SetScale(pullThrowScale_ + BREATHE_SCALE);
        if (!g_drawingInfo.multiSelectedNodes.empty()) {
            size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
            for (size_t i = 0; i < multiSelectedNodesSize; ++i) {
                std::shared_ptr<Rosen::RSCanvasNode> multiSelectedNode = g_drawingInfo.multiSelectedNodes[i];
                CHKPV(multiSelectedNode);
                multiSelectedNode->SetScale(pullThrowScale_ + BREATHE_SCALE);
            }
        }
    },  [&]() {
        FI_HILOGI("Breathe end");
    });
    Rosen::RSTransaction::FlushImplicitTransaction();
    FI_HILOGI("leave");
    return;
}

void DragDrawing::PullThrowBreatheEndAnimation()
{
    FI_HILOGI("enter");
    auto parentNode = g_drawingInfo.parentNode;
    CHKPV(parentNode);
    Rosen::RSAnimationTimingProtocol BREATHE_TIMING_END_PROTOCOL(std::round(0.0f)); // animation time
    Rosen::RSAnimationTimingCurve BREATHE_CURVE = Rosen::RSAnimationTimingCurve::LINEAR;

    parentNode->SetScale(0.99f);
    Rosen::RSNode::Animate(BREATHE_TIMING_END_PROTOCOL, BREATHE_CURVE, [&]() {
        CHKPV(g_drawingInfo.parentNode);
        g_drawingInfo.parentNode->SetScale(1.0f);
    },  [&]() {
        FI_HILOGI("Breathe end Animation End");
    });
    Rosen::RSTransaction::FlushImplicitTransaction();
    FI_HILOGI("leave");
    return;
}

void DragDrawing::PullThrowZoomOutAnimation()
{
    FI_HILOGI("enter");
    auto parentNode = g_drawingInfo.parentNode;
    CHKPV(parentNode);
    Rosen::RSAnimationTimingProtocol zoomOutProtocol(std::round(ZOOMOUT_PULLTHROW)); // animation time
    Rosen::RSAnimationTimingCurve zoomOutCurve = Rosen::RSAnimationTimingCurve::LINEAR;
 
    Rosen::RSNode::Animate(zoomOutProtocol, zoomOutCurve, [&]() {
        CHKPV(g_drawingInfo.parentNode);
        g_drawingInfo.parentNode->SetScale(1.0f);
    },  [&]() {
        FI_HILOGI("PullThrowZoomOutAnimation End");
        PullThrowBreatheEndAnimation();
    });
    Rosen::RSTransaction::FlushImplicitTransaction();
    FI_HILOGI("leave");
    return;
}
#endif // OHOS_ENABLE_PULLTHROW

#ifdef OHOS_BUILD_INTERNAL_DROP_ANIMATION
void DragDrawing::GetDragDrawingInfo(DragInternalInfo &dragInternalInfo)
{
    FI_HILOGI("enter");
    dragInternalInfo.positionX = g_drawingInfo.x;
    dragInternalInfo.positionY = g_drawingInfo.y;
    dragInternalInfo.scale = GetScaling();
    dragInternalInfo.pixelMapX = g_drawingInfo.pixelMapX;
    dragInternalInfo.pixelMapY = g_drawingInfo.pixelMapY;
    dragInternalInfo.argb = g_drawingInfo.filterInfo.argb;
    dragInternalInfo.rootNode = g_drawingInfo.rootNode;
    dragInternalInfo.parentNode = g_drawingInfo.parentNode;
    dragInternalInfo.curvesMaskNode = g_drawingInfo.curvesMaskNode;
    dragInternalInfo.lightNode = g_drawingInfo.lightNode;
    dragInternalInfo.currentPixelMap = AccessGlobalPixelMapLocked();
    dragInternalInfo.nodes = g_drawingInfo.nodes;
    dragInternalInfo.multiSelectedNodes = g_drawingInfo.multiSelectedNodes;
    dragInternalInfo.multiSelectedPixelMaps = g_drawingInfo.multiSelectedPixelMaps;
    dragInternalInfo.rotation = GetRotation(g_drawingInfo.displayId);
    dragInternalInfo.handler = handler_;
 
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDisplayById(g_drawingInfo.displayId);
    if (display == nullptr) {
        FI_HILOGD("Get display info failed, display:%{public}d", g_drawingInfo.displayId);
        display = Rosen::DisplayManager::GetInstance().GetDisplayById(0);
        if (display == nullptr) {
            FI_HILOGE("Get default display info failed");
            dragInternalInfo.displayWidth = 0;
            dragInternalInfo.displayHeight = 0;
            FI_HILOGI("leave");
            return;
        }
    }
    int32_t width = display->GetWidth();
    int32_t height = display->GetHeight();
    dragInternalInfo.displayWidth = width;
    dragInternalInfo.displayHeight = height;
    FI_HILOGI("leave");
    return;
}
 
void DragDrawing::RemoveStyleNodeAnimations()
{
    FI_HILOGI("enter");
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return;
    }
    std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
    CHKPV(dragStyleNode);
    if (dragStyleNode != nullptr && drawStyleScaleModifier_ != nullptr) {
        dragStyleNode->RemoveModifier(drawStyleScaleModifier_);
        dragStyleNode->RemoveAllAnimations();
        drawStyleScaleModifier_ = nullptr;
        needBreakStyleScaleAnimation_ = true;
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
    FI_HILOGI("leave");
}
#endif // OHOS_BUILD_INTERNAL_DROP_ANIMATION

void DragDrawing::LongPressDragZoomInAnimation()
{
    FI_HILOGD("enter");
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return;
    }
    CHKPV(g_drawingInfo.parentNode);
    g_drawingInfo.parentNode->SetScale(1.0f);
    if (!g_drawingInfo.multiSelectedNodes.empty()) {
        size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
        for (size_t i = 0; i < multiSelectedNodesSize; ++i) {
            std::shared_ptr<Rosen::RSCanvasNode> multiSelectedNode = g_drawingInfo.multiSelectedNodes[i];
            CHKPV(multiSelectedNode);
            multiSelectedNode->SetScale(1.0f);
        }
    }
    std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
    CHKPV(dragStyleNode);
    dragStyleNode->SetScale(1.0f);

    Rosen::RSAnimationTimingProtocol protocolZoomIn;
    protocolZoomIn.SetDuration(ZOOM_IN_DURATION);
    Rosen::RSNode::Animate(protocolZoomIn, CURVE, [&]() {
        CHKPV(g_drawingInfo.parentNode);
        g_drawingInfo.parentNode->SetScale(ZOOM_IN_SCALE);
        if (!g_drawingInfo.multiSelectedNodes.empty()) {
            size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
            for (size_t i = 0; i < multiSelectedNodesSize; ++i) {
                std::shared_ptr<Rosen::RSCanvasNode> multiSelectedNode = g_drawingInfo.multiSelectedNodes[i];
                CHKPV(multiSelectedNode);
                multiSelectedNode->SetScale(ZOOM_IN_SCALE);
            }
        }
        std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
        CHKPV(dragStyleNode);
        dragStyleNode->SetScale(ZOOM_IN_SCALE);
    },  []() { FI_HILOGD("ZoomIn end"); });

    FI_HILOGD("leave");
    return;
}

void DragDrawing::SetMultiSelectedAnimationFlag(bool needMultiSelectedAnimation)
{
    FI_HILOGI("needMultiSelectedAnimation:%{public}d", needMultiSelectedAnimation);
    needMultiSelectedAnimation_ = needMultiSelectedAnimation;
}

void DragDrawing::LongPressDragZoomOutAnimation()
{
    FI_HILOGD("enter");
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return;
    }
    Rosen::RSAnimationTimingProtocol protocolZoomOut;
    protocolZoomOut.SetDuration(ZOOM_OUT_DURATION);
    Rosen::RSNode::Animate(protocolZoomOut, CURVE, [&]() {
        CHKPV(g_drawingInfo.parentNode);
        g_drawingInfo.parentNode->SetScale(ZOOM_OUT_SCALE);
        if (!g_drawingInfo.multiSelectedNodes.empty()) {
            size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
            for (size_t i = 0; i < multiSelectedNodesSize; ++i) {
                std::shared_ptr<Rosen::RSCanvasNode> multiSelectedNode = g_drawingInfo.multiSelectedNodes[i];
                CHKPV(multiSelectedNode);
                multiSelectedNode->SetScale(ZOOM_OUT_SCALE);
            }
        }
        std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
        CHKPV(dragStyleNode);
        dragStyleNode->SetScale(ZOOM_OUT_SCALE);
    },  []() { FI_HILOGD("ZoomOut end"); });

    g_drawingInfo.startNum = START_TIME;
    g_drawingInfo.needDestroyDragWindow = false;
    StartVsync();
    FI_HILOGD("leave");
    return;
}

void DragDrawing::LongPressDragAnimation()
{
    FI_HILOGD("enter");
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return;
    }
    LongPressDragAlphaAnimation();
    LongPressDragZoomInAnimation();
    Rosen::RSAnimationTimingProtocol protocolZoomOut;
    protocolZoomOut.SetDuration(ZOOM_DURATION);
    Rosen::RSNode::Animate(protocolZoomOut, CURVE, [&]() {
        ShadowInfo shadowInfo;
        auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
        CHKPV(currentPixelMap);
        float widthScale = CalculateWidthScale();
        currentPixelMap->scale(widthScale, widthScale, Media::AntiAliasingOption::HIGH);
        shadowInfo.pixelMap = currentPixelMap;
        shadowInfo.x = g_drawingInfo.pixelMapX * widthScale;
        shadowInfo.y = g_drawingInfo.pixelMapY * widthScale;
        UpdateShadowPic(shadowInfo);
    },  []() { FI_HILOGD("Scale zoom out end"); });

    g_drawingInfo.startNum = START_TIME;
    g_drawingInfo.needDestroyDragWindow = false;
    StartVsync();
    FI_HILOGD("leave");
    return;
}

void DragDrawing::OnStartDrag(const DragAnimationData &dragAnimationData)
{
    FI_HILOGI("enter");
    if (g_drawingInfo.nodes.size() <= PIXEL_MAP_INDEX) {
        FI_HILOGE("The index is out of bounds, node size is %{public}zu", g_drawingInfo.nodes.size());
        return;
    }
    std::shared_ptr<Rosen::RSCanvasNode> shadowNode = g_drawingInfo.nodes[PIXEL_MAP_INDEX];
    CHKPV(shadowNode);
    if (DrawShadow(shadowNode) != RET_OK) {
        FI_HILOGE("Draw shadow failed");
        return;
    }
    g_drawingInfo.isCurrentDefaultStyle = true;
    FI_HILOGI("leave");
}

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
void DragDrawing::OnStartDragExt()
{
    if (dragExtHandler_ == nullptr) {
        FI_HILOGE("Fail to open drag drop extension library");
        return;
    }
    auto dragDropStartExtFunc = reinterpret_cast<DragStartExtFunc>(dlsym(dragExtHandler_, "OnStartDragExt"));
    if (dragDropStartExtFunc == nullptr) {
        FI_HILOGE("Fail to get drag drop extension function");
        CHKPV(dragExtHandler_);
        dlclose(dragExtHandler_);
        dragExtHandler_ = nullptr;
        return;
    }
#ifdef OHOS_DRAG_ENABLE_ANIMATION
    if (!GetSuperHubHandler()->PostTask(
        [dragDropStartExtFunc] {
            return dragDropStartExtFunc(g_dragDataForSuperHub);
        })
    ) {
        FI_HILOGE("Start style animation failed");
    }
#endif // OHOS_DRAG_ENABLE_ANIMATION
}

void DragDrawing::NotifyDragInfo(const std::string &sourceName, const std::string &targetName)
{
    FI_HILOGI("NotifyDragInfo");
    if (dragExtHandler_ == nullptr) {
        FI_HILOGE("Fail to open drag drop extension library");
        return;
    }
    auto dragDropExtFunc = reinterpret_cast<DragNotifyExtFunc>(dlsym(dragExtHandler_, "OnNotifyDragInfo"));
    if (dragDropExtFunc == nullptr) {
        FI_HILOGE("Fail to get drag drop extension function");
        CHKPV(dragExtHandler_);
        dlclose(dragExtHandler_);
        dragExtHandler_ = nullptr;
        return;
    }
    struct DragEventInfo dragEventInfo;
    dragEventInfo.sourcePkgName = sourceName;
    dragEventInfo.targetPkgName = targetName;
    GetSuperHubHandler();
    CHKPV(superHubHandler_);
    if (!superHubHandler_->PostTask([dragDropExtFunc, dragEventInfo] ()
        mutable { return dragDropExtFunc(dragEventInfo); })) {
        FI_HILOGE("notify drag info failed");
    }
}

std::shared_ptr<AppExecFwk::EventHandler> DragDrawing::GetSuperHubHandler()
{
    if (superHubHandler_ == nullptr) {
        auto runner = AppExecFwk::EventRunner::Create(SUPER_HUB_THREAD_NAME);
        superHubHandler_ = std::make_shared<AppExecFwk::EventHandler>(std::move(runner));
    }
    return superHubHandler_;
}
#endif // OHOS_BUILD_ENABLE_ARKUI_X

float DragDrawing::AdjustDoubleValue(double doubleValue)
{
    FI_HILOGI("doubleValue is %{public}f", doubleValue);
    float dragOriginDpi = DRAG_DATA_MGR.GetDragOriginDpi();
    if (dragOriginDpi > EPSILON) {
        float scalingValue = GetScaling() / dragOriginDpi;
        doubleValue = doubleValue * scalingValue;
        if (fabs(scalingValue - 1.0f) > EPSILON) {
            float widthScale = CalculateWidthScale();
            doubleValue = doubleValue * widthScale;
        }
    }
    float floatValue = static_cast<float>(doubleValue);
    FI_HILOGI("floatValue is %{public}f", floatValue);
    return floatValue;
}

void DragDrawing::CheckStyleNodeModifier(std::shared_ptr<Rosen::RSCanvasNode> styleNode)
{
    FI_HILOGD("enter");
    CHKPV(styleNode);
    if (drawStyleChangeModifier_ != nullptr) {
        styleNode->RemoveModifier(drawStyleChangeModifier_);
        drawStyleChangeModifier_ = nullptr;
    }
    if (drawStyleScaleModifier_ != nullptr && hasRunningScaleAnimation_) {
        needBreakStyleScaleAnimation_ = true;
    }
    styleNode->RemoveAllAnimations();
    FI_HILOGD("leave");
}

void DragDrawing::RemoveStyleNodeModifier(std::shared_ptr<Rosen::RSCanvasNode> styleNode)
{
    FI_HILOGD("enter");
    CHKPV(styleNode);
    if (drawStyleChangeModifier_ != nullptr) {
        styleNode->RemoveModifier(drawStyleChangeModifier_);
        drawStyleChangeModifier_ = nullptr;
    }
    if (drawStyleScaleModifier_ != nullptr) {
        styleNode->RemoveModifier(drawStyleScaleModifier_);
        drawStyleScaleModifier_ = nullptr;
    }
    FI_HILOGD("leave");
}

void DragDrawing::UpdateAnimationProtocol(Rosen::RSAnimationTimingProtocol protocol)
{
    FI_HILOGD("enter");
    g_drawingInfo.startNum = START_TIME;
    interruptNum_ = START_TIME * INTERRUPT_SCALE;
    hasRunningAnimation_ = true;
    bool stopSignal = true;
    CHKPV(rsUiDirector_);
    while (hasRunningAnimation_) {
        hasRunningAnimation_ = rsUiDirector_->FlushAnimation(g_drawingInfo.startNum);
        rsUiDirector_->FlushModifier();
        rsUiDirector_->SendMessages();
        if ((g_drawingInfo.startNum >= interruptNum_) && stopSignal) {
            protocol.SetDuration(TIME_STOP);
            stopSignal = false;
        }
        g_drawingInfo.startNum += INTERVAL_TIME;
        usleep(TIME_SLEEP);
    }
    FI_HILOGD("leave");
}

void DragDrawing::StartStyleAnimation(float startScale, float endScale, int32_t duration)
{
    FI_HILOGI("StartStyleAnimation, startScale is %{public}lf", startScale);
    if (!CheckNodesValid() || needBreakStyleScaleAnimation_ || hasRunningStopAnimation_) {
        FI_HILOGE("needBreakStyleScaleAnimation_ or hasRunningStopAnimation_, return");
        return;
    }
    if (g_drawingInfo.nodes.size() <= DRAG_STYLE_INDEX) {
        FI_HILOGE("The index is out of bounds, node size is %{public}zu", g_drawingInfo.nodes.size());
        return;
    }
    std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
    CHKPV(dragStyleNode);
    RemoveStyleNodeModifier(dragStyleNode);
    drawStyleScaleModifier_ = std::make_shared<DrawStyleScaleModifier>();
    dragStyleNode->AddModifier(drawStyleScaleModifier_);
    CHKPV(drawStyleScaleModifier_);
    drawStyleScaleModifier_->SetScale(startScale);
    Rosen::RSAnimationTimingProtocol protocol;
    protocol.SetDuration(duration);
    auto springCurveStyle = endScale == STYLE_END_SCALE
        ? Rosen::RSAnimationTimingCurve::CreateCubicCurve(BEZIER_030, BEZIER_000, BEZIER_040, BEZIER_100)
        : Rosen::RSAnimationTimingCurve::CreateCubicCurve(BEZIER_020, BEZIER_000, BEZIER_060, BEZIER_100);
    Rosen::RSNode::Animate(protocol, springCurveStyle, [&]() {
        if (drawStyleScaleModifier_ != nullptr) {
            drawStyleScaleModifier_->SetScale(endScale);
        }
    }, []() { FI_HILOGD("StartStyleAnimation end"); });
    UpdateAnimationProtocol(protocol);
    if (endScale == STYLE_CHANGE_SCALE) {
        if (drawStyleChangeModifier_ != nullptr) {
            dragStyleNode->RemoveModifier(drawStyleChangeModifier_);
            drawStyleChangeModifier_ = nullptr;
        }
        if (drawStyleScaleModifier_ != nullptr) {
            dragStyleNode->RemoveModifier(drawStyleScaleModifier_);
            drawStyleScaleModifier_ = nullptr;
        }
        drawStyleChangeModifier_ = std::make_shared<DrawStyleChangeModifier>(g_drawingInfo.stylePixelMap, isRTL_);
        dragStyleNode->AddModifier(drawStyleChangeModifier_);
    }
    if (endScale == STYLE_END_SCALE && drawStyleScaleModifier_ != nullptr) {
        dragStyleNode->RemoveModifier(drawStyleScaleModifier_);
        drawStyleScaleModifier_ = nullptr;
    }
}

void DragDrawing::ChangeStyleAnimation()
{
    FI_HILOGD("enter");
    hasRunningScaleAnimation_ = true;
    StartStyleAnimation(START_STYLE_SCALE, STYLE_CHANGE_SCALE, TIME_DRAG_CHANGE_STYLE);
    StartStyleAnimation(STYLE_CHANGE_SCALE, STYLE_MAX_SCALE, TIME_DRAG_CHANGE_STYLE);
    StartStyleAnimation(STYLE_MAX_SCALE, STYLE_END_SCALE, TIME_DRAG_STYLE);
    needBreakStyleScaleAnimation_ = false;
    hasRunningScaleAnimation_ = false;
    FI_HILOGD("leave");
}

void DragDrawing::OnDragStyleAnimation()
{
    FI_HILOGD("enter");
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return;
    }
    if (g_drawingInfo.nodes.size() <= DRAG_STYLE_INDEX) {
        FI_HILOGE("The index is out of bounds, node size is %{public}zu", g_drawingInfo.nodes.size());
        return;
    }
    std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
    CHKPV(dragStyleNode);
    needBreakStyleScaleAnimation_ = false;
    if (g_drawingInfo.isPreviousDefaultStyle == true || g_drawingInfo.isCurrentDefaultStyle == true) {
        FI_HILOGE("Has DefaultStyle, change style and return");
        CheckStyleNodeModifier(dragStyleNode);
        drawStyleChangeModifier_ = std::make_shared<DrawStyleChangeModifier>(g_drawingInfo.stylePixelMap, isRTL_);
        dragStyleNode->AddModifier(drawStyleChangeModifier_);
        return;
    }
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    if (handler_ == nullptr) {
        auto runner = AppExecFwk::EventRunner::Create(THREAD_NAME);
        handler_ = std::make_shared<AppExecFwk::EventHandler>(std::move(runner));
    }
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    CheckStyleNodeModifier(dragStyleNode);
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    CHKPV(handler_);
    handler_->RemoveTask("dragStyleAnimationTask");
    handler_->PostTask(std::bind(&DragDrawing::ChangeStyleAnimation, this), "dragStyleAnimationTask");
#else
    ChangeStyleAnimation();
#endif
    FI_HILOGD("leave");
}

void DragDrawing::OnDragStyle(std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode,
    std::shared_ptr<Media::PixelMap> stylePixelMap)
{
    FI_HILOGD("enter");
    CHKPV(dragStyleNode);
    CHKPV(stylePixelMap);
#ifdef OHOS_DRAG_ENABLE_ANIMATION
    if (handler_ == nullptr) {
        auto runner = AppExecFwk::EventRunner::Create(THREAD_NAME);
        CHKPV(runner);
        handler_ = std::make_shared<AppExecFwk::EventHandler>(std::move(runner));
    }
    if (drawSVGModifier_ != nullptr) {
        dragStyleNode->RemoveModifier(drawSVGModifier_);
        drawSVGModifier_ = nullptr;
    }
    CHKPV(handler_);
    if (!handler_->PostTask([this] { this->OnDragStyleAnimation(); })) {
        FI_HILOGE("Drag style animation failed");
        DrawStyle(dragStyleNode, stylePixelMap);
    }
#else // OHOS_DRAG_ENABLE_ANIMATION
    DrawStyle(dragStyleNode, stylePixelMap);
#endif // OHOS_DRAG_ENABLE_ANIMATION
    FI_HILOGD("leave");
}

void DragDrawing::OnStopAnimationSuccess()
{
    FI_HILOGI("enter");
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return;
    }
    if (g_drawingInfo.nodes.size() <= DRAG_STYLE_INDEX) {
        FI_HILOGE("The index is out of bounds, node size is %{public}zu", g_drawingInfo.nodes.size());
        return;
    }
    std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
    if (dragStyleNode != nullptr && drawStyleScaleModifier_ != nullptr) {
        dragStyleNode->RemoveModifier(drawStyleScaleModifier_);
        dragStyleNode->RemoveAllAnimations();
        drawStyleScaleModifier_ = nullptr;
        needBreakStyleScaleAnimation_ = true;
    }
    CHKPV(g_drawingInfo.rootNode);
    hasRunningStopAnimation_ = true;
    if (drawDragStopModifier_ != nullptr) {
        g_drawingInfo.rootNode->RemoveModifier(drawDragStopModifier_);
        drawDragStopModifier_ = nullptr;
    }
    drawDragStopModifier_ = std::make_shared<DrawDragStopModifier>();
    g_drawingInfo.rootNode->AddModifier(drawDragStopModifier_);
    drawDragStopModifier_->SetAlpha(BEGIN_ALPHA);
    drawDragStopModifier_->SetScale(BEGIN_SCALE);
    drawDragStopModifier_->SetStyleScale(START_STYLE_SCALE);
    drawDragStopModifier_->SetStyleAlpha(START_STYLE_ALPHA);
    Rosen::RSAnimationTimingProtocol windowProtocol;
    Rosen::RSAnimationTimingProtocol styleProtocol;
    windowProtocol.SetDuration(TIME_STOP_SUCCESS_WINDOW);
    styleProtocol.SetDuration(TIME_STOP_SUCCESS_STYLE);
    auto springCurveSuccessWindow = Rosen::RSAnimationTimingCurve::CreateCubicCurve(BEZIER_040, BEZIER_000,
        BEZIER_100, BEZIER_100);
    auto springCurveSuccessStyle = Rosen::RSAnimationTimingCurve::CreateCubicCurve(BEZIER_000, BEZIER_000,
        BEZIER_100, BEZIER_100);
    Rosen::RSNode::Animate(windowProtocol, springCurveSuccessWindow, [&]() {
        drawDragStopModifier_->SetAlpha(BEGIN_ALPHA);
        drawDragStopModifier_->SetScale(END_SCALE_SUCCESS);
        Rosen::RSNode::Animate(styleProtocol, springCurveSuccessStyle, [&]() {
            drawDragStopModifier_->SetStyleAlpha(END_STYLE_ALPHA);
            drawDragStopModifier_->SetStyleScale(START_STYLE_SCALE);
        });
    },  []() { FI_HILOGD("OnStopAnimationSuccess end"); });
    DoEndAnimation();
    FI_HILOGI("leave");
}

void DragDrawing::OnStopDragSuccess(std::shared_ptr<Rosen::RSCanvasNode> shadowNode,
    std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode)
{
    FI_HILOGD("enter");
    auto animateCb = [this] { return this->InitVSync(END_ALPHA, END_SCALE_SUCCESS); };
#ifdef OHOS_DRAG_ENABLE_ANIMATION
    ResetAnimationParameter();
    auto runner = AppExecFwk::EventRunner::Create(THREAD_NAME);
    CHKPV(runner);
    handler_ = std::make_shared<AppExecFwk::EventHandler>(std::move(runner));
    CHKPV(handler_);
    if (!handler_->PostTask([this] { return this->OnStopAnimationSuccess(); })) {
        FI_HILOGE("Failed to stop style animation");
        RunAnimation(animateCb);
    }
#else // OHOS_DRAG_ENABLE_ANIMATION
    RunAnimation(animateCb);
#endif // OHOS_DRAG_ENABLE_ANIMATION
    FI_HILOGD("leave");
}

void DragDrawing::OnStopAnimationFail()
{
    FI_HILOGI("enter");
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return;
    }
    if (g_drawingInfo.nodes.size() <= DRAG_STYLE_INDEX) {
        FI_HILOGE("The index is out of bounds, node size is %{public}zu", g_drawingInfo.nodes.size());
        return;
    }
    std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
    if (dragStyleNode != nullptr && drawStyleScaleModifier_ != nullptr) {
        dragStyleNode->RemoveModifier(drawStyleScaleModifier_);
        dragStyleNode->RemoveAllAnimations();
        drawStyleScaleModifier_ = nullptr;
        needBreakStyleScaleAnimation_ = true;
    }
    CHKPV(g_drawingInfo.rootNode);
    if (drawDragStopModifier_ != nullptr) {
        g_drawingInfo.rootNode->RemoveModifier(drawDragStopModifier_);
        drawDragStopModifier_ = nullptr;
    }
    drawDragStopModifier_ = std::make_shared<DrawDragStopModifier>();
    hasRunningStopAnimation_ = true;
    g_drawingInfo.rootNode->AddModifier(drawDragStopModifier_);
    drawDragStopModifier_->SetAlpha(BEGIN_ALPHA);
    drawDragStopModifier_->SetScale(BEGIN_SCALE);
    drawDragStopModifier_->SetStyleScale(START_STYLE_SCALE);
    drawDragStopModifier_->SetStyleAlpha(START_STYLE_ALPHA);
    Rosen::RSAnimationTimingProtocol protocol;
    protocol.SetDuration(TIME_STOP_FAIL_WINDOW);
    auto springCurveFail = Rosen::RSAnimationTimingCurve::CreateCubicCurve(BEZIER_033, BEZIER_000,
        BEZIER_067, BEZIER_100);
    Rosen::RSNode::Animate(protocol, springCurveFail, [&]() {
        drawDragStopModifier_->SetAlpha(END_ALPHA);
        drawDragStopModifier_->SetScale(END_SCALE_FAIL);
        drawDragStopModifier_->SetStyleScale(START_STYLE_SCALE);
        drawDragStopModifier_->SetStyleAlpha(END_STYLE_ALPHA);
    }, []() { FI_HILOGD("OnStopAnimationFail end"); });
    DoEndAnimation();
    FI_HILOGI("leave");
}

void DragDrawing::OnStopDragFail(std::shared_ptr<Rosen::RSSurfaceNode> surfaceNode,
    std::shared_ptr<Rosen::RSNode> rootNode)
{
    FI_HILOGD("enter");
    auto animateCb = [this] { return this->InitVSync(END_ALPHA, END_SCALE_FAIL); };
#ifdef OHOS_DRAG_ENABLE_ANIMATION
    ResetAnimationParameter();
    auto runner = AppExecFwk::EventRunner::Create(THREAD_NAME);
    CHKPV(runner);
    handler_ = std::make_shared<AppExecFwk::EventHandler>(std::move(runner));
    CHKPV(handler_);
    if (!handler_->PostTask([this] { this->OnStopAnimationFail(); })) {
        FI_HILOGE("Failed to stop style animation");
        RunAnimation(animateCb);
    }
#else // OHOS_DRAG_ENABLE_ANIMATION
    RunAnimation(animateCb);
#endif // OHOS_DRAG_ENABLE_ANIMATION
    FI_HILOGD("leave");
}

void DragDrawing::OnStopAnimation()
{
    FI_HILOGD("enter");
}

int32_t DragDrawing::RunAnimation(std::function<int32_t()> cb)
{
    FI_HILOGD("enter");
    ResetAnimationParameter();
#ifndef IOS_PLATFORM
    auto runner = AppExecFwk::EventRunner::Create(THREAD_NAME);
#else
    auto runner = AppExecFwk::EventRunner::Current(); // IOS animation can run main thread
#endif // IOS_PLATFORM
    CHKPR(runner, RET_ERR);
    handler_ = std::make_shared<AppExecFwk::EventHandler>(std::move(runner));
    if (!handler_->PostTask(cb)) {
        FI_HILOGE("Send vsync event failed");
        return RET_ERR;
    }
    FI_HILOGD("leave");
    return RET_OK;
}

int32_t DragDrawing::DrawShadow(std::shared_ptr<Rosen::RSCanvasNode> shadowNode)
{
    FI_HILOGD("enter");
    CHKPR(shadowNode, RET_ERR);
    if (drawPixelMapModifier_ != nullptr) {
        shadowNode->RemoveModifier(drawPixelMapModifier_);
        drawPixelMapModifier_ = nullptr;
    }
    drawPixelMapModifier_ = std::make_shared<DrawPixelMapModifier>();
    shadowNode->AddModifier(drawPixelMapModifier_);
    FilterInfo filterInfo = g_drawingInfo.filterInfo;
    Rosen::Vector4f cornerRadiusVector = { filterInfo.cornerRadius1, filterInfo.cornerRadius2,
        filterInfo.cornerRadius3, filterInfo.cornerRadius4 };
    shadowNode->SetCornerRadius(cornerRadiusVector * filterInfo.dipScale * filterInfo.scale);
    shadowNode->SetAlpha(filterInfo.opacity);
    FI_HILOGD("leave");
    return RET_OK;
}

int32_t DragDrawing::DrawMouseIcon()
{
    FI_HILOGD("enter");
    if (g_drawingInfo.nodes.size() < MOUSE_NODE_MIN_COUNT) {
        FI_HILOGE("Nodes size invalid, node size:%{public}zu", g_drawingInfo.nodes.size());
        return RET_ERR;
    }
    if (g_drawingInfo.nodes.size() <= MOUSE_ICON_INDEX) {
        FI_HILOGE("The index is out of bounds, node size is %{public}zu", g_drawingInfo.nodes.size());
        return RET_ERR;
    }
    std::shared_ptr<Rosen::RSCanvasNode> mouseIconNode = g_drawingInfo.nodes[MOUSE_ICON_INDEX];
    CHKPR(mouseIconNode, RET_ERR);
    if (drawMouseIconModifier_ != nullptr) {
        mouseIconNode->RemoveModifier(drawMouseIconModifier_);
        drawMouseIconModifier_ = nullptr;
    }
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    int32_t ret = MMI::InputManager::GetInstance()->GetPointerStyle(GLOBAL_WINDOW_ID, pointerStyle_);
    if (ret != RET_OK) {
        FI_HILOGE("Get pointer style failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    drawMouseIconModifier_ = std::make_shared<DrawMouseIconModifier>(pointerStyle_);
    mouseIconNode->AddModifier(drawMouseIconModifier_);
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    FI_HILOGD("leave");
    return RET_OK;
}

void DragDrawing::FlushDragPosition(uint64_t nanoTimestamp)
{
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    if (dragState_ == DragState::MOTION_DRAGGING) {
        FI_HILOGD("Current in MOTION_DRAGGING, skip");
        return;
    }
    if (rsUiDirector_ != nullptr) {
        rsUiDirector_->SetTimeStamp(nanoTimestamp, RENDER_THREAD_NAME);
    } else {
        FI_HILOGE("rsUiDirector_ is nullptr");
    }
    DragMoveEvent event = dragSmoothProcessor_.SmoothMoveEvent(nanoTimestamp,
        vSyncStation_.GetVSyncPeriod());
    FI_HILOGD("Move position x:%{private}f, y:%{private}f, timestamp:%{public}" PRId64
        "displayId:%{public}d", event.displayX, event.displayY, event.timestamp, event.displayId);
    Rosen::Rotation currentRotation = GetRotation(event.displayId);
    StartTrace(HITRACE_TAG_MSDP, "OnDragMove,displayX:" + std::to_string(event.displayX)
        + ",displayY:" + std::to_string(event.displayY) + "displayId:" + std::to_string(event.displayId)
        + ",rotation:" + std::to_string(static_cast<uint32_t>(currentRotation)));
    if (DragWindowRotationFlush_ == currentRotation) {
        UpdateDragPosition(event.displayId, event.displayX, event.displayY);
        vSyncStation_.RequestFrame(TYPE_FLUSH_DRAG_POSITION, frameCallback_);
    }
    DragWindowRotationFlush_ = currentRotation;
    FinishTrace(HITRACE_TAG_MSDP);
#endif // OHOS_BUILD_ENABLE_ARKUI_X
}

void DragDrawing::OnDragMove(int32_t displayId, int32_t displayX, int32_t displayY, int64_t actionTime)
{
    if (screenRotateState_) {
        screenRotateState_ = false;
    }
    if (isRunningRotateAnimation_) {
        FI_HILOGD("Doing rotate drag window animate, ignore draw drag window");
        return;
    }
#ifdef IOS_PLATFORM
    actionTime_ = actionTime;
#endif // IOS_PLATFORM

#ifdef OHOS_BUILD_PC_PRODUCT
    if (g_drawingInfo.sourceType == MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        UpdateDragPosition(displayId, displayX, displayY);
        return;
    }
#endif // OHOS_BUILD_PC_PRODUCT

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    std::chrono::microseconds microseconds(actionTime);
    TimeStamp time(microseconds);
    uint64_t actionTimeCount = static_cast<uint64_t>(time.time_since_epoch().count());
    DragMoveEvent event = {
        .displayX = displayX,
        .displayY = displayY,
        .displayId = displayId,
        .timestamp = actionTimeCount,
    };
    dragSmoothProcessor_.InsertEvent(event);
    if (frameCallback_ == nullptr) {
        frameCallback_ = std::make_shared<DragFrameCallback>([this](uint64_t nanoTimestamp) {
            this->FlushDragPosition(nanoTimestamp);
        });
    }
    vSyncStation_.RequestFrame(TYPE_FLUSH_DRAG_POSITION, frameCallback_);
#else
    UpdateDragPosition(displayId, displayX, displayY);
#endif // OHOS_BUILD_ENABLE_ARKUI_X
}

#ifdef OHOS_ENABLE_PULLTHROW
void DragDrawing::OnPullThrowDragMove(int32_t displayId, int32_t displayX, int32_t displayY, int64_t actionTime)
{
    FI_HILOGD("enter");
    
    if (screenRotateState_) {
        screenRotateState_ = false;
    }
    if (isRunningRotateAnimation_) {
        FI_HILOGD("Doing rotate drag window animate, ignore draw drag window");
        return;
    }
#ifdef IOS_PLATFORM
    actionTime_ = actionTime;
#endif // IOS_PLATFORM
    if (g_drawingInfo.sourceType == MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        UpdateDragPosition(displayId, displayX, displayY);
        return;
    }
    UpdateDragPosition(displayId, displayX, displayY);
}
#endif // OHOS_ENABLE_PULLTHROW

int32_t DragDrawing::DrawStyle(std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode,
    std::shared_ptr<Media::PixelMap> stylePixelMap)
{
    FI_HILOGD("enter");
    CHKPR(dragStyleNode, RET_ERR);
    CHKPR(stylePixelMap, RET_ERR);
    if (drawSVGModifier_ != nullptr) {
        dragStyleNode->RemoveModifier(drawSVGModifier_);
        drawSVGModifier_ = nullptr;
    }
    drawSVGModifier_ = std::make_shared<DrawSVGModifier>(stylePixelMap, isRTL_);
    dragStyleNode->AddModifier(drawSVGModifier_);
    FI_HILOGD("leave");
    return RET_OK;
}

int32_t DragDrawing::InitVSync(float endAlpha, float endScale)
{
    FI_HILOGD("enter");
    CHKPR(g_drawingInfo.rootNode, RET_ERR);
    if (drawDynamicEffectModifier_ != nullptr) {
        g_drawingInfo.rootNode->RemoveModifier(drawDynamicEffectModifier_);
        drawDynamicEffectModifier_ = nullptr;
    }
    drawDynamicEffectModifier_ = std::make_shared<DrawDynamicEffectModifier>();
    g_drawingInfo.rootNode->AddModifier(drawDynamicEffectModifier_);
    drawDynamicEffectModifier_->SetAlpha(BEGIN_ALPHA);
    drawDynamicEffectModifier_->SetScale(BEGIN_SCALE);

    Rosen::RSAnimationTimingProtocol protocol;
    protocol.SetDuration(SUCCESS_ANIMATION_DURATION);
    Rosen::RSNode::Animate(protocol, Rosen::RSAnimationTimingCurve::EASE_IN_OUT, [&]() {
        drawDynamicEffectModifier_->SetAlpha(endAlpha);
        drawDynamicEffectModifier_->SetScale(endScale);
    },  []() { FI_HILOGD("InitVSync end"); });
    Rosen::RSTransaction::FlushImplicitTransaction();
    DoEndAnimation();
    FI_HILOGD("leave");
    return RET_OK;
}

int32_t DragDrawing::StartVsync()
{
    FI_HILOGI("enter");
    auto currentReceiver = AccessReceiverLocked();
    if (currentReceiver == nullptr) {
        CHKPR(handler_, RET_ERR);
        currentReceiver = Rosen::RSInterfaces::GetInstance().CreateVSyncReceiver("DragDrawing", handler_);
        CHKPR(currentReceiver, RET_ERR);
        UpdateReceiverLocked(currentReceiver);
    }
#ifdef IOS_PLATFORM
    rsUiDirector_->FlushAnimation(g_drawingInfo.startNum);
#endif // IOS_PLATFORM
    int32_t ret = currentReceiver->Init();
    if (ret != RET_OK) {
        FI_HILOGE("Receiver init failed");
        return RET_ERR;
    }
    Rosen::VSyncReceiver::FrameCallback fcb = {
        .userData_ = this,
        .callback_ = [this](int64_t parm1, void *parm2) { this->OnVsync(); }
    };
    ret = currentReceiver->RequestNextVSync(fcb);
    if (ret != RET_OK) {
        FI_HILOGE("Request next vsync failed");
    }
    FI_HILOGI("leave");
    return ret;
}

void DragDrawing::OnVsync()
{
    FI_HILOGD("enter");
    CHKPV(rsUiDirector_);
    bool hasRunningAnimation = rsUiDirector_->FlushAnimation(g_drawingInfo.startNum);
    rsUiDirector_->FlushModifier();
    rsUiDirector_->SendMessages();
    if (!hasRunningAnimation) {
        FI_HILOGI("Stop runner, hasRunningAnimation:%{public}d, needDestroyDragWindow:%{public}d",
            hasRunningAnimation, g_drawingInfo.needDestroyDragWindow.load());
        if (g_drawingInfo.needDestroyDragWindow) {
            ResetAnimationFlag();
        }
        return;
    }
    Rosen::VSyncReceiver::FrameCallback fcb = {
        .userData_ = this,
        .callback_ = [this](int64_t parm1, void *parm2) { this->OnVsync(); }
    };
    auto currentReceiver = AccessReceiverLocked();
    CHKPV(currentReceiver);
    int32_t ret = currentReceiver->RequestNextVSync(fcb);
    if (ret != RET_OK) {
        FI_HILOGE("Request next vsync failed");
    }
    rsUiDirector_->SendMessages();
    g_drawingInfo.startNum += INTERVAL_TIME;
    FI_HILOGD("leave");
}

void DragDrawing::InitDrawingInfo(const DragData &dragData, bool isLongPressDrag)
{
    g_drawingInfo.isRunning = true;
    if (dragData.shadowInfos.empty()) {
        FI_HILOGE("ShadowInfos is empty");
        return;
    }
    DragDrawing::UpdataGlobalPixelMapLocked(dragData.shadowInfos.front().pixelMap);
    g_drawingInfo.pixelMapX = dragData.shadowInfos.front().x;
    g_drawingInfo.pixelMapY = dragData.shadowInfos.front().y;
    float dragOriginDpi = DRAG_DATA_MGR.GetDragOriginDpi();
    if (dragOriginDpi > EPSILON) {
        float scalingValue = GetScaling() / dragOriginDpi;
        auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
        CHKPV(currentPixelMap);
        currentPixelMap->scale(scalingValue, scalingValue, Media::AntiAliasingOption::HIGH);
        g_drawingInfo.pixelMapX = g_drawingInfo.pixelMapX * scalingValue;
        g_drawingInfo.pixelMapY = g_drawingInfo.pixelMapY * scalingValue;
        if (fabs(scalingValue - 1.0f) > EPSILON) {
            float widthScale = CalculateWidthScale();
            CHKPV(currentPixelMap);
            currentPixelMap->scale(widthScale, widthScale, Media::AntiAliasingOption::HIGH);
            g_drawingInfo.pixelMapX = g_drawingInfo.pixelMapX * widthScale;
            g_drawingInfo.pixelMapY = g_drawingInfo.pixelMapY * widthScale;
        }
    }
    g_drawingInfo.currentDragNum = dragData.dragNum;
    g_drawingInfo.sourceType = dragData.sourceType;
    g_drawingInfo.displayId = dragData.displayId;
    g_drawingInfo.displayX = dragData.displayX;
    g_drawingInfo.displayY = dragData.displayY;
    RotateDisplayXY(g_drawingInfo.displayX, g_drawingInfo.displayY);
    if (!ParserExtraInfo(dragData.extraInfo, g_drawingInfo.extraInfo)) {
        FI_HILOGI("No parser valid extraInfo data");
    }
    if (!ParserFilterInfo(dragData.filterInfo, g_drawingInfo.filterInfo)) {
        FI_HILOGI("No parser valid filterInfo data");
    }
    size_t shadowInfosSize = dragData.shadowInfos.size();
    for (size_t i = 1; i < shadowInfosSize; ++i) {
        std::shared_ptr<Media::PixelMap> pixelMap = dragData.shadowInfos[i].pixelMap;
        if (dragOriginDpi > EPSILON) {
            float scalingValue = GetScaling() / dragOriginDpi;
            CHKPV(pixelMap);
            pixelMap->scale(scalingValue, scalingValue, Media::AntiAliasingOption::HIGH);
        }
        g_drawingInfo.multiSelectedPixelMaps.emplace_back(pixelMap);
    }
}

int32_t DragDrawing::InitDragAnimationData(DragAnimationData &dragAnimationData)
{
    auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
    CHKPR(currentPixelMap, RET_ERR);
    dragAnimationData.pixelMap = currentPixelMap;
    dragAnimationData.displayX = g_drawingInfo.displayX;
    dragAnimationData.displayY = g_drawingInfo.displayY;
    dragAnimationData.offsetX = g_drawingInfo.pixelMapX;
    dragAnimationData.offsetY = g_drawingInfo.pixelMapY;
    return RET_OK;
}

int32_t DragDrawing::InitLayer()
{
    FI_HILOGI("enter");
    if (g_drawingInfo.surfaceNode == nullptr) {
        FI_HILOGE("Init layer failed, surfaceNode is nullptr");
        return RET_ERR;
    }
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    auto surface = g_drawingInfo.surfaceNode->GetSurface();
    if (surface == nullptr) {
        g_drawingInfo.surfaceNode->DetachFromWindowContainer(g_drawingInfo.displayId);
        g_drawingInfo.surfaceNode = nullptr;
        FI_HILOGE("Init layer failed, surface is nullptr");
        Rosen::RSTransaction::FlushImplicitTransaction();
        return RET_ERR;
    }
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    if (g_drawingInfo.isInitUiDirector) {
        g_drawingInfo.isInitUiDirector = false;
        rsUiDirector_ = Rosen::RSUIDirector::Create();
        CHKPR(rsUiDirector_, RET_ERR);
        rsUiDirector_->Init();
        rsUiDirector_->SetUITaskRunner([this](const std::function<void()>& task, uint32_t delay = 0) {
            CHKPV(this->handler_);
            this->handler_->PostTask(task, delay);
        });
    }
    rsUiDirector_->SetRSSurfaceNode(g_drawingInfo.surfaceNode);
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    int32_t rootNodeSize = std::max(displayWidth_, displayHeight_);
    InitCanvas(rootNodeSize, rootNodeSize);
    FI_HILOGI("Root node size:%{public}d, display Width:%{public}d, display height:%{public}d",
        rootNodeSize, displayWidth_, displayHeight_);
#else
    CHKPR(window_, RET_ERR);
    InitCanvas(window_->GetRect().width_, window_->GetRect().height_);
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    Rosen::Rotation rotation = GetRotation(g_drawingInfo.displayId);
    if (rotation != Rosen::Rotation::ROTATION_0) {
        RotateDragWindow(rotation);
    } else {
        DragWindowRotateInfo_.rotation = ROTATION_0;
    }
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    DragWindowRotationFlush_ = rotation;
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    Rosen::RSTransaction::FlushImplicitTransaction();
    FI_HILOGI("leave");
    return RET_OK;
}

void DragDrawing::InitCanvas(int32_t width, int32_t height)
{
    FI_HILOGI("enter");
    if (g_drawingInfo.rootNode == nullptr) {
        g_drawingInfo.rootNode = Rosen::RSRootNode::Create();
        CHKPV(g_drawingInfo.rootNode);
    }
    g_drawingInfo.rootNode->SetBounds(0, 0, width, height);
    g_drawingInfo.rootNode->SetFrame(0, 0, width, height);
    g_drawingInfo.rootNode->SetBackgroundColor(SK_ColorTRANSPARENT);
    std::shared_ptr<Rosen::RSCanvasNode> filterNode = Rosen::RSCanvasNode::Create();
    CHKPV(filterNode);
    g_drawingInfo.nodes.emplace_back(filterNode);
    ProcessFilter();
    std::shared_ptr<Rosen::RSCanvasNode> pixelMapNode = Rosen::RSCanvasNode::Create();
    CHKPV(pixelMapNode);
    pixelMapNode->SetForegroundColor(TRANSPARENT_COLOR_ARGB);
    pixelMapNode->SetGrayScale(g_drawingInfo.filterInfo.dragNodeGrayscale);
    g_drawingInfo.nodes.emplace_back(pixelMapNode);
    std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = Rosen::RSCanvasNode::Create();
    CHKPV(dragStyleNode);
    g_drawingInfo.nodes.emplace_back(dragStyleNode);
    if (g_drawingInfo.parentNode == nullptr) {
        g_drawingInfo.parentNode = Rosen::RSCanvasNode::Create();
        CHKPV(g_drawingInfo.parentNode);
    }
    g_drawingInfo.parentNode->AddChild(filterNode);
    g_drawingInfo.parentNode->AddChild(pixelMapNode);
    if (!g_drawingInfo.multiSelectedPixelMaps.empty()) {
        InitMultiSelectedNodes();
        if (!g_drawingInfo.multiSelectedNodes.empty()) {
            size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
            for (size_t i = 0; i < multiSelectedNodesSize; ++i) {
                g_drawingInfo.rootNode->AddChild(g_drawingInfo.multiSelectedNodes[i]);
            }
        }
    }
    g_drawingInfo.rootNode->AddChild(g_drawingInfo.parentNode);
    CHKPV(rsUiDirector_);
#ifndef OHOS_BUILD_PC_PRODUCT
    if (g_drawingInfo.sourceType == MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        std::shared_ptr<Rosen::RSCanvasNode> mouseIconNode = Rosen::RSCanvasNode::Create();
        CHKPV(mouseIconNode);
        g_drawingInfo.nodes.emplace_back(mouseIconNode);
        g_drawingInfo.rootNode->AddChild(mouseIconNode);
        rsUiDirector_->SetRSRootNode(Rosen::RSBaseNode::ReinterpretCast<Rosen::RSRootNode>(g_drawingInfo.rootNode));
        FI_HILOGI("leave");
        return;
    }
#endif // OHOS_BUILD_PC_PRODUCT
    rsUiDirector_->SetRSRootNode(Rosen::RSBaseNode::ReinterpretCast<Rosen::RSRootNode>(g_drawingInfo.rootNode));
    FI_HILOGI("leave");
}

void DragDrawing::CreateWindow()
{
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    FI_HILOGI("Parameter screen number:%{public}llu", static_cast<unsigned long long>(screenId_));
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "drag window";
    surfaceNodeConfig.surfaceWindowType = Rosen::SurfaceWindowType::SYSTEM_SCB_WINDOW;
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    g_drawingInfo.surfaceNode = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    CHKPV(g_drawingInfo.surfaceNode);
#ifndef OHOS_BUILD_PC_PRODUCT
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDisplayById(g_drawingInfo.displayId);
#else
    sptr<Rosen::DisplayInfo> display =
        Rosen::DisplayManager::GetInstance().GetVisibleAreaDisplayInfoById(g_drawingInfo.displayId);
#endif // OHOS_BUILD_PC_PRODUCT
    if (display == nullptr) {
        FI_HILOGD("Get display info failed, display:%{public}d", g_drawingInfo.displayId);
#ifndef OHOS_BUILD_PC_PRODUCT
        display = Rosen::DisplayManager::GetInstance().GetDisplayById(0);
#else
        display = Rosen::DisplayManager::GetInstance().GetVisibleAreaDisplayInfoById(0);
#endif // OHOS_BUILD_PC_PRODUCT
        if (display == nullptr) {
            FI_HILOGE("Get display info failed, display is nullptr");
            return;
        }
    }
    uint64_t rsScreenId = screenId_;
    displayWidth_ = display->GetWidth();
    displayHeight_ = display->GetHeight();
#ifndef OHOS_BUILD_PC_PRODUCT
    sptr<Rosen::Screen> screen = Rosen::ScreenManager::GetInstance().GetScreenById(screenId_);
    if ((screen != nullptr) && (!screen->IsReal())) {
        if (!Rosen::DisplayManager::GetInstance().ConvertScreenIdToRsScreenId(screenId_, rsScreenId)) {
            FI_HILOGE("ConvertScreenIdToRsScreenId failed");
            return;
        }
    }
#else
    if (!Rosen::DisplayManager::GetInstance().ConvertScreenIdToRsScreenId(screenId_, rsScreenId)) {
        FI_HILOGE("ConvertScreenIdToRsScreenId failed");
        return;
    }
#endif // OHOS_BUILD_PC_PRODUCT
    screenId_ = rsScreenId;
    FI_HILOGI("Parameter rsScreen number:%{public}llu", static_cast<unsigned long long>(rsScreenId));
    int32_t surfaceNodeSize = std::max(displayWidth_, displayHeight_);
    g_drawingInfo.surfaceNode->SetBounds(0, 0, surfaceNodeSize, surfaceNodeSize);
#else
    CHKPV(window_);
    g_drawingInfo.surfaceNode = window_->GetSurfaceNode();
    CHKPV(g_drawingInfo.surfaceNode);
    g_drawingInfo.surfaceNode->SetBounds(0, 0, window_->GetRect().width_, window_->GetRect().height_);
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    g_drawingInfo.surfaceNode->SetFrameGravity(Rosen::Gravity::RESIZE_ASPECT_FILL);
    g_drawingInfo.surfaceNode->SetPositionZ(DRAG_WINDOW_POSITION_Z);
    g_drawingInfo.surfaceNode->SetBackgroundColor(SK_ColorTRANSPARENT);
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    g_drawingInfo.surfaceNode->AttachToWindowContainer(rsScreenId);
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    g_drawingInfo.surfaceNode->SetVisible(false);
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void DragDrawing::RemoveModifier()
{
    FI_HILOGD("enter");
    if ((g_drawingInfo.nodes.size() < TOUCH_NODE_MIN_COUNT)) {
        FI_HILOGE("Nodes size invalid, node size:%{public}zu", g_drawingInfo.nodes.size());
        return;
    }

    if (g_drawingInfo.nodes.size() <= PIXEL_MAP_INDEX || g_drawingInfo.nodes.size() <= DRAG_STYLE_INDEX) {
        FI_HILOGE("The index is out of bounds, node size is %{public}zu", g_drawingInfo.nodes.size());
        return;
    }
    std::shared_ptr<Rosen::RSCanvasNode> pixelMapNode = g_drawingInfo.nodes[PIXEL_MAP_INDEX];
    CHKPV(pixelMapNode);
    if (drawPixelMapModifier_ != nullptr) {
        pixelMapNode->RemoveModifier(drawPixelMapModifier_);
        drawPixelMapModifier_ = nullptr;
    }
    std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
    CHKPV(dragStyleNode);
    if (drawSVGModifier_ != nullptr) {
        dragStyleNode->RemoveModifier(drawSVGModifier_);
        drawSVGModifier_ = nullptr;
    }

    if (drawStyleChangeModifier_ != nullptr) {
        dragStyleNode->RemoveModifier(drawStyleChangeModifier_);
        drawStyleChangeModifier_ = nullptr;
    }

    if (drawStyleScaleModifier_ != nullptr) {
        dragStyleNode->RemoveModifier(drawStyleScaleModifier_);
        drawStyleScaleModifier_ = nullptr;
    }
    FI_HILOGD("leave");
}

int32_t DragDrawing::UpdateSvgNodeInfo(xmlNodePtr curNode, int32_t extendSvgWidth)
{
    FI_HILOGD("enter");
    if (xmlStrcmp(curNode->name, BAD_CAST "svg")) {
        FI_HILOGE("Svg format invalid");
        return RET_ERR;
    }
    std::ostringstream oStrStream;
    xmlChar* widthProp = xmlGetProp(curNode, BAD_CAST "width");
    oStrStream << widthProp;
    std::string srcSvgWidth = oStrStream.str();
    xmlFree(widthProp);
    if (srcSvgWidth.length() < STRING_PX_LENGTH) {
        FI_HILOGE("Svg width invalid, srcSvgWidth:%{public}s", srcSvgWidth.c_str());
        return RET_ERR;
    }
    srcSvgWidth = srcSvgWidth.substr(0, srcSvgWidth.length() - STRING_PX_LENGTH);
    if (!IsNum(srcSvgWidth)) {
        FI_HILOGE("srcSvgWidth is not digital, srcSvgWidth:%{public}s", srcSvgWidth.c_str());
        return RET_ERR;
    }
    int32_t number = std::stoi(srcSvgWidth) + extendSvgWidth;
    std::string tgtSvgWidth = std::to_string(number);
    tgtSvgWidth.append("px");
    xmlSetProp(curNode, BAD_CAST "width", BAD_CAST tgtSvgWidth.c_str());
    oStrStream.str("");
    xmlChar* viewBoxProp = xmlGetProp(curNode, BAD_CAST "viewBox");
    oStrStream << viewBoxProp;
    std::string srcViewBox = oStrStream.str();
    std::istringstream iStrStream(srcViewBox);
    xmlFree(viewBoxProp);
    std::string tmpString;
    std::string tgtViewBox;
    int32_t i = 0;
    while (iStrStream >> tmpString) {
        if (i == VIEW_BOX_POS) {
            if (!IsNum(tmpString)) {
                FI_HILOGE("tmpString is not digital, tmpString:%{public}s", tmpString.c_str());
                return RET_ERR;
            }
            number = std::stoi(tmpString) + extendSvgWidth;
            tmpString = std::to_string(number);
        }
        tgtViewBox.append(tmpString);
        tgtViewBox += " ";
        ++i;
    }

    xmlSetProp(curNode, BAD_CAST "viewBox", BAD_CAST tgtViewBox.c_str());
    FI_HILOGD("leave");
    return RET_OK;
}

xmlNodePtr DragDrawing::GetRectNode(xmlNodePtr curNode)
{
    FI_HILOGD("enter");
    curNode = curNode->xmlChildrenNode;
    while (curNode != nullptr) {
        if (!xmlStrcmp(curNode->name, BAD_CAST "g")) {
            while (!xmlStrcmp(curNode->name, BAD_CAST "g")) {
                curNode = curNode->xmlChildrenNode;
            }
            break;
        }
        curNode = curNode->next;
    }
    FI_HILOGD("leave");
    return curNode;
}

xmlNodePtr DragDrawing::UpdateRectNode(int32_t extendSvgWidth, xmlNodePtr curNode)
{
    FI_HILOGD("enter");
    while (curNode != nullptr) {
        if (!xmlStrcmp(curNode->name, BAD_CAST "rect")) {
            std::ostringstream oStrStream;
            xmlChar* widthProp = xmlGetProp(curNode, BAD_CAST "width");
            oStrStream << widthProp;
            std::string srcRectWidth = oStrStream.str();
            xmlFree(widthProp);
            if (!IsNum(srcRectWidth)) {
                FI_HILOGE("srcRectWidth is not digital, srcRectWidth:%{public}s", srcRectWidth.c_str());
                return nullptr;
            }
            int32_t number = std::stoi(srcRectWidth) + extendSvgWidth;
            xmlSetProp(curNode, BAD_CAST "width", BAD_CAST std::to_string(number).c_str());
        }
        if (!xmlStrcmp(curNode->name, BAD_CAST "text")) {
            return curNode->xmlChildrenNode;
        }
        curNode = curNode->next;
    }
    FI_HILOGE("Empty node of XML");
    return nullptr;
}

void DragDrawing::UpdateTspanNode(xmlNodePtr curNode)
{
    FI_HILOGD("enter");
    while (curNode != nullptr) {
        if (!xmlStrcmp(curNode->name, BAD_CAST "tspan")) {
            xmlNodeSetContent(curNode, BAD_CAST std::to_string(g_drawingInfo.currentDragNum).c_str());
        }
        curNode = curNode->next;
    }
    FI_HILOGD("leave");
}

int32_t DragDrawing::ParseAndAdjustSvgInfo(xmlNodePtr curNode)
{
    FI_HILOGD("enter");
    CHKPR(curNode, RET_ERR);
    std::string strStyle = std::to_string(g_drawingInfo.currentDragNum);
    if (strStyle.empty()) {
        FI_HILOGE("strStyle size:%{public}zu invalid", strStyle.size());
        return RET_ERR;
    }
    int32_t extendSvgWidth = (static_cast<int32_t>(strStyle.size()) - 1) * EIGHT_SIZE;
    xmlKeepBlanksDefault(0);
    int32_t ret = UpdateSvgNodeInfo(curNode, extendSvgWidth);
    if (ret != RET_OK) {
        FI_HILOGE("Update svg node info failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    curNode = GetRectNode(curNode);
    CHKPR(curNode, RET_ERR);
    curNode = UpdateRectNode(extendSvgWidth, curNode);
    CHKPR(curNode, RET_ERR);
    UpdateTspanNode(curNode);
    FI_HILOGD("leave");
    return RET_OK;
}

std::shared_ptr<Media::PixelMap> DragDrawing::DecodeSvgToPixelMap(
    const std::string &filePath)
{
    FI_HILOGD("enter");
    xmlDocPtr xmlDoc = xmlReadFile(filePath.c_str(), 0, XML_PARSE_NOBLANKS);
    if (NeedAdjustSvgInfo()) {
        xmlNodePtr node = xmlDocGetRootElement(xmlDoc);
        CHKPP(node);
        int32_t ret = ParseAndAdjustSvgInfo(node);
        if (ret != RET_OK) {
            FI_HILOGE("Parse and adjust svg info failed, ret:%{public}d", ret);
            xmlFreeDoc(xmlDoc);
            return nullptr;
        }
    }
    xmlChar *xmlbuff = nullptr;
    int32_t buffersize = 0;
    xmlDocDumpFormatMemory(xmlDoc, &xmlbuff, &buffersize, 1);
    std::ostringstream oStrStream;
    oStrStream << xmlbuff;
    std::string content = oStrStream.str();
    xmlFree(xmlbuff);
    xmlFreeDoc(xmlDoc);
    Media::SourceOptions opts;
    opts.formatHint = "image/svg+xml";
    uint32_t errCode = 0;
    auto imageSource = Media::ImageSource::CreateImageSource(reinterpret_cast<const uint8_t*>(content.c_str()),
        content.size(), opts, errCode);
    CHKPP(imageSource);
    Media::DecodeOptions decodeOpts;
    SetDecodeOptions(decodeOpts);
    std::shared_ptr<Media::PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errCode);
    FI_HILOGD("leave");
    return pixelMap;
}

bool DragDrawing::NeedAdjustSvgInfo()
{
    FI_HILOGD("enter");
    if (g_drawingInfo.currentStyle == DragCursorStyle::DEFAULT) {
        return false;
    }
    if ((g_drawingInfo.currentStyle == DragCursorStyle::COPY) &&
        (g_drawingInfo.currentDragNum == DRAG_NUM_ONE)) {
        return false;
    }
    if ((g_drawingInfo.currentStyle == DragCursorStyle::MOVE) &&
        (g_drawingInfo.currentDragNum == DRAG_NUM_ONE)) {
        return false;
    }
    if ((g_drawingInfo.currentStyle == DragCursorStyle::FORBIDDEN) &&
        (g_drawingInfo.currentDragNum == DRAG_NUM_ONE)) {
        return false;
    }
    FI_HILOGD("leave");
    return true;
}

void DragDrawing::GetFilePath(std::string &filePath)
{
    FI_HILOGD("enter");
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    if (isRTL_) {
        GetRTLFilePath(filePath);
    } else {
        GetLTRFilePath(filePath);
    }
#else
    GetLTRFilePath(filePath);
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    FI_HILOGD("leave");
}
 
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
void DragDrawing::GetLTRFilePath(std::string &filePath)
{
    FI_HILOGD("enter");
    switch (g_drawingInfo.currentStyle) {
        case DragCursorStyle::COPY: {
            if (g_drawingInfo.currentDragNum == DRAG_NUM_ONE) {
                filePath = COPY_ONE_DRAG_PATH;
            } else {
                filePath = COPY_DRAG_PATH;
            }
            break;
        }
        case DragCursorStyle::MOVE: {
            filePath = MOVE_DRAG_PATH;
            break;
        }
        case DragCursorStyle::FORBIDDEN: {
            if (g_drawingInfo.currentDragNum == DRAG_NUM_ONE) {
                filePath = FORBID_ONE_DRAG_PATH;
            } else {
                filePath = FORBID_DRAG_PATH;
            }
            break;
        }
        case DragCursorStyle::DEFAULT:
        default: {
            FI_HILOGW("Not need draw svg style, DragCursorStyle:%{public}d", g_drawingInfo.currentStyle);
            break;
        }
    }
    FI_HILOGD("leave");
}
 
void DragDrawing::GetRTLFilePath(std::string &filePath)
{
    FI_HILOGD("enter");
    switch (g_drawingInfo.currentStyle) {
        case DragCursorStyle::COPY: {
            if (g_drawingInfo.currentDragNum == DRAG_NUM_ONE) {
                filePath = COPY_ONE_DRAG_RTL_PATH;
            } else {
                filePath = COPY_DRAG_RTL_PATH;
            }
            break;
        }
        case DragCursorStyle::MOVE: {
            filePath = MOVE_DRAG_RTL_PATH;
            break;
        }
        case DragCursorStyle::FORBIDDEN: {
            if (g_drawingInfo.currentDragNum == DRAG_NUM_ONE) {
                filePath = FORBID_ONE_DRAG_RTL_PATH;
            } else {
                filePath = FORBID_DRAG_RTL_PATH;
            }
            break;
        }
        case DragCursorStyle::DEFAULT:
        default: {
            FI_HILOGW("Not need draw svg style, DragCursorStyle:%{public}d", g_drawingInfo.currentStyle);
            break;
        }
    }
    FI_HILOGD("leave");
}
#else
void DragDrawing::GetLTRFilePath(std::string &filePath)
{
    FI_HILOGD("enter");
    switch (g_drawingInfo.currentStyle) {
        case DragCursorStyle::COPY: {
            if (g_drawingInfo.currentDragNum == DRAG_NUM_ONE) {
                filePath = svgFilePath_ + COPY_ONE_DRAG_NAME;
            } else {
                filePath = svgFilePath_ + COPY_DRAG_NAME;
            }
            break;
        }
        case DragCursorStyle::MOVE: {
            filePath = svgFilePath_ + MOVE_DRAG_NAME;
            break;
        }
        case DragCursorStyle::FORBIDDEN: {
            if (g_drawingInfo.currentDragNum == DRAG_NUM_ONE) {
                filePath = svgFilePath_ + FORBID_ONE_DRAG_NAME;
            } else {
                filePath = svgFilePath_ + FORBID_DRAG_NAME;
            }
            break;
        }
        case DragCursorStyle::DEFAULT:
        default: {
            FI_HILOGW("Not need draw svg style, DragCursorStyle:%{public}d", g_drawingInfo.currentStyle);
            break;
        }
    }
    FI_HILOGD("leave");
}
#endif // OHOS_BUILD_ENABLE_ARKUI_X

void DragDrawing::SetDecodeOptions(Media::DecodeOptions &decodeOpts)
{
    FI_HILOGD("enter");
    std::string strStyle = std::to_string(g_drawingInfo.currentDragNum);
    if (strStyle.empty()) {
        FI_HILOGE("strStyle size:%{public}zu invalid", strStyle.size());
        return;
    }
    int32_t extendSvgWidth = (static_cast<int32_t>(strStyle.size()) - 1) * EIGHT_SIZE;
    if ((g_drawingInfo.currentStyle == DragCursorStyle::COPY) && (g_drawingInfo.currentDragNum == DRAG_NUM_ONE)) {
        decodeOpts.desiredSize = {
            .width = DEVICE_INDEPENDENT_PIXEL * GetScaling(),
            .height = DEVICE_INDEPENDENT_PIXEL * GetScaling()
        };
    } else {
        decodeOpts.desiredSize = {
            .width = (DEVICE_INDEPENDENT_PIXEL + extendSvgWidth) * GetScaling(),
            .height = DEVICE_INDEPENDENT_PIXEL * GetScaling()
        };
    }
    FI_HILOGD("leave");
}

void DragDrawing::ParserDragShadowInfo(const cJSON* filterInfoParser, FilterInfo &filterInfo)
{
    CHKPV(filterInfoParser);
    cJSON *offsetX = cJSON_GetObjectItemCaseSensitive(filterInfoParser, "drag_shadow_offsetX");
    if (cJSON_IsNumber(offsetX)) {
        filterInfo.offsetX = static_cast<float>(offsetX->valuedouble);
    }
    cJSON *offsetY = cJSON_GetObjectItemCaseSensitive(filterInfoParser, "drag_shadow_offsetY");
    if (cJSON_IsNumber(offsetY)) {
        filterInfo.offsetY = static_cast<float>(offsetY->valuedouble);
    }
    cJSON *argb = cJSON_GetObjectItemCaseSensitive(filterInfoParser, "drag_shadow_argb");
    if (cJSON_IsNumber(argb)) {
        filterInfo.argb = static_cast<uint32_t>(argb->valueint);
    }
    cJSON *shadowIsFilled   = cJSON_GetObjectItemCaseSensitive(filterInfoParser, "shadow_is_filled");
    if (cJSON_IsBool(shadowIsFilled)) {
        filterInfo.shadowIsFilled = cJSON_IsTrue(shadowIsFilled);
    }
    cJSON *shadowMask   = cJSON_GetObjectItemCaseSensitive(filterInfoParser, "shadow_mask");
    if (cJSON_IsBool(shadowMask)) {
        filterInfo.shadowMask = cJSON_IsTrue(shadowMask);
    }
    cJSON *shadowColorStrategy  = cJSON_GetObjectItemCaseSensitive(filterInfoParser, "shadow_color_strategy");
    if (cJSON_IsNumber(shadowColorStrategy)) {
        filterInfo.shadowColorStrategy = shadowColorStrategy->valueint;
    }
    cJSON *isHardwareAcceleration  = cJSON_GetObjectItemCaseSensitive(
        filterInfoParser, "shadow_is_hardwareacceleration");
    if (cJSON_IsBool(isHardwareAcceleration)) {
        filterInfo.isHardwareAcceleration = cJSON_IsTrue(isHardwareAcceleration);
    }
    if (filterInfo.isHardwareAcceleration) {
        cJSON *elevation  = cJSON_GetObjectItemCaseSensitive(filterInfoParser, "shadow_elevation");
        if (cJSON_IsNumber(elevation)) {
            filterInfo.elevation = static_cast<float>(elevation->valuedouble);
        }
    } else {
        cJSON *shadowCorner = cJSON_GetObjectItemCaseSensitive(filterInfoParser, "shadow_corner");
        if (cJSON_IsNumber(shadowCorner)) {
            filterInfo.shadowCorner = static_cast<float>(shadowCorner->valuedouble);
        }
    }
}

void DragDrawing::ParserTextDragShadowInfo(const cJSON* filterInfoParser, FilterInfo &filterInfo)
{
    CHKPV(filterInfoParser);
    cJSON *path = cJSON_GetObjectItemCaseSensitive(filterInfoParser, "drag_shadow_path");
    if (cJSON_IsString(path)) {
        float dragOriginDpi = DRAG_DATA_MGR.GetDragOriginDpi();
        if (dragOriginDpi > EPSILON) {
            filterInfo.path = "";
        } else {
            filterInfo.path = path->valuestring;
        }
    }
}

void DragDrawing::PrintDragShadowInfo()
{
    FilterInfo filterInfo = g_drawingInfo.filterInfo;
    if (!filterInfo.shadowEnable) {
        FI_HILOGI("Not supported shadow");
        return;
    }
    FI_HILOGI("dragType:%{public}s, shadowIsFilled:%{public}s, shadowMask:%{public}s, shadowColorStrategy :%{public}d, "
        "shadowCorner:%{public}f, offsetX:%{private}f, offsetY:%{private}f, argb:%{public}u, elevation:%{public}f, "
        "isHardwareAcceleration:%{public}s", filterInfo.dragType.c_str(),
        filterInfo.shadowIsFilled ? "true" : "false", filterInfo.shadowMask ? "true" : "false",
        filterInfo.shadowColorStrategy, filterInfo.shadowCorner, filterInfo.offsetX, filterInfo.offsetY,
        filterInfo.argb, filterInfo.elevation, filterInfo.isHardwareAcceleration ? "true" : "false");
    if (!filterInfo.path.empty()) {
        FI_HILOGI("path:%{private}s", filterInfo.path.c_str());
    }
}

bool DragDrawing::ParserFilterInfo(const std::string &filterInfoStr, FilterInfo &filterInfo)
{
    FI_HILOGD("FilterInfo size:%{public}zu, filterInfo:%{public}s", filterInfoStr.size(), filterInfoStr.c_str());
    if (filterInfoStr.empty()) {
        FI_HILOGD("FilterInfo is empty");
        return false;
    }
    JsonParser filterInfoParser(filterInfoStr.c_str());
    if (!cJSON_IsObject(filterInfoParser.Get())) {
        FI_HILOGE("FilterInfo is not json object");
        return false;
    }
    cJSON *dipScale = cJSON_GetObjectItemCaseSensitive(filterInfoParser.Get(), "dip_scale");
    if (cJSON_IsNumber(dipScale)) {
        filterInfo.dipScale = AdjustDoubleValue(dipScale->valuedouble);
    }
    cJSON *scale = cJSON_GetObjectItemCaseSensitive(filterInfoParser.Get(), "scale");
    if (cJSON_IsNumber(scale)) {
        filterInfo.scale = AdjustDoubleValue(scale->valuedouble);
    }
    ParserCornerRadiusInfo(filterInfoParser.Get(), g_drawingInfo.filterInfo);
    cJSON *dragType = cJSON_GetObjectItemCaseSensitive(filterInfoParser.Get(), "drag_type");
    if (cJSON_IsString(dragType)) {
        filterInfo.dragType = dragType->valuestring;
    }
    cJSON *shadowEnable = cJSON_GetObjectItemCaseSensitive(filterInfoParser.Get(), "shadow_enable");
    if (cJSON_IsBool(shadowEnable)) {
        filterInfo.shadowEnable = cJSON_IsTrue(shadowEnable);
    }
    if (filterInfo.shadowEnable) {
        ParserDragShadowInfo(filterInfoParser.Get(), filterInfo);
        if (filterInfo.dragType == "text") {
            ParserTextDragShadowInfo(filterInfoParser.Get(), filterInfo);
        }
        PrintDragShadowInfo();
    }
    ParserBlurInfo(filterInfoParser.Get(), g_drawingInfo.filterInfo);
    cJSON *dragNodeGrayscale = cJSON_GetObjectItemCaseSensitive(filterInfoParser.Get(), "drag_node_gray_scale");
    if (cJSON_IsNumber(dragNodeGrayscale)) {
        filterInfo.dragNodeGrayscale = static_cast<float>(dragNodeGrayscale->valuedouble);
    }
    cJSON *eventId = cJSON_GetObjectItemCaseSensitive(filterInfoParser.Get(), "event_id");
    if (cJSON_IsNumber(eventId)) {
        DRAG_DATA_MGR.SetEventId(eventId->valueint);
    }
    cJSON *enableAnimation = cJSON_GetObjectItemCaseSensitive(filterInfoParser.Get(), "enable_animation");
    if (cJSON_IsBool(enableAnimation)) {
        filterInfo.enableAnimation = cJSON_IsTrue(enableAnimation) ? true : false;
    }
    return true;
}

void DragDrawing::ParserCornerRadiusInfo(const cJSON *cornerRadiusInfoStr, FilterInfo &filterInfo)
{
    CHKPV(cornerRadiusInfoStr);
    cJSON *cornerRadius1 = cJSON_GetObjectItemCaseSensitive(cornerRadiusInfoStr, "drag_corner_radius1");
    if (cJSON_IsNumber(cornerRadius1)) {
        filterInfo.cornerRadius1 = static_cast<float>(cornerRadius1->valuedouble);
    }
    cJSON *cornerRadius2 = cJSON_GetObjectItemCaseSensitive(cornerRadiusInfoStr, "drag_corner_radius2");
    if (cJSON_IsNumber(cornerRadius2)) {
        filterInfo.cornerRadius2 = static_cast<float>(cornerRadius2->valuedouble);
    }
    cJSON *cornerRadius3 = cJSON_GetObjectItemCaseSensitive(cornerRadiusInfoStr, "drag_corner_radius3");
    if (cJSON_IsNumber(cornerRadius3)) {
        filterInfo.cornerRadius3 = static_cast<float>(cornerRadius3->valuedouble);
    }
    cJSON *cornerRadius4 = cJSON_GetObjectItemCaseSensitive(cornerRadiusInfoStr, "drag_corner_radius4");
    if (cJSON_IsNumber(cornerRadius4)) {
        filterInfo.cornerRadius4 = static_cast<float>(cornerRadius4->valuedouble);
    }
}

void DragDrawing::ParserBlurInfo(const cJSON *BlurInfoInfoStr, FilterInfo &filterInfo)
{
    CHKPV(BlurInfoInfoStr);
    cJSON *opacity = cJSON_GetObjectItemCaseSensitive(BlurInfoInfoStr, "dip_opacity");
    if (cJSON_IsNumber(opacity)) {
        if ((opacity->valuedouble) > MAX_OPACITY || (opacity->valuedouble) <= MIN_OPACITY) {
            FI_HILOGE("Parser opacity limits abnormal, opacity:%{public}f", opacity->valuedouble);
        } else {
            filterInfo.opacity = static_cast<float>(opacity->valuedouble);
        }
    }
    float tempCoef1 = 0.0f;
    cJSON *coef1 = cJSON_GetObjectItemCaseSensitive(BlurInfoInfoStr, "blur_coef1");
    if (cJSON_IsNumber(coef1)) {
        tempCoef1 = static_cast<float>(coef1->valuedouble);
    }
    float tempCoef2 = 0.0f;
    cJSON *coef2 = cJSON_GetObjectItemCaseSensitive(BlurInfoInfoStr, "blur_coef2");
    if (cJSON_IsNumber(coef2)) {
        tempCoef2 = static_cast<float>(coef2->valuedouble);
    }
    filterInfo.coef = { tempCoef1, tempCoef2 };
    cJSON *blurRadius = cJSON_GetObjectItemCaseSensitive(BlurInfoInfoStr, "blur_radius");
    if (cJSON_IsNumber(blurRadius)) {
        filterInfo.blurRadius = AdjustDoubleValue(blurRadius->valuedouble);
    }
    cJSON *blurStaturation = cJSON_GetObjectItemCaseSensitive(BlurInfoInfoStr, "blur_staturation");
    if (cJSON_IsNumber(blurStaturation)) {
        filterInfo.blurStaturation = static_cast<float>(blurStaturation->valuedouble);
    }
    cJSON *blurBrightness = cJSON_GetObjectItemCaseSensitive(BlurInfoInfoStr, "blur_brightness");
    if (cJSON_IsNumber(blurBrightness)) {
        filterInfo.blurBrightness = static_cast<float>(blurBrightness->valuedouble);
    }
    cJSON *blurColor = cJSON_GetObjectItemCaseSensitive(BlurInfoInfoStr, "blur_color");
    if (cJSON_IsNumber(blurColor)) {
        filterInfo.blurColor = static_cast<uint32_t>(blurColor->valueint);
    }
    cJSON *blurStyle = cJSON_GetObjectItemCaseSensitive(BlurInfoInfoStr, "blur_style");
    if (cJSON_IsNumber(blurStyle)) {
        filterInfo.blurStyle = blurStyle->valueint;
    }
    return;
}

bool DragDrawing::ParserExtraInfo(const std::string &extraInfoStr, ExtraInfo &extraInfo)
{
    FI_HILOGD("ExtraInfo size:%{public}zu, extraInfo:%{public}s",
        extraInfoStr.size(), extraInfoStr.c_str());
    if (extraInfoStr.empty()) {
        FI_HILOGD("ExtraInfo is empty");
        return false;
    }
    JsonParser extraInfoParser(extraInfoStr.c_str());
    if (!cJSON_IsObject(extraInfoParser.Get())) {
        FI_HILOGE("ExtraInfo is not json object");
        return false;
    }
    cJSON *componentType = cJSON_GetObjectItemCaseSensitive(extraInfoParser.Get(), "drag_data_type");
    if (cJSON_IsString(componentType)) {
        extraInfo.componentType = componentType->valuestring;
    }
    cJSON *blurStyle = cJSON_GetObjectItemCaseSensitive(extraInfoParser.Get(), "drag_blur_style");
    if (cJSON_IsNumber(blurStyle)) {
        extraInfo.blurStyle = blurStyle->valueint;
    }
    cJSON *cornerRadius = cJSON_GetObjectItemCaseSensitive(extraInfoParser.Get(), "drag_corner_radius");
    if (cJSON_IsNumber(cornerRadius)) {
        extraInfo.cornerRadius = static_cast<float>(cornerRadius->valuedouble);
    }
    cJSON *allowDistributed = cJSON_GetObjectItemCaseSensitive(extraInfoParser.Get(), "drag_allow_distributed");
    if (cJSON_IsBool(allowDistributed)) {
        extraInfo.allowDistributed = cJSON_IsTrue(allowDistributed) ? true : false;
    }
    float tempCoef1 = 0.0f;
    cJSON *coef1 = cJSON_GetObjectItemCaseSensitive(extraInfoParser.Get(), "blur_coef1");
    if (cJSON_IsNumber(coef1)) {
        tempCoef1 = static_cast<float>(coef1->valuedouble);
    }
    float tempCoef2 = 0.0f;
    cJSON *coef2 = cJSON_GetObjectItemCaseSensitive(extraInfoParser.Get(), "blur_coef2");
    if (cJSON_IsNumber(coef2)) {
        tempCoef2 = static_cast<float>(coef2->valuedouble);
    }
    extraInfo.coef = { tempCoef1, tempCoef2 };
    return true;
}

bool DragDrawing::GetAllowDragState()
{
    return g_drawingInfo.extraInfo.allowDistributed;
}

void DragDrawing::SetScreenId(uint64_t screenId)
{
    FI_HILOGD("enter");
    screenId_ = screenId;
}

int32_t DragDrawing::RotateDragWindow(Rosen::Rotation rotation,
    const std::shared_ptr<Rosen::RSTransaction>& rsTransaction, bool isAnimated)
{
    if (needRotatePixelMapXY_) {
        auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
        CHKPR(currentPixelMap, RET_ERR);
        g_drawingInfo.pixelMapX = -(HALF_RATIO * currentPixelMap->GetWidth());
        g_drawingInfo.pixelMapY = -(EIGHT_SIZE * GetScaling());
    }
    float rotateAngle = (rotation == Rosen::Rotation::ROTATION_0) ? ROTATION_0 :
        ROTATION_360 - (ROTATION_90 * static_cast<int32_t>(rotation));
    FI_HILOGI("rotateAngle:%{public}f, isAnimated:%{public}d", rotateAngle, isAnimated);
    return DoRotateDragWindow(rotateAngle, rsTransaction, isAnimated);
}

void DragDrawing::RotateCanvasNode(float pivotX, float pivotY, float rotation)
{
    FI_HILOGD("enter");
    CHKPV(g_drawingInfo.parentNode);
    g_drawingInfo.parentNode->SetPivot(pivotX, pivotY);
    g_drawingInfo.parentNode->SetRotation(rotation);
    if (!g_drawingInfo.multiSelectedNodes.empty()) {
        size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
        for (size_t i = 0; i < multiSelectedNodesSize; ++i) {
            std::shared_ptr<Rosen::RSCanvasNode> multiSelectedNode = g_drawingInfo.multiSelectedNodes[i];
            CHKPV(multiSelectedNode);
            float degrees = DEFAULT_ANGLE;
            if (i == FIRST_PIXELMAP_INDEX) {
                degrees = rotation + POSITIVE_ANGLE;
            } else if (i == SECOND_PIXELMAP_INDEX) {
                degrees = rotation + NEGATIVE_ANGLE;
            }
            multiSelectedNode->SetPivot(HALF_PIVOT, HALF_PIVOT);
            multiSelectedNode->SetRotation(degrees);
        }
    }
#ifndef OHOS_BUILD_PC_PRODUCT
    if (g_drawingInfo.sourceType == MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        if (!CheckNodesValid()) {
            FI_HILOGE("Check nodes valid failed");
            return;
        }
        std::shared_ptr<Rosen::RSCanvasNode> mouseIconNode = g_drawingInfo.nodes[MOUSE_ICON_INDEX];
        CHKPV(mouseIconNode);
        mouseIconNode->SetPivot(DEFAULT_PIVOT, DEFAULT_PIVOT);
        mouseIconNode->SetRotation(rotation);
    }
#endif // OHOS_BUILD_PC_PRODUCT
    float positionX = g_drawingInfo.currentPositionX;
    float positionY = g_drawingInfo.currentPositionY;
    AdjustRotateDisplayXY(positionX, positionY);
    DrawRotateDisplayXY(positionX, positionY);
    FI_HILOGD("leave");
}

void DragDrawing::SetRotation(Rosen::DisplayId displayId, Rosen::Rotation rotation)
{
    FI_HILOGI("displayId:%{public}d, rotation:%{public}d",
        static_cast<int32_t>(displayId), static_cast<int32_t>(rotation));
    auto iter = rotationMap_.find(displayId);
    if (iter == rotationMap_.end()) {
        rotationMap_.emplace(displayId, rotation);
        FI_HILOGW("Create a new element");
        return;
    }
    if (iter->second != rotation) {
        rotationMap_[displayId] = rotation;
    }
}

Rosen::Rotation DragDrawing::GetRotation(Rosen::DisplayId displayId)
{
    if (!rotationMap_.empty()) {
        auto iter = rotationMap_.find(displayId);
        if (iter != rotationMap_.end()) {
            FI_HILOGD("displayId:%{public}d, rotation:%{public}d",
                static_cast<int32_t>(iter->first), static_cast<int32_t>(iter->second));
            return iter->second;
        }
    }
    return Rosen::Rotation::ROTATION_0;
}

void DragDrawing::RemoveDisplayIdFromMap(Rosen::DisplayId displayId)
{
    FI_HILOGI("displayId:%{public}d", static_cast<int32_t>(displayId));
    if (rotationMap_.empty()) {
        FI_HILOGE("rotation map is empty");
        return;
    }
    auto iter = rotationMap_.find(displayId);
    if (iter == rotationMap_.end()) {
        FI_HILOGW("displayId does not exist in rotation map");
        return;
    }
    rotationMap_.erase(displayId);
}

void DragDrawing::ProcessFilter()
{
    FI_HILOGD("enter");
    if (g_drawingInfo.nodes.size() <= BACKGROUND_FILTER_INDEX) {
        FI_HILOGE("The index is out of bounds, node size is %{public}zu", g_drawingInfo.nodes.size());
        return;
    }
    std::shared_ptr<Rosen::RSCanvasNode> filterNode = g_drawingInfo.nodes[BACKGROUND_FILTER_INDEX];
    CHKPV(filterNode);
    auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
    CHKPV(currentPixelMap);
    FilterInfo filterInfo = g_drawingInfo.filterInfo;
    ExtraInfo extraInfo = g_drawingInfo.extraInfo;
    if (filterInfo.blurStyle != -1) {
        SetCustomDragBlur(filterInfo, filterNode);
    } else if (extraInfo.componentType == BIG_FOLDER_LABEL) {
        SetComponentDragBlur(filterInfo, extraInfo, filterNode);
    }
    FI_HILOGD("Add filter successfully");
    FI_HILOGD("leave");
}

void DragDrawing::SetCustomDragBlur(const FilterInfo &filterInfo, std::shared_ptr<Rosen::RSCanvasNode> filterNode)
{
    CHKPV(filterNode);
    auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
    CHKPV(currentPixelMap);
    Rosen::BLUR_COLOR_MODE mode = (Rosen::BLUR_COLOR_MODE)filterInfo.blurStyle;
    std::shared_ptr<Rosen::RSFilter> backFilter = Rosen::RSFilter::CreateMaterialFilter(
        RadiusVp2Sigma(filterInfo.blurRadius, filterInfo.dipScale),
        filterInfo.blurStaturation, filterInfo.blurBrightness, filterInfo.blurColor, mode);
    if (backFilter == nullptr) {
        FI_HILOGE("Create backgroundFilter failed");
        return;
    }
    filterNode->SetBackgroundFilter(backFilter);
    filterNode->SetGreyCoef(filterInfo.coef);
    filterNode->SetAlpha(filterInfo.opacity);
    int32_t adjustSize = TWELVE_SIZE * GetScaling();
    filterNode->SetBounds(DEFAULT_POSITION_X, adjustSize, currentPixelMap->GetWidth(),
        currentPixelMap->GetHeight());
    filterNode->SetFrame(DEFAULT_POSITION_X, adjustSize, currentPixelMap->GetWidth(),
        currentPixelMap->GetHeight());
    if ((filterInfo.blurRadius < 0) || (filterInfo.dipScale < 0) ||
        (fabs(filterInfo.dipScale) < EPSILON) || ((std::numeric_limits<float>::max()
        / filterInfo.dipScale) < filterInfo.blurRadius)) {
        FI_HILOGE("Invalid parameters, cornerRadius:%{public}f, dipScale:%{public}f",
            filterInfo.blurRadius, filterInfo.dipScale);
        return;
    }
    Rosen::Vector4f cornerRadiusVector = { filterInfo.cornerRadius1, filterInfo.cornerRadius2,
        filterInfo.cornerRadius3, filterInfo.cornerRadius4 };
    filterNode->SetCornerRadius(cornerRadiusVector * filterInfo.dipScale);
    FI_HILOGD("Set custom drag blur successfully");
}

void DragDrawing::SetComponentDragBlur(const FilterInfo &filterInfo, const ExtraInfo &extraInfo,
    std::shared_ptr<Rosen::RSCanvasNode> filterNode)
{
    CHKPV(filterNode);
    auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
    CHKPV(currentPixelMap);
    std::shared_ptr<Rosen::RSFilter> backFilter = Rosen::RSFilter::CreateMaterialFilter(
        RadiusVp2Sigma(RADIUS_VP, filterInfo.dipScale),
        DEFAULT_SATURATION, DEFAULT_BRIGHTNESS, DEFAULT_COLOR_VALUE);
    if (backFilter == nullptr) {
        FI_HILOGE("Create backgroundFilter failed");
        return;
    }
    filterNode->SetBackgroundFilter(backFilter);
    filterNode->SetGreyCoef(extraInfo.coef);
    filterNode->SetAlpha(filterInfo.opacity);
    int32_t adjustSize = TWELVE_SIZE * GetScaling();
    filterNode->SetBounds(DEFAULT_POSITION_X, adjustSize, currentPixelMap->GetWidth(),
        currentPixelMap->GetHeight());
    filterNode->SetFrame(DEFAULT_POSITION_X, adjustSize, currentPixelMap->GetWidth(),
        currentPixelMap->GetHeight());
    if ((extraInfo.cornerRadius < 0) || (filterInfo.dipScale < 0) ||
        (fabs(filterInfo.dipScale) < EPSILON) || ((std::numeric_limits<float>::max()
        / filterInfo.dipScale) < extraInfo.cornerRadius)) {
        FI_HILOGE("Invalid parameters, cornerRadius:%{public}f, dipScale:%{public}f",
            extraInfo.cornerRadius, filterInfo.dipScale);
        return;
    }
    filterNode->SetCornerRadius(extraInfo.cornerRadius * filterInfo.dipScale);
    FI_HILOGD("Set component drag blur successfully");
    return;
}

int32_t DragDrawing::SetNodesLocation()
{
    FI_HILOGD("enter");
    Rosen::RSAnimationTimingProtocol protocol;
    Rosen::RSNode::Animate(protocol, SPRING, [&]() {
        float displayX = g_drawingInfo.currentPositionX;
        float displayY = g_drawingInfo.currentPositionY;
        AdjustRotateDisplayXY(displayX, displayY);
        int32_t positionX = displayX + g_drawingInfo.pixelMapX;
        int32_t positionY = displayY + g_drawingInfo.pixelMapY - TWELVE_SIZE * GetScaling();
        int32_t adjustSize = TWELVE_SIZE * GetScaling();
        CHKPV(g_drawingInfo.parentNode);
        auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
        CHKPV(currentPixelMap);
        g_drawingInfo.parentNode->SetBounds(positionX, positionY, currentPixelMap->GetWidth(),
            currentPixelMap->GetHeight() + adjustSize);
        g_drawingInfo.parentNode->SetFrame(positionX, positionY, currentPixelMap->GetWidth(),
            currentPixelMap->GetHeight() + adjustSize);
        if (!g_drawingInfo.multiSelectedNodes.empty() && !g_drawingInfo.multiSelectedPixelMaps.empty()) {
            size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
            size_t multiSelectedPixelMapsSize = g_drawingInfo.multiSelectedPixelMaps.size();
            for (size_t i = 0; (i < multiSelectedNodesSize) && (i < multiSelectedPixelMapsSize); ++i) {
                std::shared_ptr<Rosen::RSCanvasNode> multiSelectedNode = g_drawingInfo.multiSelectedNodes[i];
                std::shared_ptr<Media::PixelMap> multiSelectedPixelMap = g_drawingInfo.multiSelectedPixelMaps[i];
                auto pixelMap  = currentPixelMap;
                CHKPV(pixelMap);
                CHKPV(multiSelectedNode);
                CHKPV(multiSelectedPixelMap);
                float multiSelectedPositionX = positionX + (static_cast<float>(pixelMap->GetWidth()) / TWICE_SIZE) -
                    (static_cast<float>(multiSelectedPixelMap->GetWidth()) / TWICE_SIZE);
                float multiSelectedPositionY = positionY + (static_cast<float>(pixelMap->GetHeight()) / TWICE_SIZE) -
                    (static_cast<float>(multiSelectedPixelMap->GetHeight()) / TWICE_SIZE - adjustSize);
                    multiSelectedNode->SetBounds(multiSelectedPositionX, multiSelectedPositionY,
                        multiSelectedPixelMap->GetWidth(), multiSelectedPixelMap->GetHeight());
                    multiSelectedNode->SetFrame(multiSelectedPositionX, multiSelectedPositionY,
                        multiSelectedPixelMap->GetWidth(), multiSelectedPixelMap->GetHeight());
            }
        }
    }, [this]() {
        FI_HILOGD("SetNodesLocation end");
    });
#ifdef IOS_PLATFORM
    g_drawingInfo.startNum = actionTime_; // IOS animation starts time
#else
    g_drawingInfo.startNum = START_TIME;
#endif // IOS_PLATFORM
    g_drawingInfo.needDestroyDragWindow = false;
    StartVsync();
    FI_HILOGD("leave");
    return RET_OK;
}


int32_t DragDrawing::EnterTextEditorArea(bool enable)
{
    FI_HILOGD("enter");
    if (enable) {
        DRAG_DATA_MGR.SetInitialPixelMapLocation({ g_drawingInfo.pixelMapX, g_drawingInfo.pixelMapY });
        needRotatePixelMapXY_ = true;
        RotatePixelMapXY();
    } else {
        needRotatePixelMapXY_ = false;
        auto initialPixelMapLocation = DRAG_DATA_MGR.GetInitialPixelMapLocation();
        g_drawingInfo.pixelMapX = initialPixelMapLocation.first;
        g_drawingInfo.pixelMapY = initialPixelMapLocation.second;
    }
    DRAG_DATA_MGR.SetPixelMapLocation({ g_drawingInfo.pixelMapX, g_drawingInfo.pixelMapY });
    if (RunAnimation([this] {
        return this->SetNodesLocation();
    }) != RET_OK) {
        FI_HILOGE("RunAnimation to SetNodesLocation failed");
        return RET_ERR;
    }
    DRAG_DATA_MGR.SetTextEditorAreaFlag(enable);
    FI_HILOGI("EnterTextEditorArea %{public}s successfully", (enable ? "true" : "false"));
    return RET_OK;
}

float DragDrawing::RadiusVp2Sigma(float radiusVp, float dipScale)
{
    float radiusPx = radiusVp * dipScale;
    return radiusPx > 0.0f ? BLUR_SIGMA_SCALE * radiusPx + 0.5f : 0.0f;
}

int32_t DragDrawing::UpdatePreviewStyle(const PreviewStyle &previewStyle)
{
    FI_HILOGD("enter");
    if (g_drawingInfo.nodes.size() <= PIXEL_MAP_INDEX) {
        FI_HILOGE("The index is out of bounds, node size is %{public}zu", g_drawingInfo.nodes.size());
        return RET_ERR;
    } else if (ModifyPreviewStyle(g_drawingInfo.nodes[PIXEL_MAP_INDEX], previewStyle) != RET_OK) {
        FI_HILOGE("ModifyPreviewStyle failed");
        return RET_ERR;
    }
    if (ModifyMultiPreviewStyle(std::vector<PreviewStyle>(g_drawingInfo.multiSelectedNodes.size(), previewStyle)) !=
        RET_OK) {
        FI_HILOGE("ModifyPreviewStyle failed");
        return RET_ERR;
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
    FI_HILOGD("leave");
    return RET_OK;
}

int32_t DragDrawing::UpdatePreviewStyleWithAnimation(const PreviewStyle &previewStyle,
    const PreviewAnimation &animation)
{
    FI_HILOGD("enter");
    std::shared_ptr<Rosen::RSCanvasNode> pixelMapNode = g_drawingInfo.nodes[PIXEL_MAP_INDEX];
    CHKPR(pixelMapNode, RET_ERR);
    PreviewStyle originStyle;
    originStyle.types = previewStyle.types;
    if (auto color = pixelMapNode->GetShowingProperties().GetForegroundColor(); color.has_value()) {
        originStyle.foregroundColor = color->AsArgbInt();
        originStyle.radius = previewStyle.radius;
    }
    size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
    std::vector<PreviewStyle> multiOriginStyles;
    for (size_t i = 0; i < multiSelectedNodesSize; ++i) {
        if (auto color = g_drawingInfo.multiSelectedNodes[i]->GetShowingProperties().GetForegroundColor();
            color.has_value()) {
            PreviewStyle currentStyle;
            currentStyle.types = { PreviewType::FOREGROUND_COLOR, PreviewType::RADIUS };
            currentStyle.foregroundColor = color->AsArgbInt();
            currentStyle.radius = previewStyle.radius;
            multiOriginStyles.push_back(currentStyle);
        }
    }
    if (ModifyPreviewStyle(pixelMapNode, originStyle) != RET_OK) {
        FI_HILOGE("ModifyPreviewStyle failed");
        return RET_ERR;
    }
    if (ModifyMultiPreviewStyle(multiOriginStyles) != RET_OK) {
        FI_HILOGE("ModifyMultiPreviewStyle failed");
        return RET_ERR;
    }
    Rosen::RSAnimationTimingProtocol protocol;
    protocol.SetDuration(animation.duration);
    auto curve = AnimationCurve::CreateCurve(animation.curveName, animation.curve);
    Rosen::RSNode::Animate(protocol, curve, [&]() {
        if (ModifyPreviewStyle(pixelMapNode, previewStyle) != RET_OK) {
            FI_HILOGE("ModifyPreviewStyle failed");
        }
        if (ModifyMultiPreviewStyle(std::vector<PreviewStyle>(multiSelectedNodesSize, previewStyle)) != RET_OK) {
            FI_HILOGE("ModifyMultiPreviewStyle failed");
        }
    },  []() { FI_HILOGD("UpdatePreviewStyleWithAnimation end"); });
    FI_HILOGD("leave");
    return RET_OK;
}

void DragDrawing::UpdateMousePosition(float mousePositionX, float mousePositionY)
{
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return;
    }
    if (g_drawingInfo.nodes.size() <= MOUSE_ICON_INDEX) {
        FI_HILOGE("The index out of bounds, node size:%{public}zu", g_drawingInfo.nodes.size());
        return;
    }
    std::shared_ptr<Rosen::RSCanvasNode> mouseIconNode = g_drawingInfo.nodes[MOUSE_ICON_INDEX];
    CHKPV(mouseIconNode);
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    if (pointerStyle_.id == MOUSE_DRAG_CURSOR_CIRCLE_STYLE || pointerStyle_.options == MAGIC_STYLE_OPT) {
        float positionX = mousePositionX - (static_cast<float>(g_drawingInfo.mouseWidth) / CURSOR_CIRCLE_MIDDLE);
        float positionY = mousePositionY - (static_cast<float>(g_drawingInfo.mouseHeight) / CURSOR_CIRCLE_MIDDLE);
        mouseIconNode->SetBounds(positionX, positionY, g_drawingInfo.mouseWidth, g_drawingInfo.mouseHeight);
        mouseIconNode->SetFrame(positionX, positionY, g_drawingInfo.mouseWidth, g_drawingInfo.mouseHeight);
    } else {
        mouseIconNode->SetBounds(mousePositionX, mousePositionY,
            g_drawingInfo.mouseWidth, g_drawingInfo.mouseHeight);
        mouseIconNode->SetFrame(mousePositionX, mousePositionY,
            g_drawingInfo.mouseWidth, g_drawingInfo.mouseHeight);
    }
#endif // OHOS_BUILD_ENABLE_ARKUI_X
}

int32_t DragDrawing::RotateDragWindowAsync(Rosen::Rotation rotation)
{
    isRunningRotateAnimation_ = true;
    int32_t repeatTime = 1;
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    CHKPR(context_, RET_ERR);
    timerId_ = context_->GetTimerManager().AddTimer(ASYNC_ROTATE_TIME, repeatTime, [this, rotation]() {
        RotateDragWindow(rotation, nullptr, true);
        isRunningRotateAnimation_ = false;
    });
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    if (timerId_ < 0) {
        FI_HILOGE("Add timer failed, timerId_:%{public}d", timerId_);
        isRunningRotateAnimation_ = false;
        return RET_ERR;
    }
    return RET_OK;
}

int32_t DragDrawing::RotateDragWindowSync(const std::shared_ptr<Rosen::RSTransaction>& rsTransaction)
{
    FI_HILOGD("enter");
    isRunningRotateAnimation_ = true;
    Rosen::Rotation rotation = GetRotation(g_drawingInfo.displayId);
    RotateDragWindow(rotation, rsTransaction, true);
    isRunningRotateAnimation_ = false;
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    if ((context_ != nullptr) && (timerId_ >= 0)) {
        context_->GetTimerManager().RemoveTimer(timerId_);
        timerId_ = -1;
    }
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    return RET_OK;
}

void DragDrawing::DoDrawMouse(int32_t mousePositionX, int32_t mousePositionY)
{
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return;
    }
    if (g_drawingInfo.nodes.size() <= MOUSE_ICON_INDEX) {
        FI_HILOGE("The index is out of bounds, node size is %{public}zu", g_drawingInfo.nodes.size());
        return;
    }
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    std::shared_ptr<Rosen::RSCanvasNode> mouseIconNode = g_drawingInfo.nodes[MOUSE_ICON_INDEX];
    CHKPV(mouseIconNode);
    if (pointerStyle_.id == MOUSE_DRAG_CURSOR_CIRCLE_STYLE || pointerStyle_.options == MAGIC_STYLE_OPT) {
        int32_t positionX = mousePositionX - (g_drawingInfo.mouseWidth / CURSOR_CIRCLE_MIDDLE);
        int32_t positionY = mousePositionY - (g_drawingInfo.mouseHeight / CURSOR_CIRCLE_MIDDLE);
        mouseIconNode->SetBounds(positionX, positionY, g_drawingInfo.mouseWidth, g_drawingInfo.mouseHeight);
        mouseIconNode->SetFrame(positionX, positionY, g_drawingInfo.mouseWidth, g_drawingInfo.mouseHeight);
    } else {
        mouseIconNode->SetBounds(mousePositionX, mousePositionY,
            g_drawingInfo.mouseWidth, g_drawingInfo.mouseHeight);
        mouseIconNode->SetFrame(mousePositionX, mousePositionY,
            g_drawingInfo.mouseWidth, g_drawingInfo.mouseHeight);
    }
#endif // OHOS_BUILD_ENABLE_ARKUI_X
}

int32_t DragDrawing::UpdateDefaultDragStyle(DragCursorStyle style)
{
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return RET_ERR;
    }
    if (g_drawingInfo.nodes.size() <= DRAG_STYLE_INDEX) {
        FI_HILOGE("The index is out of bounds, node size is %{public}zu", g_drawingInfo.nodes.size());
        return RET_ERR;
    }
    if (!g_drawingInfo.isCurrentDefaultStyle) {
        std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
        CHKPR(dragStyleNode, RET_ERR);
        CHKPR(g_drawingInfo.parentNode, RET_ERR);
        g_drawingInfo.parentNode->RemoveChild(dragStyleNode);
        CHKPR(rsUiDirector_, RET_ERR);
        rsUiDirector_->SendMessages();
    }
    g_drawingInfo.currentStyle = style;
    bool isPreviousDefaultStyle = g_drawingInfo.isCurrentDefaultStyle;
    g_drawingInfo.isPreviousDefaultStyle = isPreviousDefaultStyle;
    g_drawingInfo.isCurrentDefaultStyle = true;
    return RET_OK;
}

int32_t DragDrawing::UpdateValidDragStyle(DragCursorStyle style)
{
    g_drawingInfo.currentStyle = style;
    if (g_drawingInfo.isCurrentDefaultStyle) {
        if (!CheckNodesValid()) {
            FI_HILOGE("Check nodes valid failed");
            return RET_ERR;
        }
        if (g_drawingInfo.nodes.size() <= DRAG_STYLE_INDEX) {
            FI_HILOGE("The index is out of bounds, node size is %{public}zu", g_drawingInfo.nodes.size());
            return RET_ERR;
        }
        std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
        CHKPR(dragStyleNode, RET_ERR);
        CHKPR(g_drawingInfo.parentNode, RET_ERR);
        g_drawingInfo.parentNode->AddChild(dragStyleNode);
    }
    std::string filePath;
    GetFilePath(filePath);
    if (!IsValidSvgFile(filePath)) {
        FI_HILOGE("Svg file is invalid");
        return RET_ERR;
    }
    std::shared_ptr<Media::PixelMap> pixelMap = DecodeSvgToPixelMap(filePath);
    CHKPR(pixelMap, RET_ERR);
    bool isPreviousDefaultStyle = g_drawingInfo.isCurrentDefaultStyle;
    g_drawingInfo.isPreviousDefaultStyle = isPreviousDefaultStyle;
    g_drawingInfo.isCurrentDefaultStyle = false;
    g_drawingInfo.stylePixelMap = pixelMap;
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return RET_ERR;
    }
    std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
    CHKPR(dragStyleNode, RET_ERR);
    OnDragStyle(dragStyleNode, pixelMap);
    CHKPR(rsUiDirector_, RET_ERR);
    rsUiDirector_->SendMessages();
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#ifdef MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
    DragDFX::WriteUpdateDragStyle(style, OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR);
#endif // MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    return RET_OK;
}

int32_t DragDrawing::ModifyPreviewStyle(std::shared_ptr<Rosen::RSCanvasNode> node, const PreviewStyle &previewStyle)
{
    FI_HILOGD("enter");
    CHKPR(node, RET_ERR);
    if (float radius = 0.0F; ParserRadius(radius)) {
        node->SetCornerRadius(radius);
        FI_HILOGD("SetCornerRadius by radius:%{public}f", radius);
    }
    for (const auto &type : previewStyle.types) {
        switch (type) {
            case PreviewType::FOREGROUND_COLOR: {
                node->SetForegroundColor(previewStyle.foregroundColor);
                break;
            }
            case PreviewType::OPACITY: {
                node->SetAlpha(previewStyle.opacity / static_cast<float>(HEX_FF));
                break;
            }
            case PreviewType::RADIUS: {
                node->SetCornerRadius(previewStyle.radius);
                break;
            }
            case PreviewType::SCALE: {
                node->SetScale(previewStyle.scale);
                break;
            }
            default: {
                FI_HILOGE("Unsupported type");
                break;
            }
        }
    }
    FI_HILOGD("leave");
    return RET_OK;
}

int32_t DragDrawing::ModifyMultiPreviewStyle(const std::vector<PreviewStyle> &previewStyles)
{
    size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
    if (previewStyles.size() != multiSelectedNodesSize) {
        FI_HILOGE("Size of previewStyles:%{public}zu does not match multiSelectedNodesSize:%{public}zu",
            previewStyles.size(), multiSelectedNodesSize);
        return RET_ERR;
    }
    for (size_t i = 0; i < multiSelectedNodesSize; ++i) {
        if (ModifyPreviewStyle(g_drawingInfo.multiSelectedNodes[i], previewStyles[i]) != RET_OK) {
            FI_HILOGW("ModifyPreviewStyle No.%{public}zu failed", i);
        }
    }
    return RET_OK;
}

void DragDrawing::MultiSelectedAnimation(int32_t positionX, int32_t positionY, int32_t adjustSize,
    bool isMultiSelectedAnimation)
{
    size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
    size_t multiSelectedPixelMapsSize = g_drawingInfo.multiSelectedPixelMaps.size();
    for (size_t i = 0; (i < multiSelectedNodesSize) && (i < multiSelectedPixelMapsSize); ++i) {
        std::shared_ptr<Rosen::RSCanvasNode> multiSelectedNode = g_drawingInfo.multiSelectedNodes[i];
        std::shared_ptr<Media::PixelMap> multiSelectedPixelMap = g_drawingInfo.multiSelectedPixelMaps[i];
        auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
        CHKPV(currentPixelMap);
        CHKPV(multiSelectedNode);
        CHKPV(multiSelectedPixelMap);
        int32_t multiSelectedPositionX = positionX + (currentPixelMap->GetWidth() / TWICE_SIZE) -
            (multiSelectedPixelMap->GetWidth() / TWICE_SIZE);
        int32_t multiSelectedPositionY = positionY + (currentPixelMap->GetHeight() / TWICE_SIZE) -
            ((multiSelectedPixelMap->GetHeight() / TWICE_SIZE) - adjustSize);
        if (isMultiSelectedAnimation) {
            Rosen::RSAnimationTimingProtocol protocol;
            if (i == FIRST_PIXELMAP_INDEX) {
                protocol.SetDuration(SHORT_DURATION);
            } else {
                protocol.SetDuration(LONG_DURATION);
            }
            Rosen::RSNode::Animate(protocol, Rosen::RSAnimationTimingCurve::EASE_IN_OUT, [&]() {
                multiSelectedNode->SetBounds(multiSelectedPositionX, multiSelectedPositionY,
                    multiSelectedPixelMap->GetWidth(), multiSelectedPixelMap->GetHeight());
                multiSelectedNode->SetFrame(multiSelectedPositionX, multiSelectedPositionY,
                    multiSelectedPixelMap->GetWidth(), multiSelectedPixelMap->GetHeight());
            },  []() { FI_HILOGD("MultiSelectedAnimation end"); });
        } else {
            multiSelectedNode->SetBounds(multiSelectedPositionX, multiSelectedPositionY,
                multiSelectedPixelMap->GetWidth(), multiSelectedPixelMap->GetHeight());
            multiSelectedNode->SetFrame(multiSelectedPositionX, multiSelectedPositionY,
                multiSelectedPixelMap->GetWidth(), multiSelectedPixelMap->GetHeight());
        }
    }
}

void DragDrawing::InitMultiSelectedNodes()
{
    FI_HILOGD("enter");
    size_t multiSelectedPixelMapsSize = g_drawingInfo.multiSelectedPixelMaps.size();
    for (size_t i = 0; i < multiSelectedPixelMapsSize; ++i) {
        std::shared_ptr<Media::PixelMap> multiSelectedPixelMap = g_drawingInfo.multiSelectedPixelMaps[i];
        std::shared_ptr<Rosen::RSCanvasNode> multiSelectedNode = Rosen::RSCanvasNode::Create();
        multiSelectedNode->SetBgImageWidth(multiSelectedPixelMap->GetWidth());
        multiSelectedNode->SetBgImageHeight(multiSelectedPixelMap->GetHeight());
        multiSelectedNode->SetBgImagePositionX(0);
        multiSelectedNode->SetBgImagePositionY(0);
        multiSelectedNode->SetForegroundColor(TRANSPARENT_COLOR_ARGB);
        auto rosenImage = std::make_shared<Rosen::RSImage>();
        rosenImage->SetPixelMap(multiSelectedPixelMap);
        rosenImage->SetImageRepeat(0);
        multiSelectedNode->SetBgImage(rosenImage);
        float alpha = DEFAULT_ALPHA;
        float degrees = DEFAULT_ANGLE;
        if (i == FIRST_PIXELMAP_INDEX) {
            alpha = FIRST_PIXELMAP_ALPHA;
            degrees = POSITIVE_ANGLE;
        } else if (i == SECOND_PIXELMAP_INDEX) {
            alpha = SECOND_PIXELMAP_ALPHA;
            degrees = NEGATIVE_ANGLE;
        }
        multiSelectedNode->SetRotation(degrees);
        multiSelectedNode->SetCornerRadius(g_drawingInfo.filterInfo.cornerRadius1 * g_drawingInfo.filterInfo.dipScale *
            g_drawingInfo.filterInfo.scale);
        multiSelectedNode->SetAlpha(alpha);
        g_drawingInfo.multiSelectedNodes.emplace_back(multiSelectedNode);
    }
    FI_HILOGD("leave");
}

void DragDrawing::ClearMultiSelectedData()
{
    FI_HILOGD("enter");
    if (!g_drawingInfo.multiSelectedNodes.empty()) {
        g_drawingInfo.multiSelectedNodes.clear();
        g_drawingInfo.multiSelectedNodes.shrink_to_fit();
    }
    if (!g_drawingInfo.multiSelectedPixelMaps.empty()) {
        g_drawingInfo.multiSelectedPixelMaps.clear();
        g_drawingInfo.multiSelectedPixelMaps.shrink_to_fit();
    }
    FI_HILOGD("leave");
}

void DragDrawing::RotateDisplayXY(int32_t &displayX, int32_t &displayY)
{
Rosen::Rotation rotation = GetRotation(g_drawingInfo.displayId);
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#ifndef OHOS_BUILD_PC_PRODUCT
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDisplayById(g_drawingInfo.displayId);
#else
    sptr<Rosen::DisplayInfo> display =
        Rosen::DisplayManager::GetInstance().GetVisibleAreaDisplayInfoById(g_drawingInfo.displayId);
#endif // OHOS_BUILD_PC_PRODUCT
    if (display == nullptr) {
        FI_HILOGD("Get display info failed, display:%{public}d", g_drawingInfo.displayId);
        rotation = GetRotation(0);
#ifndef OHOS_BUILD_PC_PRODUCT
        display = Rosen::DisplayManager::GetInstance().GetDisplayById(0);
#else
        display = Rosen::DisplayManager::GetInstance().GetVisibleAreaDisplayInfoById(0);
#endif // OHOS_BUILD_PC_PRODUCT
        CHKPV(display);
    }
    int32_t width = display->GetWidth();
    int32_t height = display->GetHeight();
#else
    CHKPV(window_);
    int32_t width = window_->GetRect().width_;
    int32_t height = window_->GetRect().height_;
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    switch (rotation) {
        case Rosen::Rotation::ROTATION_0: {
            break;
        }
        case Rosen::Rotation::ROTATION_90: {
            int32_t temp = displayY;
            displayY = width - displayX;
            displayX = temp;
            break;
        }
        case Rosen::Rotation::ROTATION_180: {
            displayX = width - displayX;
            displayY = height - displayY;
            break;
        }
        case Rosen::Rotation::ROTATION_270: {
            int32_t temp = displayX;
            displayX = height - displayY;
            displayY = temp;
            break;
        }
        default: {
            FI_HILOGW("Unknown parameter, rotation:%{public}d", static_cast<int32_t>(rotation));
            break;
        }
    }
}

void DragDrawing::RotatePosition(float &displayX, float &displayY)
{
Rosen::Rotation rotation = GetRotation(g_drawingInfo.displayId);
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    int32_t width = displayWidth_;
    int32_t height = displayHeight_;
#else
    CHKPV(window_);
    int32_t width = window_->GetRect().width_;
    int32_t height = window_->GetRect().height_;
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    switch (rotation) {
        case Rosen::Rotation::ROTATION_0: {
            break;
        }
        case Rosen::Rotation::ROTATION_90: {
            int32_t temp = displayY;
            displayY = width - displayX;
            displayX = temp;
            break;
        }
        case Rosen::Rotation::ROTATION_180: {
            displayX = width - displayX;
            displayY = height - displayY;
            break;
        }
        case Rosen::Rotation::ROTATION_270: {
            int32_t temp = displayX;
            displayX = height - displayY;
            displayY = temp;
            break;
        }
        default: {
            FI_HILOGE("Invalid parameter, rotation:%{public}d", static_cast<int32_t>(rotation));
            break;
        }
    }
}

void DragDrawing::RotatePixelMapXY()
{
    Rosen::Rotation rotation = GetRotation(g_drawingInfo.displayId);
    FI_HILOGI("displayId:%{public}d, rotation:%{public}d", g_drawingInfo.displayId, static_cast<int32_t>(rotation));
    auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
    CHKPV(currentPixelMap);
    switch (rotation) {
        case Rosen::Rotation::ROTATION_0:
        case Rosen::Rotation::ROTATION_180: {
            g_drawingInfo.pixelMapX = -(HALF_RATIO * currentPixelMap->GetWidth());
            g_drawingInfo.pixelMapY = -(EIGHT_SIZE * GetScaling());
            break;
        }
        case Rosen::Rotation::ROTATION_90:
        case Rosen::Rotation::ROTATION_270: {
            g_drawingInfo.pixelMapX = -(HALF_RATIO * currentPixelMap->GetWidth());
            g_drawingInfo.pixelMapY = -(EIGHT_SIZE * GetScaling());
            break;
        }
        default: {
            FI_HILOGE("Invalid parameter, rotation:%{public}d", static_cast<int32_t>(rotation));
            break;
        }
    }
}

void DragDrawing::ResetAnimationParameter()
{
    FI_HILOGI("enter");
    hasRunningScaleAnimation_ = false;
    CHKPV(handler_);
#ifndef IOS_PLATFORM
    handler_->RemoveAllEvents();
    handler_->RemoveAllFileDescriptorListeners();
#endif // IOS_PLATFORM
    handler_ = nullptr;
    UpdateReceiverLocked(nullptr);
    FI_HILOGI("leave");
}

int32_t DragDrawing::GetSvgTouchPositionX(int32_t currentPixelMapWidth, int32_t stylePixelMapWidth, bool isRTL)
{
    float scalingValue = GetScaling();
    int32_t adjustSize = EIGHT_SIZE * scalingValue;
    int32_t svgTouchPositionX = -adjustSize;
    if (!isRTL) {
        svgTouchPositionX = currentPixelMapWidth + adjustSize - stylePixelMapWidth;
    }
    return svgTouchPositionX;
}

void DragDrawing::ResetAnimationFlag(bool isForce)
{
    FI_HILOGI("enter");
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    if (!isForce && (g_drawingInfo.context != nullptr) && (g_drawingInfo.timerId >= 0)) {
        g_drawingInfo.context->GetTimerManager().RemoveTimer(g_drawingInfo.timerId);
        g_drawingInfo.timerId = -1;
    }
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    if (drawDynamicEffectModifier_ != nullptr) {
        CHKPV(g_drawingInfo.rootNode);
        g_drawingInfo.rootNode->RemoveModifier(drawDynamicEffectModifier_);
        drawDynamicEffectModifier_ = nullptr;
    }
    DestroyDragWindow();
    g_drawingInfo.isRunning = false;
    g_drawingInfo.timerId = -1;
    ResetAnimationParameter();
    FI_HILOGI("leave");
}

void DragDrawing::DoEndAnimation()
{
    FI_HILOGI("enter");
#ifdef IOS_PLATFORM
    g_drawingInfo.startNum = actionTime_;
#else
    g_drawingInfo.startNum = START_TIME;
#endif // IOS_PLATFORM
    g_drawingInfo.needDestroyDragWindow = true;
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    if (g_drawingInfo.context != nullptr) {
        int32_t repeatCount = 1;
        g_drawingInfo.timerId = g_drawingInfo.context->GetTimerManager().AddTimer(TIMEOUT_MS, repeatCount, [this]() {
            FI_HILOGW("Timeout, automatically reset animation flag");
            CHKPV(handler_);
            handler_->PostTask(std::bind(&DragDrawing::ResetAnimationFlag, this, true));
        });
    }
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    StartVsync();
    FI_HILOGI("leave");
}

void DragDrawing::ResetParameter()
{
    FI_HILOGI("enter");
    g_drawingInfo.startNum = START_TIME;
    g_drawingInfo.needDestroyDragWindow = false;
    displayWidth_ = -1;
    displayHeight_ = -1;
    needRotatePixelMapXY_ = false;
    hasRunningStopAnimation_ = false;
    needMultiSelectedAnimation_ = true;
    pointerStyle_ = {};
    g_drawingInfo.isExistScalingValue = false;
    g_drawingInfo.currentPositionX = -1.0f;
    g_drawingInfo.currentPositionY = -1.0f;
    g_drawingInfo.sourceType = -1;
    g_drawingInfo.currentDragNum = -1;
    g_drawingInfo.pixelMapX = -1;
    g_drawingInfo.pixelMapY = -1;
    g_drawingInfo.displayX = -1;
    g_drawingInfo.displayY = -1;
    g_drawingInfo.mouseWidth = 0;
    g_drawingInfo.mouseHeight = 0;
    g_drawingInfo.rootNodeWidth = -1;
    g_drawingInfo.rootNodeHeight = -1;
    DragDrawing::UpdataGlobalPixelMapLocked(nullptr);
    g_drawingInfo.stylePixelMap = nullptr;
    g_drawingInfo.isPreviousDefaultStyle = false;
    g_drawingInfo.isCurrentDefaultStyle = false;
    g_drawingInfo.currentStyle = DragCursorStyle::DEFAULT;
    g_drawingInfo.filterInfo = {};
    g_drawingInfo.extraInfo = {};
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    StopVSyncStation();
    frameCallback_ = nullptr;
    DragWindowRotationFlush_ = { Rosen::Rotation::ROTATION_0 };
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    isRunningRotateAnimation_ = false;
    screenRotateState_ = false;
    isRTL_ = false;
    FI_HILOGI("leave");
}

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
void DragDrawing::StopVSyncStation()
{
    FI_HILOGI("enter");
    dragSmoothProcessor_.ResetParameters();
    vSyncStation_.StopVSyncRequest();
    FI_HILOGI("leave");
}

void DragDrawing::SetDragStyleRTL(bool isRTL)
{
    FI_HILOGI("enter");
    isRTL_ = isRTL;
    FI_HILOGI("leave");
}
#endif // OHOS_BUILD_ENABLE_ARKUI_X

int32_t DragDrawing::DoRotateDragWindow(float rotation,
    const std::shared_ptr<Rosen::RSTransaction>& rsTransaction, bool isAnimated)
{
    FI_HILOGI("Rotation:%{public}f, isAnimated:%{public}d", rotation, isAnimated);
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#ifndef OHOS_BUILD_PC_PRODUCT
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDisplayById(g_drawingInfo.displayId);
#else
    sptr<Rosen::DisplayInfo> display =
        Rosen::DisplayManager::GetInstance().GetVisibleAreaDisplayInfoById(g_drawingInfo.displayId);
#endif // OHOS_BUILD_PC_PRODUCT
    if (display == nullptr) {
        FI_HILOGD("Get display info failed, display:%{public}d", g_drawingInfo.displayId);
#ifndef OHOS_BUILD_PC_PRODUCT
        display = Rosen::DisplayManager::GetInstance().GetDisplayById(0);
#else
        display = Rosen::DisplayManager::GetInstance().GetVisibleAreaDisplayInfoById(0);
#endif // OHOS_BUILD_PC_PRODUCT
        CHKPR(display, RET_ERR);
    }
    displayWidth_ = display->GetWidth();
    displayHeight_ = display->GetHeight();
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
    CHKPR(currentPixelMap, RET_ERR);
    if ((currentPixelMap->GetWidth() <= 0) || (currentPixelMap->GetHeight() <= 0)) {
        FI_HILOGE("Invalid parameter pixelmap");
        return RET_ERR;
    }
    float adjustSize = TWELVE_SIZE * GetScaling();
    float pivotX = HALF_PIVOT;
    float pivotY = 0.0f;
    if (fabsf(adjustSize + currentPixelMap->GetHeight()) < EPSILON) {
        pivotY = HALF_PIVOT;
    } else {
        pivotY = ((currentPixelMap->GetHeight() * 1.0 / TWICE_SIZE) + adjustSize) /
            (adjustSize + currentPixelMap->GetHeight());
    }
    if (!isAnimated) {
        DragWindowRotateInfo_.rotation = rotation;
        DragWindowRotateInfo_.pivotX = pivotX;
        DragWindowRotateInfo_.pivotY = pivotY;
        RotateCanvasNode(pivotX, pivotY, rotation);
        Rosen::RSTransaction::FlushImplicitTransaction();
        return RET_OK;
    }
    return DoRotateDragWindowAnimation(rotation, pivotX, pivotY, rsTransaction);
}

template <typename T>
void DragDrawing::AdjustRotateDisplayXY(T &displayX, T &displayY)
{
    Rosen::Rotation rotation = GetRotation(g_drawingInfo.displayId);
    FI_HILOGD("displayId:%{public}d, rotation:%{public}d", g_drawingInfo.displayId, static_cast<int32_t>(rotation));
    auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
    CHKPV(currentPixelMap);
    switch (rotation) {
        case Rosen::Rotation::ROTATION_0: {
            break;
        }
        case Rosen::Rotation::ROTATION_90: {
            displayX -= (currentPixelMap->GetWidth() - currentPixelMap->GetHeight()) / TWICE_SIZE +
                g_drawingInfo.pixelMapX - g_drawingInfo.pixelMapY;
            displayY -= (currentPixelMap->GetWidth() - currentPixelMap->GetHeight()) / TWICE_SIZE +
                g_drawingInfo.pixelMapX + currentPixelMap->GetHeight() + g_drawingInfo.pixelMapY;
            break;
        }
        case Rosen::Rotation::ROTATION_180: {
            displayX -= currentPixelMap->GetWidth() + (g_drawingInfo.pixelMapX * TWICE_SIZE);
            displayY -= currentPixelMap->GetHeight() + (g_drawingInfo.pixelMapY * TWICE_SIZE);
            break;
        }
        case Rosen::Rotation::ROTATION_270: {
            displayX -= (currentPixelMap->GetWidth() - currentPixelMap->GetHeight()) / TWICE_SIZE +
                g_drawingInfo.pixelMapX + currentPixelMap->GetHeight() + g_drawingInfo.pixelMapY;
            displayY += (currentPixelMap->GetWidth() - currentPixelMap->GetHeight()) / TWICE_SIZE +
                g_drawingInfo.pixelMapX - g_drawingInfo.pixelMapY;
            break;
        }
        default: {
            FI_HILOGE("Invalid parameter, rotation:%{public}d", static_cast<int32_t>(rotation));
            break;
        }
    }
}

void DragDrawing::DrawRotateDisplayXY(float positionX, float positionY)
{
    FI_HILOGD("enter");
    float adjustSize = TWELVE_SIZE * GetScaling();
    float parentPositionX = positionX + g_drawingInfo.pixelMapX;
    float parentPositionY = positionY + g_drawingInfo.pixelMapY - adjustSize;
    auto parentNode = g_drawingInfo.parentNode;
    auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
    CHKPV(parentNode);
    CHKPV(currentPixelMap);
    parentNode->SetBounds(parentPositionX, parentPositionY, currentPixelMap->GetWidth(),
        currentPixelMap->GetHeight() + adjustSize);
    parentNode->SetFrame(parentPositionX, parentPositionY, currentPixelMap->GetWidth(),
        currentPixelMap->GetHeight() + adjustSize);
    if (!g_drawingInfo.multiSelectedNodes.empty() && !g_drawingInfo.multiSelectedPixelMaps.empty()) {
        DoMultiSelectedAnimation(parentPositionX, parentPositionY, adjustSize, false);
    }
    FI_HILOGD("leave");
}

void DragDrawing::ScreenRotateAdjustDisplayXY(
    Rosen::Rotation rotation, Rosen::Rotation lastRotation, float &displayX, float &displayY)
{
    FI_HILOGI("enter");
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#ifndef OHOS_BUILD_PC_PRODUCT
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDisplayById(g_drawingInfo.displayId);
#else
    sptr<Rosen::DisplayInfo> display =
        Rosen::DisplayManager::GetInstance().GetVisibleAreaDisplayInfoById(g_drawingInfo.displayId);
#endif // OHOS_BUILD_PC_PRODUCT
    if (display == nullptr) {
        FI_HILOGD("Get display info failed, display:%{public}d", g_drawingInfo.displayId);
#ifndef OHOS_BUILD_PC_PRODUCT
        display = Rosen::DisplayManager::GetInstance().GetDisplayById(0);
#else
        display = Rosen::DisplayManager::GetInstance().GetVisibleAreaDisplayInfoById(0);
#endif // OHOS_BUILD_PC_PRODUCT
        CHKPV(display);
    }
    displayWidth_ = display->GetWidth();
    displayHeight_ = display->GetHeight();
    int32_t width = displayWidth_;
    int32_t height = displayHeight_;
#else
    CHKPV(window_);
    int32_t width = window_->GetRect().width_;
    int32_t height = window_->GetRect().height_;
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    if ((static_cast<int32_t>(lastRotation) + NUM_ONE) % NUM_FOUR == static_cast<int32_t>(rotation)) {
        int32_t temp = displayX;
        displayX = width - displayY;
        displayY = temp;
    } else if ((static_cast<int32_t>(lastRotation) + NUM_TWO) % NUM_FOUR == static_cast<int32_t>(rotation)) {
        displayX = width - displayX;
        displayY = height - displayY;
    } else {
        int32_t temp = displayY;
        displayY = height - displayX;
        displayX = temp;
    }
    FI_HILOGI("leave");
}

void DragDrawing::UpdateDragDataForSuperHub(const DragData &dragData)
{
    g_dragDataForSuperHub.extraInfo = dragData.extraInfo;
    g_dragDataForSuperHub.sourceType = dragData.sourceType;
    g_dragDataForSuperHub.displayX = dragData.displayX;
    g_dragDataForSuperHub.displayY = dragData.displayY;
    g_dragDataForSuperHub.dragNum = dragData.dragNum;
    g_dragDataForSuperHub.summarys = dragData.summarys;
}

std::shared_ptr<Media::PixelMap> DragDrawing::AccessGlobalPixelMapLocked()
{
    std::shared_lock<std::shared_mutex> lock(g_pixelMapLock);
    return g_drawingInfo.pixelMap;
}

void DragDrawing::UpdataGlobalPixelMapLocked(std::shared_ptr<Media::PixelMap> pixelmap)
{
    std::unique_lock<std::shared_mutex> lock(g_pixelMapLock);
    g_drawingInfo.pixelMap = pixelmap;
}

std::shared_ptr<Rosen::VSyncReceiver> DragDrawing::AccessReceiverLocked()
{
    std::shared_lock<std::shared_mutex> lock(receiverMutex_);
    return receiver_;
}

void DragDrawing::UpdateReceiverLocked(std::shared_ptr<Rosen::VSyncReceiver> receiver)
{
    std::unique_lock<std::shared_mutex> lock(receiverMutex_);
    receiver_ = receiver;
}

void DragDrawing::ScreenRotate(Rosen::Rotation rotation, Rosen::Rotation lastRotation)
{
    FI_HILOGI("enter, rotation:%{public}d, lastRotation:%{public}d", static_cast<int32_t>(rotation),
        static_cast<int32_t>(lastRotation));
    ScreenRotateAdjustDisplayXY(rotation, lastRotation, g_drawingInfo.x, g_drawingInfo.y);
    DrawRotateDisplayXY(g_drawingInfo.x, g_drawingInfo.y);
#ifndef OHOS_BUILD_PC_PRODUCT
    if (g_drawingInfo.sourceType == MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        ScreenRotateAdjustDisplayXY(
            rotation, lastRotation, g_drawingInfo.currentPositionX, g_drawingInfo.currentPositionY);
        UpdateMousePosition(g_drawingInfo.currentPositionX, g_drawingInfo.currentPositionY);
    }
#endif // OHOS_BUILD_PC_PRODUCT
    Rosen::RSTransaction::FlushImplicitTransaction();
    screenRotateState_ = true;
    FI_HILOGI("leave");
}

int32_t DragDrawing::DoRotateDragWindowAnimation(float rotation, float pivotX, float pivotY,
    const std::shared_ptr<Rosen::RSTransaction>& rsTransaction)
{
    FI_HILOGD("enter");
    if (rsTransaction != nullptr) {
        Rosen::RSTransaction::FlushImplicitTransaction();
        rsTransaction->Begin();
    }
    if ((rotation == ROTATION_0) && (DragWindowRotateInfo_.rotation == ROTATION_270)) {
        RotateCanvasNode(DragWindowRotateInfo_.pivotX, DragWindowRotateInfo_.pivotY, -ROTATION_90);
    } else if ((rotation == ROTATION_270) && (DragWindowRotateInfo_.rotation == ROTATION_0)) {
        RotateCanvasNode(DragWindowRotateInfo_.pivotX, DragWindowRotateInfo_.pivotY, ROTATION_360);
    }

    Rosen::RSAnimationTimingProtocol protocol;
    protocol.SetDuration(ANIMATION_DURATION);
    Rosen::RSNode::Animate(protocol, SPRING, [&]() {
        RotateCanvasNode(pivotX, pivotY, rotation);
        DragWindowRotateInfo_.rotation = rotation;
        DragWindowRotateInfo_.pivotX = pivotX;
        DragWindowRotateInfo_.pivotY = pivotY;
        return RET_OK;
    },  []() { FI_HILOGD("DoRotateDragWindowAnimation end"); });
    if (rsTransaction != nullptr) {
        rsTransaction->Commit();
    } else {
        Rosen::RSTransaction::FlushImplicitTransaction();
    }
    FI_HILOGD("leave");
    return RET_OK;
}

bool DragDrawing::ParserRadius(float &radius)
{
    FilterInfo filterInfo = g_drawingInfo.filterInfo;
    ExtraInfo extraInfo = g_drawingInfo.extraInfo;
    if ((extraInfo.cornerRadius < 0) || (filterInfo.dipScale < 0) ||
        (fabs(filterInfo.dipScale) < EPSILON) || ((std::numeric_limits<float>::max()
        / filterInfo.dipScale) < extraInfo.cornerRadius)) {
        FI_HILOGE("Invalid parameters, cornerRadius:%{public}f, dipScale:%{public}f",
            extraInfo.cornerRadius, filterInfo.dipScale);
        return false;
    }
    radius = extraInfo.cornerRadius * filterInfo.dipScale;
    return true;
}

DragDrawing::~DragDrawing()
{
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    if (dragExtHandler_ != nullptr) {
        dlclose(dragExtHandler_);
        dragExtHandler_ = nullptr;
    }
#endif // OHOS_BUILD_ENABLE_ARKUI_X
}

void DrawSVGModifier::Draw(RSDrawingContext& context) const
{
    FI_HILOGD("enter");
    CHKPV(stylePixelMap_);
    auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
    CHKPV(currentPixelMap);
    float scalingValue = GetScaling();
    if (SCALE_THRESHOLD_EIGHT < scalingValue || fabsf(SCALE_THRESHOLD_EIGHT - scalingValue) < EPSILON) {
        FI_HILOGE("Invalid scalingValue:%{public}f", scalingValue);
        return;
    }
    int32_t svgTouchPositionX = DragDrawing::GetSvgTouchPositionX(
        currentPixelMap->GetWidth(), stylePixelMap_->GetWidth(), isRTL_);
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return;
    }
    std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
    CHKPV(dragStyleNode);
    int32_t adjustSize = (TWELVE_SIZE - EIGHT_SIZE) * scalingValue;
    dragStyleNode->SetBounds(svgTouchPositionX, adjustSize, stylePixelMap_->GetWidth() + adjustSize,
        stylePixelMap_->GetHeight());
    dragStyleNode->SetFrame(svgTouchPositionX, adjustSize, stylePixelMap_->GetWidth() + adjustSize,
        stylePixelMap_->GetHeight());
    dragStyleNode->SetBgImageWidth(stylePixelMap_->GetWidth());
    dragStyleNode->SetBgImageHeight(stylePixelMap_->GetHeight());
    dragStyleNode->SetBgImagePositionX(0);
    dragStyleNode->SetBgImagePositionY(0);
    auto rosenImage = std::make_shared<Rosen::RSImage>();
    rosenImage->SetPixelMap(stylePixelMap_);
    rosenImage->SetImageRepeat(0);
    dragStyleNode->SetBgImage(rosenImage);
    Rosen::RSTransaction::FlushImplicitTransaction();
    FI_HILOGD("leave");
}

Rosen::SHADOW_COLOR_STRATEGY DrawPixelMapModifier::ConvertShadowColorStrategy(int32_t shadowColorStrategy) const
{
    if (shadowColorStrategy == static_cast<int32_t>(Rosen::SHADOW_COLOR_STRATEGY::COLOR_STRATEGY_NONE)) {
        return Rosen::SHADOW_COLOR_STRATEGY::COLOR_STRATEGY_NONE ;
    } else if (shadowColorStrategy == static_cast<int32_t>(Rosen::SHADOW_COLOR_STRATEGY::COLOR_STRATEGY_AVERAGE)) {
        return Rosen::SHADOW_COLOR_STRATEGY::COLOR_STRATEGY_AVERAGE ;
    } else if (shadowColorStrategy == static_cast<int32_t>(Rosen::SHADOW_COLOR_STRATEGY::COLOR_STRATEGY_MAIN)) {
        return Rosen::SHADOW_COLOR_STRATEGY::COLOR_STRATEGY_MAIN ;
    } else {
        return Rosen::SHADOW_COLOR_STRATEGY::COLOR_STRATEGY_NONE;
    }
}

void DrawPixelMapModifier::SetTextDragShadow(std::shared_ptr<Rosen::RSCanvasNode> pixelMapNode) const
{
    if (!g_drawingInfo.filterInfo.path.empty()) {
        FI_HILOGD("path:%{private}s", g_drawingInfo.filterInfo.path.c_str());
        pixelMapNode->SetShadowPath(Rosen::RSPath::CreateRSPath(g_drawingInfo.filterInfo.path));
    } else {
        FI_HILOGW("path is empty");
    }
}

void DrawPixelMapModifier::SetDragShadow(std::shared_ptr<Rosen::RSCanvasNode> pixelMapNode) const
{
    if ((g_drawingInfo.filterInfo.dragType == "text") && (g_drawingInfo.filterInfo.path.empty())) {
        FI_HILOGI("path is empty");
        return;
    }
    pixelMapNode->SetShadowOffset(g_drawingInfo.filterInfo.offsetX, g_drawingInfo.filterInfo.offsetY);
    pixelMapNode->SetShadowColor(g_drawingInfo.filterInfo.argb);
    pixelMapNode->SetShadowMask(g_drawingInfo.filterInfo.shadowMask);
    pixelMapNode->SetShadowIsFilled(g_drawingInfo.filterInfo.shadowIsFilled);
    pixelMapNode->SetShadowColorStrategy(ConvertShadowColorStrategy(g_drawingInfo.filterInfo.shadowColorStrategy));
    if (g_drawingInfo.filterInfo.isHardwareAcceleration) {
        pixelMapNode->SetShadowElevation(g_drawingInfo.filterInfo.elevation);
    } else {
        pixelMapNode->SetShadowRadius(g_drawingInfo.filterInfo.shadowCorner);
    }
    if (g_drawingInfo.filterInfo.dragType == "text") {
        SetTextDragShadow(pixelMapNode);
    }
}

void DrawPixelMapModifier::Draw(RSDrawingContext &context) const
{
    FI_HILOGD("enter");
    auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
    CHKPV(currentPixelMap);
    int32_t pixelMapWidth = currentPixelMap->GetWidth();
    int32_t pixelMapHeight = currentPixelMap->GetHeight();
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return;
    }
    std::shared_ptr<Rosen::RSCanvasNode> pixelMapNode = g_drawingInfo.nodes[PIXEL_MAP_INDEX];
    CHKPV(pixelMapNode);
    if (g_drawingInfo.filterInfo.shadowEnable) {
        SetDragShadow(pixelMapNode);
    }
    int32_t adjustSize = TWELVE_SIZE * GetScaling();
    pixelMapNode->SetBounds(DEFAULT_POSITION_X, adjustSize, pixelMapWidth, pixelMapHeight);
    pixelMapNode->SetFrame(DEFAULT_POSITION_X, adjustSize, pixelMapWidth, pixelMapHeight);
    pixelMapNode->SetBgImageWidth(pixelMapWidth);
    pixelMapNode->SetBgImageHeight(pixelMapHeight);
    pixelMapNode->SetBgImagePositionX(0);
    pixelMapNode->SetBgImagePositionY(0);
    Rosen::Drawing::AdaptiveImageInfo rsImageInfo = { 1, 0, {}, 1, 0, pixelMapWidth, pixelMapHeight };
    auto cvs = pixelMapNode->BeginRecording(pixelMapWidth, pixelMapHeight);
    CHKPV(cvs);
    Rosen::Drawing::Brush brush;
    cvs->AttachBrush(brush);
    FilterInfo filterInfo = g_drawingInfo.filterInfo;
    if (g_drawingInfo.filterInfo.shadowEnable && !filterInfo.path.empty() &&
        g_drawingInfo.filterInfo.dragType == "text") {
        auto rsPath = Rosen::RSPath::CreateRSPath(filterInfo.path);
        cvs->Save();
        cvs->ClipPath(rsPath->GetDrawingPath(), Rosen::Drawing::ClipOp::INTERSECT, true);
        cvs->DrawPixelMapWithParm(currentPixelMap, rsImageInfo, Rosen::Drawing::SamplingOptions());
        cvs->Restore();
    } else {
        cvs->DrawPixelMapWithParm(currentPixelMap, rsImageInfo, Rosen::Drawing::SamplingOptions());
    }
    cvs->DetachBrush();
    pixelMapNode->SetClipToBounds(true);
    pixelMapNode->FinishRecording();
    Rosen::RSTransaction::FlushImplicitTransaction();
    FI_HILOGD("leave");
}

void DrawMouseIconModifier::Draw(RSDrawingContext &context) const
{
    FI_HILOGD("enter");
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    std::shared_ptr<Media::PixelMap> pixelMap = std::make_shared<Media::PixelMap>();
    int32_t ret = RET_ERR;
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    ret = MMI::InputManager::GetInstance()->GetPointerSnapshot(&pixelMap);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    if (ret != RET_OK) {
        FI_HILOGE("Get pointer snapshot failed, ret:%{public}d", ret);
        pixelMap = DrawFromSVG();
    }
    CHKPV(pixelMap);
    OnDraw(pixelMap);
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    FI_HILOGD("leave");
}

std::shared_ptr<Media::PixelMap> DrawMouseIconModifier::DrawFromSVG() const
{
    std::string imagePath;
    if (pointerStyle_.id == MOUSE_DRAG_CURSOR_CIRCLE_STYLE) {
        imagePath = MOUSE_DRAG_CURSOR_CIRCLE_PATH;
    } else {
        imagePath = MOUSE_DRAG_DEFAULT_PATH;
    }
    int32_t pointerSize = pointerStyle_.size;
    int32_t pointerColor = pointerStyle_.color;
    int32_t cursorPixel = DEVICE_INDEPENDENT_PIXEL;
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    if (pointerStyle_.options == MAGIC_STYLE_OPT) {
        imagePath = MOUSE_DRAG_MAGIC_DEFAULT_PATH;
        int32_t ret = MMI::InputManager::GetInstance()->GetPointerSize(pointerSize);
        if (ret != RET_OK) {
            FI_HILOGW("Get pointer size failed, ret:%{public}d", ret);
        }
        ret = MMI::InputManager::GetInstance()->GetPointerColor(pointerColor);
        if (ret != RET_OK) {
            FI_HILOGW("Get pointer color failed, ret:%{public}d", ret);
        }
        cursorPixel = MAGIC_INDEPENDENT_PIXEL;
    }
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    Media::SourceOptions opts;
    opts.formatHint = "image/svg+xml";
    uint32_t errCode = 0;
    auto imageSource = Media::ImageSource::CreateImageSource(imagePath, opts, errCode);
    if (imageSource == nullptr) {
        FI_HILOGW("imageSource is null");
        return nullptr;
    }
    if (pointerSize < DEFAULT_MOUSE_SIZE) {
        FI_HILOGD("Invalid pointerSize:%{public}d", pointerSize);
        pointerSize = DEFAULT_MOUSE_SIZE;
    }
    Media::DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {
        .width = pow(INCREASE_RATIO, pointerSize - 1) * cursorPixel * GetScaling(),
        .height = pow(INCREASE_RATIO, pointerSize - 1) * cursorPixel * GetScaling()
    };
    if (pointerColor != INVALID_COLOR_VALUE) {
        decodeOpts.SVGOpts.fillColor = {.isValidColor = true, .color = pointerColor};
    }
    return imageSource->CreatePixelMap(decodeOpts, errCode);
}

void DrawMouseIconModifier::OnDraw(std::shared_ptr<Media::PixelMap> pixelMap) const
{
    FI_HILOGD("enter");
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    CHKPV(pixelMap);
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return;
    }
    g_drawingInfo.mouseWidth = pixelMap->GetWidth();
    g_drawingInfo.mouseHeight = pixelMap->GetHeight();
    if (g_drawingInfo.nodes.size() <= MOUSE_ICON_INDEX) {
        FI_HILOGE("The index is out of bounds, node size is %{public}zu", g_drawingInfo.nodes.size());
        return;
    }
    std::shared_ptr<Rosen::RSCanvasNode> mouseIconNode = g_drawingInfo.nodes[MOUSE_ICON_INDEX];
    CHKPV(mouseIconNode);
    mouseIconNode->SetBgImageWidth(pixelMap->GetWidth());
    mouseIconNode->SetBgImageHeight(pixelMap->GetHeight());
    mouseIconNode->SetBgImagePositionX(0);
    mouseIconNode->SetBgImagePositionY(0);
    auto rosenImage = std::make_shared<Rosen::RSImage>();
    rosenImage->SetPixelMap(pixelMap);
    rosenImage->SetImageRepeat(0);
    mouseIconNode->SetBgImage(rosenImage);
    Rosen::RSTransaction::FlushImplicitTransaction();
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    FI_HILOGD("leave");
}

void DrawDynamicEffectModifier::Draw(RSDrawingContext &context) const
{
    FI_HILOGD("enter");
    CHKPV(alpha_);
    CHKPV(g_drawingInfo.parentNode);
    g_drawingInfo.parentNode->SetAlpha(alpha_->Get());
    CHKPV(scale_);
    g_drawingInfo.parentNode->SetScale(scale_->Get(), scale_->Get());
    Rosen::RSTransaction::FlushImplicitTransaction();
    FI_HILOGD("leave");
}

void DrawDynamicEffectModifier::SetAlpha(float alpha)
{
    FI_HILOGD("enter");
    if (alpha_ == nullptr) {
        alpha_ = std::make_shared<Rosen::RSAnimatableProperty<float>>(alpha);
        RSModifier::AttachProperty(alpha_);
        return;
    }
    alpha_->Set(alpha);
    FI_HILOGD("leave");
}

void DrawDynamicEffectModifier::SetScale(float scale)
{
    FI_HILOGD("enter");
    if (scale_ == nullptr) {
        scale_ = std::make_shared<Rosen::RSAnimatableProperty<float>>(scale);
        RSModifier::AttachProperty(scale_);
        return;
    }
    scale_->Set(scale);
    FI_HILOGD("leave");
}

void DrawStyleChangeModifier::Draw(RSDrawingContext &context) const
{
    FI_HILOGD("enter");
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return;
    }
    if (g_drawingInfo.nodes.size() <= DRAG_STYLE_INDEX) {
        FI_HILOGE("The index is out of bounds, node size is %{public}zu", g_drawingInfo.nodes.size());
        return;
    }
    std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
    CHKPV(dragStyleNode);
    auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
    CHKPV(currentPixelMap);
    float pixelMapWidth = currentPixelMap->GetWidth();
    if (stylePixelMap_ == nullptr) {
        if (scale_ == nullptr) {
            return;
        }
        dragStyleNode->SetScale(scale_->Get());
        return;
    }
    float scalingValue = GetScaling();
    if ((1.0 * INT_MAX / EIGHT_SIZE) <= scalingValue) {
        return;
    }
    int32_t svgTouchPositionX = DragDrawing::GetSvgTouchPositionX(pixelMapWidth, stylePixelMap_->GetWidth(), isRTL_);
    dragStyleNode->SetBounds(svgTouchPositionX, (TWELVE_SIZE-EIGHT_SIZE)*scalingValue, stylePixelMap_->GetWidth(),
        stylePixelMap_->GetHeight());
    dragStyleNode->SetFrame(svgTouchPositionX, (TWELVE_SIZE-EIGHT_SIZE)*scalingValue, stylePixelMap_->GetWidth(),
        stylePixelMap_->GetHeight());
    dragStyleNode->SetBgImageWidth(stylePixelMap_->GetWidth());
    dragStyleNode->SetBgImageHeight(stylePixelMap_->GetHeight());
    dragStyleNode->SetBgImagePositionX(0);
    dragStyleNode->SetBgImagePositionY(0);
    auto rosenImage = std::make_shared<Rosen::RSImage>();
    rosenImage->SetPixelMap(stylePixelMap_);
    rosenImage->SetImageRepeat(0);
    dragStyleNode->SetBgImage(rosenImage);
    Rosen::RSTransaction::FlushImplicitTransaction();
    FI_HILOGD("leave");
}

void DrawStyleChangeModifier::SetScale(float scale)
{
    FI_HILOGD("enter");
    if (scale_ == nullptr) {
        scale_ = std::make_shared<Rosen::RSAnimatableProperty<float>>(scale);
        RSModifier::AttachProperty(scale_);
    } else {
        scale_->Set(scale);
    }
    FI_HILOGD("leave");
}

void DrawStyleScaleModifier::Draw(RSDrawingContext &context) const
{
    FI_HILOGD("enter");
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return;
    }
    if (g_drawingInfo.nodes.size() <= DRAG_STYLE_INDEX) {
        FI_HILOGE("The index is out of bounds, node size is %{public}zu", g_drawingInfo.nodes.size());
        return;
    }
    std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
    CHKPV(dragStyleNode);
    CHKPV(scale_);
    dragStyleNode->SetScale(scale_->Get());
    FI_HILOGD("leave");
}

void DrawStyleScaleModifier::SetScale(float scale)
{
    FI_HILOGD("enter");
    if (scale_ == nullptr) {
        scale_ = std::make_shared<Rosen::RSAnimatableProperty<float>>(scale);
        RSModifier::AttachProperty(scale_);
    } else {
        scale_->Set(scale);
    }
    FI_HILOGD("leave");
}

void DrawDragStopModifier::Draw(RSDrawingContext &context) const
{
    FI_HILOGD("enter");
    CHKPV(alpha_);
    CHKPV(scale_);
    if (!CheckNodesValid()) {
        FI_HILOGE("Check nodes valid failed");
        return;
    }
    CHKPV(g_drawingInfo.parentNode);
    g_drawingInfo.parentNode->SetAlpha(alpha_->Get());
    g_drawingInfo.parentNode->SetScale(scale_->Get(), scale_->Get());
    if (!g_drawingInfo.multiSelectedNodes.empty()) {
        size_t multiSelectedNodesSize = g_drawingInfo.multiSelectedNodes.size();
        for (size_t i = 0; i < multiSelectedNodesSize; ++i) {
            std::shared_ptr<Rosen::RSCanvasNode> multiSelectedNode = g_drawingInfo.multiSelectedNodes[i];
            CHKPV(multiSelectedNode);
            multiSelectedNode->SetAlpha(alpha_->Get());
            multiSelectedNode->SetScale(scale_->Get(), scale_->Get());
        }
    }
    if (g_drawingInfo.nodes.size() <= DRAG_STYLE_INDEX) {
        FI_HILOGE("The index is out of bounds, node size is %{public}zu", g_drawingInfo.nodes.size());
        return;
    }
    std::shared_ptr<Rosen::RSCanvasNode> dragStyleNode = g_drawingInfo.nodes[DRAG_STYLE_INDEX];
    CHKPV(dragStyleNode);
    CHKPV(styleScale_);
    CHKPV(styleAlpha_);
    dragStyleNode->SetScale(styleScale_->Get());
    dragStyleNode->SetAlpha(styleAlpha_->Get());
    FI_HILOGD("leave");
}

void DrawDragStopModifier::SetAlpha(float alpha)
{
    FI_HILOGD("enter");
    if (alpha_ == nullptr) {
        alpha_ = std::make_shared<Rosen::RSAnimatableProperty<float>>(alpha);
        RSModifier::AttachProperty(alpha_);
    } else {
        alpha_->Set(alpha);
    }
    FI_HILOGD("leave");
}

void DrawDragStopModifier::SetScale(float scale)
{
    FI_HILOGD("enter");
    if (scale_ == nullptr) {
        scale_ = std::make_shared<Rosen::RSAnimatableProperty<float>>(scale);
        RSModifier::AttachProperty(scale_);
    } else {
        scale_->Set(scale);
    }
    FI_HILOGD("leave");
}

void DrawDragStopModifier::SetStyleScale(float scale)
{
    FI_HILOGD("enter");
    if (styleScale_ == nullptr) {
        styleScale_ = std::make_shared<Rosen::RSAnimatableProperty<float>>(scale);
        RSModifier::AttachProperty(styleScale_);
    } else {
        styleScale_->Set(scale);
    }
    FI_HILOGD("leave");
}

void DrawDragStopModifier::SetStyleAlpha(float alpha)
{
    FI_HILOGD("enter");
    if (styleAlpha_ == nullptr) {
        styleAlpha_ = std::make_shared<Rosen::RSAnimatableProperty<float>>(alpha);
        RSModifier::AttachProperty(styleAlpha_);
    } else {
        styleAlpha_->Set(alpha);
    }
    FI_HILOGD("leave");
}

float DragDrawing::CalculateWidthScale()
{
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#ifndef OHOS_BUILD_PC_PRODUCT
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDisplayById(g_drawingInfo.displayId);
#else
    sptr<Rosen::DisplayInfo> display =
        Rosen::DisplayManager::GetInstance().GetVisibleAreaDisplayInfoById(g_drawingInfo.displayId);
#endif // OHOS_BUILD_PC_PRODUCT
    if (display == nullptr) {
        FI_HILOGD("Get display info failed, display:%{public}d", g_drawingInfo.displayId);
#ifndef OHOS_BUILD_PC_PRODUCT
        display = Rosen::DisplayManager::GetInstance().GetDisplayById(0);
#else
        display = Rosen::DisplayManager::GetInstance().GetVisibleAreaDisplayInfoById(0);
#endif // OHOS_BUILD_PC_PRODUCT
        if (display == nullptr) {
            FI_HILOGE("Get display info failed, display is nullptr");
            return DEFAULT_SCALING;
        }
    }
    auto defaultDisplay = Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
    if (defaultDisplay == nullptr) {
        FI_HILOGE("defaultDisplay is nullptr");
        return DEFAULT_SCALING;
    }
    int32_t width = display->GetWidth();
    int32_t height = display->GetHeight();
    float density = defaultDisplay->GetVirtualPixelRatio();
#else
    if (window_ == nullptr) {
        FI_HILOGE("window_ is nullptr");
        return DEFAULT_SCALING;
    }
    int32_t width = window_->GetRect().width_;
    int32_t height = window_->GetRect().height_;
    float density = window_->GetDensity();
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    int32_t minSide = std::min(width, height);
    FI_HILOGD("density:%{public}f, minSide:%{public}d", density, minSide);
    if (minSide < MAX_SCREEN_WIDTH_SM * density) {
        currentScreenSize_ = ScreenSizeType::SM;
    } else if (minSide < MAX_SCREEN_WIDTH_MD * density) {
        currentScreenSize_ = ScreenSizeType::MD;
    } else if (minSide < MAX_SCREEN_WIDTH_LG * density) {
        currentScreenSize_ = ScreenSizeType::LG;
    } else {
        currentScreenSize_ = ScreenSizeType::XL;
    }
    float scale = GetMaxWidthScale(width, height);
    return scale;
}

#ifdef OHOS_ENABLE_PULLTHROW
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
float DragDrawing::CalculatePullThrowScale()
{
    FI_HILOGI("enter");
    auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
    if (currentPixelMap == nullptr) {
        FI_HILOGE("pixelMap is nullptr");
        return DEFAULT_SCALING;
    }
    int32_t pixelMapWidth = currentPixelMap->GetWidth();
    int32_t pixelMapHeight = currentPixelMap->GetHeight();

    int32_t maxSide = std::max(pixelMapWidth, pixelMapHeight);
    
    FI_HILOGD("maxSide:%{public}d", maxSide);
    float scale = DEFAULT_SCALING;
    if (maxSide > APP_WIDTH) {
        scale  = APP_WIDTH / maxSide;
    }
    if (scale < BREATHE_SCALE) {
        scale  = BREATHE_SCALE;
    }
    FI_HILOGD("scale:%{public}f", scale);
    return scale;
}
#endif // OHOS_BUILD_ENABLE_ARKUI_X
#endif // OHOS_ENABLE_PULLTHROW

float DragDrawing::CalculateSMScale(int32_t pixelMapWidth, int32_t pixelMapHeight, int32_t shortSide)
{
    float scale = 1.0;
    if (g_dragDataForSuperHub.summarys.find("plain-text") != g_dragDataForSuperHub.summarys.end()) {
        scale = DragDrawing::CalculateScale(pixelMapWidth, pixelMapHeight, static_cast<float>(shortSide),
            static_cast<float>(shortSide) / SCALE_TYPE_FIRST);
    } else {
        scale = DragDrawing::CalculateScale(pixelMapWidth, pixelMapHeight,
            static_cast<float>(shortSide) / SCALE_TYPE_FIRST, static_cast<float>(shortSide) / SCALE_TYPE_FIRST);
    }
    return scale;
}

float DragDrawing::CalculateMDScale(int32_t pixelMapWidth, int32_t pixelMapHeight, int32_t shortSide)
{
    float scale = 1.0;
    if (g_dragDataForSuperHub.summarys.find("plain-text") != g_dragDataForSuperHub.summarys.end()) {
        scale = DragDrawing::CalculateScale(pixelMapWidth, pixelMapHeight,
            static_cast<float>(shortSide) / SCALE_TYPE_FIRST, static_cast<float>(shortSide) / SCALE_TYPE_THIRD);
    } else {
        scale = DragDrawing::CalculateScale(pixelMapWidth, pixelMapHeight,
            static_cast<float>(shortSide) / SCALE_TYPE_THIRD, static_cast<float>(shortSide) / SCALE_TYPE_THIRD);
    }
    return scale;
}

float DragDrawing::CalculateDefaultScale(int32_t pixelMapWidth, int32_t pixelMapHeight, int32_t shortSide)
{
    float scale = 1.0;
    if (g_dragDataForSuperHub.summarys.find("plain-text") != g_dragDataForSuperHub.summarys.end()) {
        scale = DragDrawing::CalculateScale(pixelMapWidth, pixelMapHeight,
            static_cast<float>(shortSide) * SCALE_TYPE_FIRST / SCALE_TYPE_SECOND,
            static_cast<float>(shortSide) / SCALE_TYPE_SECOND);
    } else {
        scale = DragDrawing::CalculateScale(pixelMapWidth, pixelMapHeight,
            static_cast<float>(shortSide) / SCALE_TYPE_SECOND, static_cast<float>(shortSide) / SCALE_TYPE_SECOND);
    }
    return scale;
}

float DragDrawing::GetMaxWidthScale(int32_t width, int32_t height)
{
    FI_HILOGD("current device screen's width is %{public}d", width);
    float scale = 1.0;
    auto currentPixelMap = DragDrawing::AccessGlobalPixelMapLocked();
    if (currentPixelMap == nullptr) {
        FI_HILOGE("pixelMap is nullptr");
        return DEFAULT_SCALING;
    }
    int32_t pixelMapWidth = currentPixelMap->GetWidth();
    int32_t pixelMapHeight = currentPixelMap->GetHeight();
    if (pixelMapWidth == 0 || pixelMapHeight == 0) {
        FI_HILOGE("pixelMap width or height is 0");
        return DEFAULT_SCALING;
    }
    int32_t shortSide = fmin(width, height);
    FI_HILOGD("currentPixelMap width is %{public}d , height is %{public}d , shortSide is : %{public}d",
        width, height, shortSide);
    switch (currentScreenSize_) {
        case ScreenSizeType::SM: {
            scale = CalculateSMScale(pixelMapWidth, pixelMapHeight, shortSide);
            break;
        }
        case ScreenSizeType::MD: {
            scale = CalculateMDScale(pixelMapWidth, pixelMapHeight, shortSide);
            break;
        }
        default: {
            scale = CalculateDefaultScale(pixelMapWidth, pixelMapHeight, shortSide);
            break;
        }
    }
    FI_HILOGD("Screen Size Type is %{public}d and scale is %{public}f",
        static_cast<int32_t>(currentScreenSize_), scale);
    return scale;
}

float DragDrawing::CalculateScale(float width, float height, float widthLimit, float heightLimit)
{
    float scale = 1.0;
    if ((width > 0 && height > 0) && (width > widthLimit || height > heightLimit)) {
        scale = fmin(widthLimit / width, heightLimit / height);
    }
    return scale;
}

#ifdef OHOS_BUILD_ENABLE_ARKUI_X
void DragDrawing::SetDragWindow(std::shared_ptr<OHOS::Rosen::Window> window)
{
    CALL_INFO_TRACE;
    window_ = window;
}

void DragDrawing::AddDragDestroy(std::function<void()> cb)
{
    CALL_INFO_TRACE;
    callback_ = cb;
}

void DragDrawing::SetSVGFilePath(const std::string &filePath)
{
    CALL_INFO_TRACE;
    svgFilePath_ = filePath;
}
#endif

void DragDrawing::LoadDragDropLib()
{
    FI_HILOGI("Begin to open drag drop extension library");
    if (dragExtHandler_ == nullptr) {
        dragExtHandler_ = dlopen(DRAG_DROP_EXTENSION_SO_PATH.c_str(), RTLD_LAZY);
    }
    CHKPL(dragExtHandler_);
    FI_HILOGI("End to open drag drop extension library");
}

void DragDrawing::DetachToDisplay(int32_t displayId)
{
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    CHKPV(g_drawingInfo.surfaceNode);
    g_drawingInfo.surfaceNode->DetachFromWindowContainer(screenId_);
    g_drawingInfo.displayId = displayId;
    StopVSyncStation();
    frameCallback_ = nullptr;
    Rosen::RSTransaction::FlushImplicitTransaction();
#endif // OHOS_BUILD_ENABLE_ARKUI_X
}

void DragDrawing::UpdateDragState(DragState dragState)
{
    dragState_ = dragState;
}

void DragDrawing::UpdateDragWindowDisplay(int32_t displayId)
{
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    CHKPV(g_drawingInfo.rootNode);
    CHKPV(g_drawingInfo.surfaceNode);
#ifndef OHOS_BUILD_PC_PRODUCT
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDisplayById(displayId);
#else
    sptr<Rosen::DisplayInfo> display = Rosen::DisplayManager::GetInstance().GetVisibleAreaDisplayInfoById(displayId);
#endif // OHOS_BUILD_PC_PRODUCT
    if (display == nullptr) {
        FI_HILOGD("Get display info failed, display:%{public}d", displayId);
#ifndef OHOS_BUILD_PC_PRODUCT
        display = Rosen::DisplayManager::GetInstance().GetDisplayById(0);
#else
        display = Rosen::DisplayManager::GetInstance().GetVisibleAreaDisplayInfoById(0);
#endif // OHOS_BUILD_PC_PRODUCT
        if (display == nullptr) {
            FI_HILOGE("Get display info failed, display is nullptr");
        }
        return;
    }
    screenId_ = display->GetScreenId();
    FI_HILOGI("Get screen id:%{public}llu", static_cast<unsigned long long>(screenId_));
    Rosen::Rotation currentRotation = GetRotation(displayId);
    FI_HILOGI("displayId:%{public}d, rotation:%{public}d",
        static_cast<int32_t>(displayId), static_cast<int32_t>(currentRotation));
#ifdef OHOS_BUILD_PC_PRODUCT
    uint64_t rsScreenId = screenId_;
    if (!Rosen::DisplayManager::GetInstance().ConvertScreenIdToRsScreenId(screenId_, rsScreenId)) {
        FI_HILOGE("ConvertScreenIdToRsScreenId failed");
        return;
    }
    screenId_ = rsScreenId;
#endif // OHOS_BUILD_PC_PRODUCT
    RotateDragWindow(currentRotation);
    g_drawingInfo.displayId = displayId;
    SetRotation(displayId, currentRotation);
    displayWidth_ = display->GetWidth();
    displayHeight_ = display->GetHeight();
    FI_HILOGI("Parameter rsScreen number:%{public}llu", static_cast<unsigned long long>(screenId_));
    int32_t surfaceNodeSize = std::max(displayWidth_, displayHeight_);
    g_drawingInfo.rootNode->SetBounds(0, 0, surfaceNodeSize, surfaceNodeSize);
    g_drawingInfo.rootNode->SetFrame(0, 0, surfaceNodeSize, surfaceNodeSize);
    g_drawingInfo.surfaceNode->SetBounds(0, 0, surfaceNodeSize, surfaceNodeSize);
    g_drawingInfo.surfaceNode->SetFrameGravity(Rosen::Gravity::RESIZE_ASPECT_FILL);
    g_drawingInfo.surfaceNode->AttachToWindowContainer(screenId_);
    Rosen::RSTransaction::FlushImplicitTransaction();
#endif // OHOS_BUILD_ENABLE_ARKUI_X
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
