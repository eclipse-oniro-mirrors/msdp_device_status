/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

//! Coordination client implementation.

#![allow(dead_code)]
#![allow(unused_variables)]

extern crate fusion_data_rust;
extern crate fusion_utils_rust;
extern crate ipc_rust;

use fusion_data_rust::{
    Intention, DefaultReply, GeneralCoordinationParam, StartCoordinationParam,
    StopCoordinationParam, GetCoordinationStateParam, FusionResult
};
use fusion_utils_rust::call_debug_enter;
use fusion_ipc_client_rust::FusionIpcClient;
use ipc_rust::{ MsgParcel, Deserialize };
use std::ffi::{ c_char, CString };
use std::rc::Rc;
use hilog_rust::{ debug, error, hilog, HiLogLabel, LogType };

const LOG_LABEL: HiLogLabel = HiLogLabel {
    log_type: LogType::LogCore,
    domain: 0xD002220,
    tag: "FusionCoordinationClient"
};

/// struct FusionCoordinationClient
#[derive(Default)]
pub struct FusionCoordinationClient {
    dummy: i32
}

impl FusionCoordinationClient {
    /// TODO: add documentation.
    pub fn enable_coordination(&self, user_data: i32, ipc_client: Rc<FusionIpcClient>) -> FusionResult<i32>
    {
        call_debug_enter!("FusionCoordinationClient::enable_coordination");
        match MsgParcel::new() {
            Some(mut reply_parcel) => {
                let param = GeneralCoordinationParam {
                    user_data
                };
                let mut borrowed_reply_parcel = reply_parcel.borrowed();
                debug!(LOG_LABEL, "Call ipc_client::enable()");
                ipc_client.enable(Intention::Coordination, &param, &mut borrowed_reply_parcel)
            }
            None => {
                error!(LOG_LABEL, "Can not instantiate MsgParcel");
                Err(-1)
            }
        }
    }

    /// TODO: add documentation.
    pub fn disable_coordination(&self, user_data: i32, ipc_client: Rc<FusionIpcClient>) -> FusionResult<i32>
    {
        call_debug_enter!("FusionCoordinationClient::disable_coordination");
        match MsgParcel::new() {
            Some(mut reply_parcel) => {
                let param = GeneralCoordinationParam {
                    user_data
                };
                let mut borrowed_reply_parcel = reply_parcel.borrowed();
                debug!(LOG_LABEL, "Call ipc_client::disable()");
                ipc_client.disable(Intention::Coordination, &param, &mut borrowed_reply_parcel)
            }
            None => {
                error!(LOG_LABEL, "Can not instantiate MsgParcel");
                Err(-1)
            }
        }
    }

    /// TODO: add documentation.
    pub fn start_coordination(&self, user_data: i32, remote_network_id: String,
        start_device_id: i32, ipc_client: Rc<FusionIpcClient>) -> FusionResult<i32>
    {
        call_debug_enter!("FusionCoordinationClient::start_coordination");
        match MsgParcel::new() {
            Some(mut reply_parcel) => {
                let param = StartCoordinationParam {
                    user_data,
                    remote_network_id,
                    start_device_id,
                };
                let mut borrowed_reply_parcel = reply_parcel.borrowed();
                debug!(LOG_LABEL, "Call ipc_client::start()");
                ipc_client.start(Intention::Coordination, &param, &mut borrowed_reply_parcel)
            }
            None => {
                error!(LOG_LABEL, "Can not instantiate MsgParcel");
                Err(-1)
            }
        }
    }

    /// TODO: add documentation.
    pub fn stop_coordination(&self, user_data: i32, is_unchained: i32,
        ipc_client: Rc<FusionIpcClient>) -> FusionResult<i32>
    {
        call_debug_enter!("FusionCoordinationClient::stop_coordination");
        match MsgParcel::new() {
            Some(mut reply_parcel) => {
                let param = StopCoordinationParam {
                    user_data,
                    is_unchained,
                };
                let mut borrowed_reply_parcel = reply_parcel.borrowed();
                debug!(LOG_LABEL, "Call ipc_client::stop()");
                ipc_client.stop(Intention::Coordination, &param, &mut borrowed_reply_parcel)
            }
            None => {
                error!(LOG_LABEL, "Can not instantiate MsgParcel");
                Err(-1)
            }
        }
    }

    /// TODO: add documentation.
    pub fn get_coordination_state(&self, user_data: i32, device_id: String,
        ipc_client: Rc<FusionIpcClient>) -> FusionResult<i32>
    {
        call_debug_enter!("FusionCoordinationClient::get_coordination_state");
        match MsgParcel::new() {
            Some(mut reply_parcel) => {
                let param = GetCoordinationStateParam {
                    user_data,
                    device_id,
                };
                let mut borrowed_reply_parcel = reply_parcel.borrowed();
                debug!(LOG_LABEL, "Call ipc_client::get_param()");
                ipc_client.get_param(Intention::Coordination, 0u32, &param, &mut borrowed_reply_parcel)?;

                match DefaultReply::deserialize(&borrowed_reply_parcel) {
                    Ok(x) => {
                        Ok(x.reply)
                    }
                    Err(_) => {
                        error!(LOG_LABEL, "Fail to deserialize DefaultReply");
                        Err(-1)
                    }
                }
            }
            None => {
                error!(LOG_LABEL, "Can not instantiate MsgParcel");
                Err(-1)
            }
        }
    }

    /// TODO: add documentation.
    pub fn register_coordination_listener(&self, ipc_client: Rc<FusionIpcClient>) -> FusionResult<i32>
    {
        call_debug_enter!("FusionCoordinationClient::register_coordination_listener");
        match MsgParcel::new() {
            Some(mut reply_parcel) => {
                let param = GeneralCoordinationParam::default();
                let mut borrowed_reply_parcel = reply_parcel.borrowed();
                debug!(LOG_LABEL, "Call ipc_client::add_watch()");
                ipc_client.add_watch(Intention::Coordination, 0u32, &param, &mut borrowed_reply_parcel)
            }
            None => {
                error!(LOG_LABEL, "Can not instantiate MsgParcel");
                Err(-1)
            }
        }
    }

    /// TODO: add documentation.
    pub fn unregister_coordination_listener(&self, ipc_client: Rc<FusionIpcClient>) -> FusionResult<i32>
    {
        call_debug_enter!("FusionCoordinationClient::unregister_coordination_listener");
        match MsgParcel::new() {
            Some(mut reply_parcel) => {
                let param = GeneralCoordinationParam::default();
                let mut borrowed_reply_parcel = reply_parcel.borrowed();
                debug!(LOG_LABEL, "Call ipc_client::remove_watch()");
                ipc_client.remove_watch(Intention::Coordination, 0u32, &param, &mut borrowed_reply_parcel)
            }
            None => {
                error!(LOG_LABEL, "Can not instantiate MsgParcel");
                Err(-1)
            }
        }
    }
}